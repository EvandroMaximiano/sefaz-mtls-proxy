const express = require('express');
const https = require('https');
const forge = require('node-forge');
const { SignedXml } = require('xml-crypto');
const app = express();

app.use(express.json({ limit: '10mb' }));

app.get('/', (req, res) => res.json({ status: 'ok', service: 'sefaz-mtls-proxy' }));
app.get('/warmup', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

// Extrai certPem, keyPem e o certificado em DER base64 do PFX
function extrairPemDoPfx(pfxBase64, senha) {
  const pfxDer = forge.util.decode64(pfxBase64);
  const pfxAsn1 = forge.asn1.fromDer(pfxDer);
  const p12 = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, senha);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];

  if (!certBags.length) throw new Error('Certificado não encontrado no PFX');
  if (!keyBags.length) throw new Error('Chave privada não encontrada no PFX');

  const cert = certBags[0].cert;
  const certPem = forge.pki.certificateToPem(cert);
  const keyPem = forge.pki.privateKeyToPem(keyBags[0].key);
  // Certificado em base64 DER para incluir no XML assinado
  const certDer = forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());

  return { certPem, keyPem, certDer, cert };
}

// Requisição mTLS para a SEFAZ
function requisitarSefaz(soap, certPem, keyPem, soapAction, path) {
  return new Promise((resolve, reject) => {
    const soapBytes = Buffer.from(soap, 'utf-8');
    const options = {
      hostname: 'www1.nfe.fazenda.gov.br',
      port: 443,
      path: path || '/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx',
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': soapAction,
        'Content-Length': soapBytes.length
      },
      cert: certPem,
      key: keyPem,
      rejectUnauthorized: false,
      timeout: 30000
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`SEFAZ status ${res.statusCode}: ${data.substring(0, 300)}`));
        } else {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout na requisição SEFAZ')); });
    req.write(soapBytes);
    req.end();
  });
}

function extrairCStat(xml) {
  const m = xml.match(/<cStat>(\d+)<\/cStat>/);
  return m ? m[1] : null;
}

// Monta SOAP de distribuição DFe por NSU
function montarSoapDistribuicao(cnpj, uf, nsu) {
  const nsuFormatado = String(nsu).padStart(15, '0');
  return `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:nfe="http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe">
  <soapenv:Header/>
  <soapenv:Body>
    <nfe:nfeDistDFeInteresse>
      <nfe:nfeDadosMsg>
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
          <tpAmb>1</tpAmb>
          <cUFAutor>${uf}</cUFAutor>
          <CNPJ>${cnpj}</CNPJ>
          <distNSU>
            <ultNSU>${nsuFormatado}</ultNSU>
          </distNSU>
        </distDFeInt>
      </nfe:nfeDadosMsg>
    </nfe:nfeDistDFeInteresse>
  </soapenv:Body>
</soapenv:Envelope>`;
}

// Monta evento de Ciência da Operação (tpEvento=210210) assinado
function montarEventoCiencia(cnpj, chNFe, certDer, keyPem) {
  const dhEvento = new Date().toISOString().replace(/\.\d{3}Z$/, '-03:00');
  const nSeqEvento = '1';
  const tpEvento = '210210';
  const cOrgao = chNFe.substring(0, 2); // UF da chave

  // XML do evento sem assinatura
  const infEventoId = `ID${tpEvento}${chNFe}${nSeqEvento.padStart(2, '0')}`;
  const xmlEvento = `<evento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">
  <infEvento Id="${infEventoId}">
    <cOrgao>${cOrgao}</cOrgao>
    <tpAmb>1</tpAmb>
    <CNPJ>${cnpj}</CNPJ>
    <chNFe>${chNFe}</chNFe>
    <dhEvento>${dhEvento}</dhEvento>
    <tpEvento>${tpEvento}</tpEvento>
    <nSeqEvento>${nSeqEvento}</nSeqEvento>
    <verEvento>1.00</verEvento>
    <detEvento versao="1.00">
      <descEvento>Ciencia da Operacao</descEvento>
    </detEvento>
  </infEvento>
</evento>`;

  // Assina o XML
  try {
    const sig = new SignedXml({ privateKey: keyPem });
    sig.addReference({
      xpath: `//*[@Id='${infEventoId}']`,
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#'
      ]
    });
    sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    sig.canonicalizationAlgorithm = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    sig.keyInfoProvider = {
      getKeyInfo: () => `<X509Data><X509Certificate>${certDer}</X509Certificate></X509Data>`
    };
    sig.computeSignature(xmlEvento);
    const xmlAssinado = sig.getSignedXml();

    // Envelope SOAP para envio de evento
    return `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:nfe="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">
  <soapenv:Header/>
  <soapenv:Body>
    <nfe:nfeRecepcaoEvento>
      <nfe:nfeDadosMsg>
        <envEvento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">
          <idLote>1</idLote>
          ${xmlAssinado}
        </envEvento>
      </nfe:nfeDadosMsg>
    </nfe:nfeRecepcaoEvento>
  </soapenv:Body>
</soapenv:Envelope>`;
  } catch(e) {
    console.error('[evento] Erro ao assinar:', e.message);
    return null;
  }
}

// Envia evento de Ciência da Operação para credenciar o CNPJ
async function enviarCienciaOperacao(cnpj, chNFe, uf, certPem, keyPem, certDer) {
  console.log(`[ciencia] Enviando Ciência da Operação para chave ${chNFe.substring(0,10)}...`);
  
  const soapEvento = montarEventoCiencia(cnpj, chNFe, certDer, keyPem);
  if (!soapEvento) {
    console.log('[ciencia] Falha ao montar evento, pulando...');
    return false;
  }

  // Determina UF para o endpoint de eventos
  const cUF = chNFe.substring(0, 2);
  const ufEventoPath = '/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx';
  
  try {
    const xmlResp = await requisitarSefaz(
      soapEvento, certPem, keyPem,
      '"http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento"',
      ufEventoPath
    );
    const cStat = extrairCStat(xmlResp);
    console.log(`[ciencia] Resposta cStat=${cStat}`);
    // 135=evento registrado, 573=duplicidade (já foi registrado antes) — ambos ok
    return cStat === '135' || cStat === '573' || cStat === '138';
  } catch(e) {
    console.error('[ciencia] Erro:', e.message);
    return false;
  }
}

// Endpoint principal de consulta de NF-e
app.post('/consultar-nfes', async (req, res) => {
  const { pfxBase64, senha, cnpj, uf, nsu = 0, chaveCredenciamento } = req.body;

  if (!pfxBase64 || !senha || !cnpj || !uf) {
    return res.status(400).json({ error: 'pfxBase64, senha, cnpj e uf são obrigatórios' });
  }

  try {
    const cnpjLimpo = cnpj.replace(/\D/g, '');
    const { certPem, keyPem, certDer } = extrairPemDoPfx(pfxBase64, senha);
    const soapAction = '"http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse"';

    // Primeira tentativa de consulta
    const soap = montarSoapDistribuicao(cnpjLimpo, uf, nsu);
    let xmlResposta = await requisitarSefaz(soap, certPem, keyPem, soapAction);
    let cStat = extrairCStat(xmlResposta);
    console.log(`[consultar] CNPJ ${cnpjLimpo} | NSU ${nsu} | cStat=${cStat}`);

    // Se 656, tenta credenciar via Ciência da Operação e repetir
    if (cStat === '656' && chaveCredenciamento) {
      console.log(`[consultar] cStat=656, enviando Ciência da Operação para credenciar...`);
      await enviarCienciaOperacao(cnpjLimpo, chaveCredenciamento, uf, certPem, keyPem, certDer);
      
      // Aguarda propagação e tenta de novo
      await new Promise(r => setTimeout(r, 3000));
      xmlResposta = await requisitarSefaz(montarSoapDistribuicao(cnpjLimpo, uf, nsu), certPem, keyPem, soapAction);
      cStat = extrairCStat(xmlResposta);
      console.log(`[consultar] Após credenciamento: cStat=${cStat}`);
    } else if (cStat === '656') {
      // Sem chave, tenta algumas vezes com delay
      for (let i = 1; i <= 3; i++) {
        await new Promise(r => setTimeout(r, 3000));
        xmlResposta = await requisitarSefaz(montarSoapDistribuicao(cnpjLimpo, uf, nsu), certPem, keyPem, soapAction);
        cStat = extrairCStat(xmlResposta);
        console.log(`[consultar] Retry ${i}: cStat=${cStat}`);
        if (cStat !== '656') break;
      }
    }

    res.json({ success: true, xml: xmlResposta, cStat });
  } catch (err) {
    console.error('[ERRO]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Endpoint dedicado para enviar Ciência da Operação
app.post('/ciencia-operacao', async (req, res) => {
  const { pfxBase64, senha, cnpj, uf, chNFe } = req.body;
  if (!pfxBase64 || !senha || !cnpj || !chNFe) {
    return res.status(400).json({ error: 'pfxBase64, senha, cnpj e chNFe são obrigatórios' });
  }
  try {
    const cnpjLimpo = cnpj.replace(/\D/g, '');
    const { certPem, keyPem, certDer } = extrairPemDoPfx(pfxBase64, senha);
    const ok = await enviarCienciaOperacao(cnpjLimpo, chNFe, uf, certPem, keyPem, certDer);
    res.json({ success: ok });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
