const express = require('express');
const https = require('https');
const forge = require('node-forge');
const crypto = require('crypto');
const app = express();

app.use(express.json({ limit: '10mb' }));

app.get('/', (req, res) => res.json({ status: 'ok', service: 'sefaz-mtls-proxy' }));
app.get('/warmup', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

const ENDPOINTS_EVENTO = {
  AM: { host: 'nfe.sefaz.am.gov.br',       path: '/services2/services/RecepcaoEvento4' },
  BA: { host: 'nfe.sefaz.ba.gov.br',        path: '/webservices/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx' },
  GO: { host: 'nfe.sefaz.go.gov.br',        path: '/nfe/services/NFeRecepcaoEvento4' },
  MG: { host: 'nfe.fazenda.mg.gov.br',      path: '/nfe2/services/NFeRecepcaoEvento4' },
  MS: { host: 'nfe.sefaz.ms.gov.br',        path: '/ws/NFeRecepcaoEvento4' },
  MT: { host: 'nfe.sefaz.mt.gov.br',        path: '/nfews/v2/services/RecepcaoEvento4' },
  PE: { host: 'nfe.sefaz.pe.gov.br',        path: '/nfe-service/services/NFeRecepcaoEvento4' },
  PR: { host: 'nfe.sefa.pr.gov.br',         path: '/nfe/NFeRecepcaoEvento4' },
  RS: { host: 'nfe.sefazrs.rs.gov.br',      path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  SP: { host: 'nfe.fazenda.sp.gov.br',      path: '/ws/nferecepcaoevento4.asmx' },
  AC: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  AL: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  AP: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  CE: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  DF: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  ES: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  MA: { host: 'www.sefazvirtual.fazenda.gov.br', path: '/NFeRecepcaoEvento4/NFeRecepcaoEvento4.asmx' },
  PA: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  PB: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  PI: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  RJ: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  RN: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  RO: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  RR: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  SC: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  SE: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
  TO: { host: 'nfe.svrs.rs.gov.br',         path: '/ws/recepcaoevento/recepcaoevento4.asmx' },
};

const CODIGO_PARA_UF = {
  '12':'AC','27':'AL','16':'AP','13':'AM','29':'BA','23':'CE','53':'DF',
  '32':'ES','52':'GO','21':'MA','51':'MT','50':'MS','31':'MG','15':'PA',
  '25':'PB','41':'PR','26':'PE','22':'PI','33':'RJ','24':'RN','43':'RS',
  '11':'RO','14':'RR','42':'SC','35':'SP','28':'SE','17':'TO'
};

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
  const certDer = forge.util.encode64(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());

  return { certPem, keyPem, certDer };
}

// Canonicalização C14N exclusiva (sem comentários, sem namespaces herdados)
function c14n(xml) {
  // Para o nosso caso, o XML já está bem formado e sem espaços extras
  // Fazemos uma normalização simples compatível com ExcC14N
  return xml.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

// Assina XML usando node-forge puro (sem xml-crypto)
function assinarXmlEvento(xmlEvento, keyPem, certDer, refId) {
  // 1. Digest SHA-256 do conteúdo canonicalizado (sem a assinatura)
  const xmlC14n = c14n(xmlEvento);
  const digestBuf = crypto.createHash('sha256').update(xmlC14n, 'utf8').digest();
  const digestB64 = digestBuf.toString('base64');

  // 2. Monta SignedInfo
  const signedInfo = `<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod><Reference URI="#${refId}"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod><DigestValue>${digestB64}</DigestValue></Reference></SignedInfo>`;

  // 3. Assina SignedInfo com RSA-SHA256
  const signedInfoC14n = c14n(signedInfo);
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(signedInfoC14n, 'utf8');
  const signatureB64 = sign.sign(keyPem, 'base64');

  // 4. Monta bloco Signature completo
  const signatureBlock = `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">${signedInfo}<SignatureValue>${signatureB64}</SignatureValue><KeyInfo><X509Data><X509Certificate>${certDer}</X509Certificate></X509Data></KeyInfo></Signature>`;

  // 5. Injeta assinatura antes do fechamento da tag raiz
  const xmlAssinado = xmlEvento.replace('</evento>', `${signatureBlock}</evento>`);
  return xmlAssinado;
}

function montarXmlEvento(cnpj, chNFe, keyPem, certDer) {
  const dhEvento = new Date().toISOString().replace(/\.\d{3}Z$/, '-03:00');
  const tpEvento = '210210';
  const nSeqEvento = '1';
  const cOrgao = chNFe.substring(0, 2);
  const infEventoId = `ID${tpEvento}${chNFe}${nSeqEvento.padStart(2, '0')}`;

  const xmlEvento = `<evento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00"><infEvento Id="${infEventoId}"><cOrgao>${cOrgao}</cOrgao><tpAmb>1</tpAmb><CNPJ>${cnpj}</CNPJ><chNFe>${chNFe}</chNFe><dhEvento>${dhEvento}</dhEvento><tpEvento>${tpEvento}</tpEvento><nSeqEvento>${nSeqEvento}</nSeqEvento><verEvento>1.00</verEvento><detEvento versao="1.00"><descEvento>Ciencia da Operacao</descEvento></detEvento></infEvento></evento>`;

  try {
    return assinarXmlEvento(xmlEvento, keyPem, certDer, infEventoId);
  } catch(e) {
    console.error('[assinar] Erro:', e.message, e.stack);
    return null;
  }
}

function montarSoapEvento(xmlEventoAssinado) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:nfe="http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4">
  <soapenv:Header/>
  <soapenv:Body>
    <nfe:nfeRecepcaoEvento>
      <nfe:nfeDadosMsg>
        <envEvento xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.00">
          <idLote>1</idLote>
          ${xmlEventoAssinado}
        </envEvento>
      </nfe:nfeDadosMsg>
    </nfe:nfeRecepcaoEvento>
  </soapenv:Body>
</soapenv:Envelope>`;
}

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

function requisitarSefaz(soap, certPem, keyPem, soapAction, host, path) {
  return new Promise((resolve, reject) => {
    const soapBytes = Buffer.from(soap, 'utf-8');
    const options = {
      hostname: host, port: 443, path, method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': soapAction,
        'Content-Length': soapBytes.length
      },
      cert: certPem, key: keyPem,
      rejectUnauthorized: false, timeout: 30000
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode !== 200) reject(new Error(`SEFAZ ${host} status ${res.statusCode}: ${data.substring(0, 300)}`));
        else resolve(data);
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout em ${host}`)); });
    req.write(soapBytes);
    req.end();
  });
}

function extrairCStat(xml) {
  const m = xml.match(/<cStat>(\d+)<\/cStat>/);
  return m ? m[1] : null;
}

async function enviarCienciaOperacao(cnpj, chNFe, ufSigla, certPem, keyPem, certDer) {
  console.log(`[ciencia] CNPJ ${cnpj} | chave ${chNFe.substring(0,10)}... | UF ${ufSigla}`);

  const xmlAssinado = montarXmlEvento(cnpj, chNFe, keyPem, certDer);
  if (!xmlAssinado) return { ok: false, erro: 'Falha ao assinar evento' };

  const soap = montarSoapEvento(xmlAssinado);
  const endpoint = ENDPOINTS_EVENTO[ufSigla] || ENDPOINTS_EVENTO['SP'];
  console.log(`[ciencia] Endpoint: ${endpoint.host}${endpoint.path}`);

  try {
    const xmlResp = await requisitarSefaz(
      soap, certPem, keyPem,
      '"http://www.portalfiscal.inf.br/nfe/wsdl/NFeRecepcaoEvento4/nfeRecepcaoEvento"',
      endpoint.host, endpoint.path
    );
    const cStat = extrairCStat(xmlResp);
    const xMotivo = xmlResp.match(/<xMotivo>(.*?)<\/xMotivo>/)?.[1] || '';
    console.log(`[ciencia] cStat=${cStat} | ${xMotivo}`);
    return { ok: cStat === '135' || cStat === '573', cStat, xMotivo, xml: xmlResp };
  } catch(e) {
    console.error('[ciencia] Erro:', e.message);
    return { ok: false, erro: e.message };
  }
}

// POST /ciencia-operacao — endpoint dedicado
app.post('/ciencia-operacao', async (req, res) => {
  const { pfxBase64, senha, cnpj, uf, chNFe } = req.body;
  if (!pfxBase64 || !senha || !cnpj || !chNFe) {
    return res.status(400).json({ error: 'pfxBase64, senha, cnpj e chNFe são obrigatórios' });
  }
  try {
    const cnpjLimpo = cnpj.replace(/\D/g, '');
    const ufSigla = uf || 'SP';
    const { certPem, keyPem, certDer } = extrairPemDoPfx(pfxBase64, senha);
    const resultado = await enviarCienciaOperacao(cnpjLimpo, chNFe, ufSigla, certPem, keyPem, certDer);
    res.json(resultado);
  } catch(err) {
    console.error('[ciencia-operacao] Erro:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /consultar-nfes — consulta DFe principal
app.post('/consultar-nfes', async (req, res) => {
  const { pfxBase64, senha, cnpj, uf, nsu = 0 } = req.body;
  if (!pfxBase64 || !senha || !cnpj || !uf) {
    return res.status(400).json({ error: 'pfxBase64, senha, cnpj e uf são obrigatórios' });
  }
  try {
    const cnpjLimpo = cnpj.replace(/\D/g, '');
    const { certPem, keyPem } = extrairPemDoPfx(pfxBase64, senha);

    const DFE_HOST = 'www1.nfe.fazenda.gov.br';
    const DFE_PATH = '/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx';
    const DFE_ACTION = '"http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse"';

    const soap = montarSoapDistribuicao(cnpjLimpo, uf, nsu);
    const xmlResposta = await requisitarSefaz(soap, certPem, keyPem, DFE_ACTION, DFE_HOST, DFE_PATH);
    const cStat = extrairCStat(xmlResposta);
    console.log(`[consultar] CNPJ ${cnpjLimpo} | NSU ${nsu} | cStat=${cStat}`);

    res.json({ success: true, xml: xmlResposta, cStat });
  } catch (err) {
    console.error('[consultar] Erro:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /consultar-chave — busca XML completo de uma NF-e por chave de acesso
app.post('/consultar-chave', async (req, res) => {
  const { pfxBase64, senha, cnpj, uf, chNFe } = req.body;
  if (!pfxBase64 || !senha || !cnpj || !chNFe) {
    return res.status(400).json({ error: 'pfxBase64, senha, cnpj e chNFe são obrigatórios' });
  }
  try {
    const cnpjLimpo = cnpj.replace(/\D/g, '');
    const ufCod = uf || '35';
    const { certPem, keyPem } = extrairPemDoPfx(pfxBase64, senha);

    const soap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:nfe="http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe">
  <soapenv:Header/>
  <soapenv:Body>
    <nfe:nfeDistDFeInteresse>
      <nfe:nfeDadosMsg>
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
          <tpAmb>1</tpAmb>
          <cUFAutor>${ufCod}</cUFAutor>
          <CNPJ>${cnpjLimpo}</CNPJ>
          <consChNFe>
            <chNFe>${chNFe}</chNFe>
          </consChNFe>
        </distDFeInt>
      </nfe:nfeDadosMsg>
    </nfe:nfeDistDFeInteresse>
  </soapenv:Body>
</soapenv:Envelope>`;

    const DFE_HOST = 'www1.nfe.fazenda.gov.br';
    const DFE_PATH = '/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx';
    const DFE_ACTION = '"http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse"';

    const xmlResposta = await requisitarSefaz(soap, certPem, keyPem, DFE_ACTION, DFE_HOST, DFE_PATH);
    const cStat = extrairCStat(xmlResposta);
    const xMotivo = xmlResposta.match(/<xMotivo>(.*?)<\/xMotivo>/)?.[1] || '';
    console.log(`[consultar-chave] chNFe=${chNFe.substring(0,10)}... | cStat=${cStat} | ${xMotivo}`);

    // Extrai o docZip da resposta
    const docZipMatch = xmlResposta.match(/<docZip[^>]*>(.*?)<\/docZip>/s);
    let xmlCompleto = null;

    if (docZipMatch && (cStat === '138' || cStat === '100')) {
      // Descomprime o Gzip
      const zlib = require('zlib');
      try {
        const buf = Buffer.from(docZipMatch[1].trim(), 'base64');
        const decompressed = zlib.gunzipSync(buf);
        xmlCompleto = decompressed.toString('utf-8');
        console.log(`[consultar-chave] XML descomprimido: ${xmlCompleto.substring(0, 80)}`);
      } catch(e) {
        console.error('[consultar-chave] Erro decompress:', e.message);
      }
    }

    res.json({
      success: true,
      cStat,
      xMotivo,
      xml: xmlCompleto,
      xmlRaw: xmlResposta
    });
  } catch(err) {
    console.error('[consultar-chave] Erro:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
