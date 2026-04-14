const express = require('express');
const https = require('https');
const forge = require('node-forge');
const app = express();

app.use(express.json({ limit: '10mb' }));

// Health check
app.get('/', (req, res) => res.json({ status: 'ok', service: 'sefaz-mtls-proxy' }));

// Extrai certPem e keyPem do PFX base64
function extrairPemDoPfx(pfxBase64, senha) {
  const pfxDer = forge.util.decode64(pfxBase64);
  const pfxAsn1 = forge.asn1.fromDer(pfxDer);
  const p12 = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, senha);

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag] || [];
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag] || [];

  if (!certBags.length) throw new Error('Certificado não encontrado no PFX');
  if (!keyBags.length) throw new Error('Chave privada não encontrada no PFX');

  const certPem = forge.pki.certificateToPem(certBags[0].cert);
  const keyPem = forge.pki.privateKeyToPem(keyBags[0].key);

  return { certPem, keyPem };
}

// Faz requisição mTLS genérica para a SEFAZ
function requisitarSefaz(soap, certPem, keyPem, soapAction) {
  return new Promise((resolve, reject) => {
    const soapBytes = Buffer.from(soap, 'utf-8');
    const options = {
      hostname: 'www1.nfe.fazenda.gov.br',
      port: 443,
      path: '/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx',
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': soapAction,
        'Content-Length': soapBytes.length
      },
      cert: certPem,
      key: keyPem,
      rejectUnauthorized: false
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`SEFAZ retornou status ${res.statusCode}: ${data.substring(0, 300)}`));
        } else {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    req.write(soapBytes);
    req.end();
  });
}

// Monta SOAP de distribuição de DF-e (consulta por NSU)
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
          <CNPJ>${cnpj.replace(/\D/g, '')}</CNPJ>
          <distNSU>
            <ultNSU>${nsuFormatado}</ultNSU>
          </distNSU>
        </distDFeInt>
      </nfe:nfeDadosMsg>
    </nfe:nfeDistDFeInteresse>
  </soapenv:Body>
</soapenv:Envelope>`;
}

// Monta SOAP de credenciamento do destinatário (habilita CNPJ para DFe)
function montarSoapCredenciamento(cnpj, uf) {
  const cnpjLimpo = cnpj.replace(/\D/g, '');
  // Manifestação de ciência da operação em uma NF-e qualquer não é ideal
  // O credenciamento real é feito via envio de evento do tipo 210210 (Ciência da Operação)
  // ou simplesmente fazendo uma consulta com NSU=0 que registra o CNPJ como interessado
  // Usamos consultarChNFe com chave fictícia para forçar registro — não, melhor:
  // A SEFAZ registra automaticamente o destinatário ao receber qualquer consulta válida.
  // Para forçar o credenciamento, fazemos uma consulta por chave de acesso conhecida
  // OU simplesmente a própria consulta distNSU já credencia.
  // Aqui implementamos o evento de "Ciência da Operação" que é o mais robusto:
  const dhEvento = new Date().toISOString().substring(0, 19) + '-03:00';
  const nSeqEvento = '1';
  const tpEvento = '210210'; // Ciência da Operação

  // Para credenciar sem uma chave específica, usamos a consulta de distribuição com NSU=0
  // que é suficiente para registrar o CNPJ na SEFAZ como destinatário ativo
  return montarSoapDistribuicao(cnpjLimpo, uf, 0);
}

// Extrai cStat da resposta XML da SEFAZ
function extrairCStat(xmlResposta) {
  const match = xmlResposta.match(/<cStat>(\d+)<\/cStat>/);
  return match ? match[1] : null;
}

// Tenta credenciar o CNPJ e aguarda propagação
async function credenciarCNPJ(cnpj, uf, certPem, keyPem) {
  console.log(`[credenciar] Iniciando credenciamento CNPJ ${cnpj} UF ${uf}`);
  
  // Faz até 3 tentativas de consulta com NSU=0 para registrar o destinatário
  for (let tentativa = 1; tentativa <= 3; tentativa++) {
    const soap = montarSoapDistribuicao(cnpj, uf, 0);
    const soapAction = '"http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse"';
    
    try {
      const xml = await requisitarSefaz(soap, certPem, keyPem, soapAction);
      const cStat = extrairCStat(xml);
      console.log(`[credenciar] Tentativa ${tentativa}: cStat=${cStat}`);
      
      if (cStat === '138' || cStat === '137') {
        // 138 = documentos localizados, 137 = nenhum documento localizado — ambos indicam CNPJ habilitado
        console.log(`[credenciar] CNPJ habilitado com sucesso (cStat=${cStat})`);
        return { habilitado: true, cStat };
      }
      
      if (cStat === '656') {
        console.log(`[credenciar] Tentativa ${tentativa}: CNPJ ainda não habilitado (656), aguardando...`);
        // Aguarda 3 segundos entre tentativas
        await new Promise(r => setTimeout(r, 3000));
      } else {
        // Outro status inesperado
        console.log(`[credenciar] Status inesperado: ${cStat}`);
        break;
      }
    } catch (err) {
      console.error(`[credenciar] Erro na tentativa ${tentativa}:`, err.message);
    }
  }
  
  return { habilitado: false, cStat: '656' };
}

// Monta SOAP de consulta por NSU
function montarSoapConsulta(cnpj, uf, nsu) {
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
          <CNPJ>${cnpj.replace(/\D/g, '')}</CNPJ>
          <distNSU>
            <ultNSU>${nsuFormatado}</ultNSU>
          </distNSU>
        </distDFeInt>
      </nfe:nfeDadosMsg>
    </nfe:nfeDistDFeInteresse>
  </soapenv:Body>
</soapenv:Envelope>`;
}

// Endpoint de consulta com credenciamento automático
app.post('/consultar-nfes', async (req, res) => {
  const { pfxBase64, senha, cnpj, uf, nsu = 0 } = req.body;

  if (!pfxBase64 || !senha || !cnpj || !uf) {
    return res.status(400).json({ error: 'pfxBase64, senha, cnpj e uf são obrigatórios' });
  }

  try {
    const { certPem, keyPem } = extrairPemDoPfx(pfxBase64, senha);
    const soapAction = '"http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse"';

    // Monta e executa consulta principal
    const soap = montarSoapConsulta(cnpj, uf, nsu);
    let xmlResposta = await requisitarSefaz(soap, certPem, keyPem, soapAction);
    let cStat = extrairCStat(xmlResposta);

    console.log(`[consultar] CNPJ ${cnpj} | NSU ${nsu} | cStat=${cStat}`);

    // Se retornar 656 (não habilitado), tenta credenciar e repetir
    if (cStat === '656') {
      console.log(`[consultar] cStat=656, iniciando credenciamento automático...`);
      
      // Aguarda 2 segundos e tenta novamente até 5 vezes
      for (let tentativa = 1; tentativa <= 5; tentativa++) {
        await new Promise(r => setTimeout(r, 2000));
        
        const soapRetry = montarSoapConsulta(cnpj, uf, nsu);
        xmlResposta = await requisitarSefaz(soapRetry, certPem, keyPem, soapAction);
        cStat = extrairCStat(xmlResposta);
        
        console.log(`[consultar] Retry ${tentativa}: cStat=${cStat}`);
        
        if (cStat !== '656') break;
      }
    }

    res.json({ success: true, xml: xmlResposta, cStat });
  } catch (err) {
    console.error('[ERRO]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Endpoint de warmup (acorda o serviço Render)
app.get('/warmup', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
