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

// Monta SOAP de distribuição de DF-e
function montarSoap(cnpj, uf, nsu) {
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

// Faz a requisição mTLS para a SEFAZ
function consultarSefaz(soap, certPem, keyPem) {
  return new Promise((resolve, reject) => {
    const soapBytes = Buffer.from(soap, 'utf-8');
    const options = {
      hostname: 'www1.nfe.fazenda.gov.br',
      port: 443,
      path: '/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx',
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse"',
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
          reject(new Error(`SEFAZ retornou status ${res.statusCode}: ${data}`));
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

// Endpoint principal
app.post('/consultar-nfes', async (req, res) => {
  const { pfxBase64, senha, cnpj, uf, nsu = 0 } = req.body;

  if (!pfxBase64 || !senha || !cnpj || !uf) {
    return res.status(400).json({ error: 'pfxBase64, senha, cnpj e uf são obrigatórios' });
  }

  try {
    const { certPem, keyPem } = extrairPemDoPfx(pfxBase64, senha);
    const soap = montarSoap(cnpj, uf, nsu);
    const xmlResposta = await consultarSefaz(soap, certPem, keyPem);
    res.json({ success: true, xml: xmlResposta });
  } catch (err) {
    console.error('[ERRO]', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
