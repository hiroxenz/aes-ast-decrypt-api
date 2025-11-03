import crypto from 'crypto';
import * as ts from 'typescript';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed. Gunakan POST.' });
  }

  const { keyHex, ivHex, ciphertextB64 } = req.body;

  if (!keyHex || !ivHex || !ciphertextB64) {
    return res.status(400).json({ 
      error: 'Missing parameters. Butuh: keyHex, ivHex, ciphertextB64' 
    });
  }

  try {
    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const ciphertext = Buffer.from(ciphertextB64, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.finalize()]);

    const paddingLength = decrypted[decrypted.length - 1];
    if (paddingLength < 1 || paddingLength > 16) {
      throw new Error('Invalid padding');
    }
    const unpadded = decrypted.slice(0, -paddingLength);
    const decryptedAst = unpadded.toString('utf-8');

    const reconstructedCode = `
// Rekonstruksi sederhana dari AST serialized (full-nya buka viewerUrl di response)
// Ini contoh berdasarkan struktur AST: interface, function handler, event listener
interface Payload {
  type: 'send';
  payload: string;
}

const handleMessage = (message: Payload): string | null => {
  if (message.type === 'send') {
    // Extract IV dari payload (contoh: slice 0-32 chars untuk hex IV)
    const iv = message.payload.slice(0, 32);
    const key = Buffer.from('4c78bda5675779040a2513e55359da9dc2f62a66c8ba2fd7c3e418f7b6aefd47', 'hex');
    const cipherText = Buffer.from(message.payload, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(cipherText);
    decrypted = Buffer.concat([decrypted, decipher.finalize()]);
    
    // Unpad PKCS7
    const padLen = decrypted[decrypted.length - 1];
    const unpadded = decrypted.slice(0, -padLen);
    return unpadded.toString('utf8');
  }
  return null;
};

// Event handler untuk window.message (mirip postMessage di browser)
const eventHandler = (event: MessageEvent) => {
  const data = event.data as Payload;
  const result = handleMessage(data);
  if (result) {
    console.log('Decrypted AST processed:', result);
    // Di sini bisa tambah logic parse AST lebih lanjut, e.g., ts.createSourceFile(result, ...)
  }
};

// Setup listener (hanya di browser environment)
if (typeof window !== 'undefined') {
  window.addEventListener('message', eventHandler, false);
}

// Optional: Factory buat generate AST baru pake TypeScript compiler
import * as tsFactory from 'typescript';
const factory = tsFactory.factory;
const sourceFile = factory.createSourceFile(
  ['temp.ts'],
  factory.createExpressionStatement(
    factory.createCallExpression(
      factory.createIdentifier('console.log'),
      undefined,
      [factory.createStringLiteral('Hello from reconstructed AST!')]
    )
  ),
  ts.NodeFlags.None
);
console.log('SourceFile example created:', sourceFile);
`.trim();

    const viewerUrl = `https://ts-ast-viewer.com/#code/${encodeURIComponent(decryptedAst)}`;

    res.status(200).json({
      success: true,
      decryptedAst: decryptedAst,  // Raw AST serialized string (panjang)
      reconstructedCode: reconstructedCode,  // Contoh reconstructed TS/JS code
      viewerUrl: viewerUrl,  // Link buat buka full tree & source di ts-ast-viewer.com
      message: 'Decrypt sukses! Paste decryptedAst ke viewer buat lihat struktur AST lengkap.'
    });

  } catch (error) {
    console.error('Decrypt error:', error);
    res.status(500).json({ 
      error: 'Decrypt gagal', 
      details: error.message 
    });
  }
}

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '10mb'  // Buat handle ciphertext base64 besar
    }
  }
};
