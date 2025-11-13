import crypto from 'crypto';

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY as string;
const ALGORITHM = 'aes-256-gcm';
if (!ENCRYPTION_KEY) {
  throw new Error('ENCRYPTION_KEY environment variable is required');
}

if (!/^[0-9a-fA-F]{64}$/.test(ENCRYPTION_KEY)) {
  throw new Error('ENCRYPTION_KEY must be a 64-character hexadecimal string (32 bytes)');
}
export function encrypt(text: string): string {
  const iv = crypto.randomBytes(16);
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');
  
  
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return JSON.stringify({
    iv: iv.toString('hex'),
    content: encrypted,
    authTag: authTag.toString('hex'),
  });
}

export function decrypt(encryptedData: string): string {
  if (!encryptedData) {
    throw new Error('Invalid encrypted data: empty string');
  }
  let data;
  try {
    data = JSON.parse(encryptedData);
  } catch (error) {
    throw new Error('Invalid encrypted data: malformed JSON');
  }

  if (!data.iv || !data.content || !data.authTag) {
    throw new Error('Invalid encrypted data: missing required fields (iv, content, authTag)');
  }
  const key = Buffer.from(ENCRYPTION_KEY.substring(0, 64), 'hex');
  
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(data.iv, 'hex')
  );
  
  decipher.setAuthTag(Buffer.from(data.authTag, 'hex'));
  
  let decrypted = decipher.update(data.content, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}