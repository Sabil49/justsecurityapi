import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET!;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

interface JWTPayload {
  id: string;
  email: string;
}

// Accept either a Next.js Pages-style request (with headers.authorization)
// or an App Router / Web Request (where headers.get is available).
type RequestWithHeaders = 
  | { headers: { get: (name: string) => string | null } }
  | { headers: Record<string, string | string[] | undefined> };

export async function verifyToken(req: RequestWithHeaders): Promise<JWTPayload> {
  // Try headers.get (NextRequest or Web Request)
  let authHeader: string | undefined;

  try {
    if (req?.headers && typeof (req.headers as any).get === 'function') {
      authHeader = (req.headers as any).get('authorization') ?? undefined;
    } else if ('headers' in req && req.headers) {
      // Pages API style
      const headers = req.headers as Record<string, string | string[] | undefined>;
      authHeader = typeof headers.authorization === 'string' 
        ? headers.authorization 
        : undefined;
    }
  } catch (e) {
    authHeader = undefined;
  }

  const token = authHeader?.replace(/^Bearer /i, '');
  if (!token) {
    throw new Error('No token provided');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Validate the decoded payload structure
    if (
      decoded && 
      typeof decoded === 'object' && 
      'id' in decoded && 
      'email' in decoded &&
      typeof decoded.id === 'string' &&
      typeof decoded.email === 'string'
    ) {
      return decoded as JWTPayload;
    }
    throw new Error('Invalid token payload structure');
  } catch (error) {
    // Preserve specific error messages for better debugging
    if (error instanceof Error && error.message === 'Invalid token payload structure') {
      throw error;
    }
    throw new Error('Invalid token');
  }
}
export function generateToken(payload: JWTPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
}