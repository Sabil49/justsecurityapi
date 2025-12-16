// lib/auth.ts
import { NextRequest } from 'next/server';
import { verify,sign } from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is not set');
}
export interface AuthUser {
  userId: string;
  email: string;
  iat: number;
  exp: number;
}

export async function verifyAuth(request: NextRequest): Promise<AuthUser> {
  // Next.js sometimes lowercases headers
  const authHeader =
    request.headers.get("authorization") ||
    request.headers.get("Authorization");

  if (!authHeader) {
    throw new Error("Authorization header missing");
  }

  // Normalize casing
  const lower = authHeader.toLowerCase();

  if (!lower.startsWith("bearer ")) {
    throw new Error("Invalid authorization header");
  }

  // Extract token safely
  const token = authHeader.split(" ")[1];
  if (!token) {
    throw new Error("Missing token");
  }
  console.log("Verifying token:", token);
  try {
    const decoded = verify(token, JWT_SECRET as string) as unknown as AuthUser;
    return decoded;
  } catch (err) {
    console.error("JWT VERIFY ERROR:", err);
    throw new Error("Invalid or expired token");
  }
}

export function createAuthToken(userId: string, email?: string): string {
  const token = sign(
    { userId, email },
    JWT_SECRET!,
    { expiresIn: '7d' }
  );
  return token;
}