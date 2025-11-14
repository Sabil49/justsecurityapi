import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { Prisma } from '@prisma/client';

/**
 * Recursively sanitize event data by redacting common sensitive keys and patterns.
 * Keeps structure but replaces sensitive values with placeholders.
 */
function sanitizeEventData(input: unknown): Prisma.InputJsonValue {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  const shallowRedactKeys = [
    'password', 'token', 'auth', 'session', 'email', 'ip', 'ssn', 'creditcard'
  ];

  function sanitize(value: any): Prisma.InputJsonValue {
    if (value === null || value === undefined) return value;

    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (emailRegex.test(trimmed)) return '[REDACTED_EMAIL]';
      if (ipv4Regex.test(trimmed)) return '[REDACTED_IPV4]';
      if (ipv6Regex.test(trimmed)) return '[REDACTED_IPV6]';
      if (trimmed.length > 200) return '[REDACTED]';
      return trimmed;
    }

    if (typeof value === 'number' || typeof value === 'boolean') {
      return value;
    }

    if (value instanceof Date) {
      return value.toISOString();
    }

    if (Array.isArray(value)) {
      return value.map((v) => sanitize(v)) as Prisma.InputJsonValue;
    }

    if (typeof value === 'object') {
      const out: Record<string, Prisma.InputJsonValue> = {};
      for (const [k, v] of Object.entries(value)) {
        const lower = k.toLowerCase();
        if (shallowRedactKeys.some(key => lower.includes(key))) {
          if (lower.includes('email')) out[k] = '[REDACTED_EMAIL]';
          else if (lower.includes('ip')) out[k] = '[REDACTED_IP]';
          else out[k] = '[REDACTED]';
        } else {
          out[k] = sanitize(v);
        }
      }
      return out;
    }

    return '[REDACTED]'; // fallback for unsupported types
  }

  try {
    return sanitize(input);
  } catch {
    return '[REDACTED]';
  }
}

export async function POST(req: NextRequest) {
  try {
    // Verify authentication
    let user;
    try {
      user = await verifyToken(req);
    } catch {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const reqBody = await req.json();
    const { type, data } = reqBody;

    if (!type || typeof type !== 'string') {
      return NextResponse.json({ error: 'Invalid or missing type field' }, { status: 400 });
    }

    if (data === undefined || data === null) {
      return NextResponse.json({ error: 'Missing data field' }, { status: 400 });
    }

    // Store sanitized telemetry safely
    await prisma.telemetryLog.create({
      data: {
        userId: user.id,
        eventType: type,
        eventData: sanitizeEventData(data),
        timestamp: new Date(),
      },
    });

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error('Telemetry error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
