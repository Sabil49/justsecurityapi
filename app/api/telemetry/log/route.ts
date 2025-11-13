import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { prisma } from '@/lib/db';

/**
 * Recursively sanitize event data by redacting common sensitive keys and patterns.
 * Keeps structure but replaces sensitive values with placeholders.
 */
function sanitizeEventData(input: unknown): unknown {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  const shallowRedactKeys = ['password', 'token', 'auth', 'session', 'email', 'ip', 'ssn', 'creditcard'];

  function sanitize(value: any): any {
    if (value === null || value === undefined) return value;
    
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (emailRegex.test(trimmed)) return '[REDACTED_EMAIL]';
      if (ipv4Regex.test(trimmed)) return '[REDACTED_IPV4]';
      if (ipv6Regex.test(trimmed)) return '[REDACTED_IPV6]';
      // generic length-based redact for long tokens
      if (trimmed.length > 200) return '[REDACTED]';
      return trimmed;
    }
    
    if (typeof value === 'number' || typeof value === 'boolean' || value instanceof Date) {
      return value instanceof Date ? value.toISOString() : value;    }
    
    if (Array.isArray(value)) {
      return value.map(sanitize);
    }
    
    if (typeof value === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        const lower = k.toLowerCase();
        if (shallowRedactKeys.some(key => lower.includes(key.toLowerCase()))) {
          if (lower.includes('email')) out[k] = '[REDACTED_EMAIL]';
          else if (lower.includes('ip')) out[k] = '[REDACTED_IP]';
          else out[k] = '[REDACTED]';
        } else {
          out[k] = sanitize(v);
        }
      }
      return out;
    }
    
    return value;
  }

  try {
    return sanitize(input);
  } catch (e) {
    // If sanitization fails for any reason, avoid leaking original data
    return '[REDACTED]';
  }
}

export async function POST(req: NextRequest) {
  try {
    // Verify authentication
    let user;
    try {
      user = await verifyToken(req);
    } catch (error) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    
    // Parse request body
    const reqBody = await req.json();
    const { type, data } = reqBody;

    // Validate required fields
    if (!type || typeof type !== 'string') {
      return NextResponse.json({ error: 'Invalid or missing type field' }, { status: 400 });
    }

    if (data === undefined || data === null) {
      return NextResponse.json({ error: 'Missing data field' }, { status: 400 });
    }

    // Store anonymized telemetry
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