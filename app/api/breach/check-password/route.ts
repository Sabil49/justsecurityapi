"use server";
// app/api/breach/check-password/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { verifyAuth } from '@/lib/auth';
import { rateLimit } from '@/lib/rate-limit';

const CheckPasswordSchema = z.object({
  hashPrefix: z.string().length(5),
  hashSuffix: z.string(),
});

export async function POST(request: NextRequest) {
  try {
    const user = await verifyAuth(request);

    // Rate limit: 50 checks per hour per user
    const { success } = await rateLimit(`password_check:${user.userId}`, 50, 3600);
    if (!success) {
      return NextResponse.json(
        { success: false, error: 'Too many requests' },
        { status: 429 }
      );
    }

    const body = await request.json();
    const validated = CheckPasswordSchema.parse(body);

    // Call HIBP Pwned Passwords API (k-anonymity model)
    const response = await fetch(
      `https://api.pwnedpasswords.com/range/${validated.hashPrefix}`,
      {
        headers: {
          'user-agent': 'AVG-Antivirus-App',
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Pwned Passwords API error: ${response.status}`);
    }

    const text = await response.text();
    const hashes = text.split('\r\n');

    // Find matching hash suffix
    for (const line of hashes) {
      const [suffix, count] = line.split(':');

      if (suffix === validated.hashSuffix) {
        return NextResponse.json({
          success: true,
          data: {
            isPwned: true,
            count: parseInt(count, 10),
          },
        });
      }
    }

    // Password not found in breaches
    return NextResponse.json({
      success: true,
      data: {
        isPwned: false,
        count: 0,
      },
    });
  } catch (error) {
    console.error('[CHECK_PASSWORD_PWNED_ERROR]', error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { success: false, error: 'Invalid request data' },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { success: false, error: 'Failed to check password' },
      { status: 500 }
    );
  }
}