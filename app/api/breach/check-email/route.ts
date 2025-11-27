"use server";
// app/api/breach/check-email/route.ts

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { verifyAuth } from '@/lib/auth';
import { rateLimit } from '@/lib/rate-limit';

const CheckEmailSchema = z.object({
  email: z.email({ message: 'Invalid email address' }),
});

const HIBP_API_KEY = process.env.HIBP_API_KEY!;
const HIBP_API = 'https://haveibeenpwned.com/api/v3';

export async function POST(request: NextRequest) {
  try {
    const user = await verifyAuth(request);

    // Rate limit: 10 checks per hour per user
    const { success } = await rateLimit(`breach_check:${user.userId}`, 10, 3600);
    if (!success) {
      return NextResponse.json(
        { success: false, error: 'Too many requests. Try again later.' },
        { status: 429 }
      );
    }

    const body = await request.json();
    const validated = CheckEmailSchema.parse(body);

    // Call Have I Been Pwned API
    const response = await fetch(
      `${HIBP_API}/breachedaccount/${encodeURIComponent(validated.email)}?truncateResponse=false`,
      {
        headers: {
          'hibp-api-key': HIBP_API_KEY,
          'user-agent': 'AVG-Antivirus-App',
        },
      }
    );

    if (response.status === 404) {
      // Email not found in breaches
      return NextResponse.json({
        success: true,
        data: {
          email: validated.email,
          breaches: [],
          isBreached: false,
        },
      });
    }

    if (!response.ok) {
      throw new Error(`HIBP API error: ${response.status}`);
    }

    const breaches = await response.json();

    return NextResponse.json({
      success: true,
      data: {
        email: validated.email,
        breaches,
        isBreached: breaches.length > 0,
      },
    });
  } catch (error) {
    console.error('[CHECK_EMAIL_BREACH_ERROR]', error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { success: false, error: 'Invalid request data' },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { success: false, error: 'Failed to check email breach' },
      { status: 500 }
    );
  }
}