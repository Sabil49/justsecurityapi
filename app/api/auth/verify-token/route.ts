// app/api/auth/verify-token/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { verify } from 'jsonwebtoken';
import { prisma } from '@/lib/prisma';

const JWT_SECRET = process.env.JWT_SECRET!;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

const VerifyTokenSchema = z.object({
  token: z.string(),
});

interface JWTPayload {
  userId: string;
  email?: string;
  isAnonymous?: boolean;
  deviceId?: string;
  exp?: number;
  iat?: number;
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validated = VerifyTokenSchema.parse(body);

    // Verify JWT token
    let decoded: JWTPayload;
    try {
      decoded = verify(validated.token, JWT_SECRET) as JWTPayload;
    } catch (jwtError) {
      console.error('[VERIFY_TOKEN] JWT verification failed:', jwtError);
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid or expired token',
        },
        { status: 401 }
      );
    }

    // Check if user still exists
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (!user) {
      return NextResponse.json(
        {
          success: false,
          error: 'User not found',
        },
        { status: 404 }
      );
    }

    // Get active subscription
    const subscription = await prisma.subscription.findFirst({
      where: {
        userId: user.id,
        status: { in: ['active', 'trial'] },
      },
      orderBy: { createdAt: 'desc' },
    });

    console.log('[VERIFY_TOKEN] Success:', {
      userId: user.id,
      isAnonymous: user.isAnonymous,
    });

    return NextResponse.json({
      success: true,
      data: {
        userId: user.id,
        email: user.email,
        name: user.name,
        isAnonymous: user.isAnonymous,
        expiresAt: decoded.exp ? decoded.exp * 1000 : null, // Convert to milliseconds
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          isAnonymous: user.isAnonymous,
        },
        subscription: subscription ? {
          tier: subscription.tier,
          status: subscription.status,
          trialEndsAt: subscription.trialEndsAt,
        } : null,
      },
    });
  } catch (error) {
    console.error('[VERIFY_TOKEN_ERROR]', error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid request data',
          details: error.issues,
        },
        { status: 400 }
      );
    }

    return NextResponse.json(
      {
        success: false,
        error: 'Token verification failed',
      },
      { status: 500 }
    );
  }
}