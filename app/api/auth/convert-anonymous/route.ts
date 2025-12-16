// app/api/auth/convert-anonymous/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/prisma';
import bcrypt from 'bcrypt';
import { sign } from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET!;
const SALT_ROUNDS = 10;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

const ConvertAnonymousSchema = z.object({
  anonymousUserId: z.string().uuid(),
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().min(2, 'Name must be at least 2 characters'),
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validated = ConvertAnonymousSchema.parse(body);

    // Verify user is anonymous
    const anonymousUser = await prisma.user.findUnique({
      where: { id: validated.anonymousUserId },
      include: {
        devices: true,
        subscriptions: true,
      },
    });

    if (!anonymousUser) {
      return NextResponse.json(
        {
          success: false,
          error: 'Anonymous user not found',
        },
        { status: 404 }
      );
    }

    if (!anonymousUser.isAnonymous) {
      return NextResponse.json(
        {
          success: false,
          error: 'User is not anonymous',
        },
        { status: 400 }
      );
    }

    // Check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: validated.email },
    });

    if (existingUser) {
      return NextResponse.json(
        {
          success: false,
          error: 'Email already registered',
        },
        { status: 409 }
      );
    }

    // Convert anonymous user to registered user
    const passwordHash = await bcrypt.hash(validated.password, SALT_ROUNDS);

    const updatedUser = await prisma.user.update({
      where: { id: validated.anonymousUserId },
      data: {
        email: validated.email,
        name: validated.name,
        authProvider: 'email',
        passwordHash,
        isAnonymous: false,
        updatedAt: new Date(),
      },
    });

    // Create new JWT tokens (now as registered user)
    const token = sign(
      {
        userId: updatedUser.id,
        email: updatedUser.email,
        isAnonymous: false,
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const refreshToken = sign(
      {
        userId: updatedUser.id,
        email: updatedUser.email,
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Get active subscription
    const subscription = await prisma.subscription.findFirst({
      where: {
        userId: updatedUser.id,
        status: { in: ['active', 'trial'] },
      },
    });

    // Log telemetry
    try {
      await prisma.telemetryLog.create({
        data: {
          userId: updatedUser.id,
          eventType: 'anonymous_conversion',
          eventData: {
            email: validated.email,
            hadDevices: anonymousUser.devices.length,
            hadSubscriptions: anonymousUser.subscriptions.length,
            timestamp: new Date().toISOString(),
          },
        },
      });
    } catch (telemetryError) {
      console.error('[TELEMETRY_ERROR]', telemetryError);
    }

    console.log('[ANONYMOUS_CONVERT] Success:', {
      userId: updatedUser.id,
      email: validated.email,
    });

    return NextResponse.json(
      {
        success: true,
        data: {
          token,
          refreshToken,
          userId: updatedUser.id,
          isAnonymous: false,
          user: {
            id: updatedUser.id,
            email: updatedUser.email,
            name: updatedUser.name,
          },
          subscription: subscription ? {
            tier: subscription.tier,
            status: subscription.status,
            trialEndsAt: subscription.trialEndsAt,
          } : null,
        },
      },
      { status: 200 }
    );
  } catch (error) {
    console.error('[ANONYMOUS_CONVERT_ERROR]', error);

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
        error: 'Conversion failed',
      },
      { status: 500 }
    );
  }
}