// app/api/auth/anonymous-login/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/prisma';
import { sign } from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET!;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

const AnonymousLoginSchema = z.object({
  deviceInfo: z.object({
    deviceId: z.string(),
    deviceName: z.string(),
    platform: z.enum(['ANDROID', 'IOS']),
    osVersion: z.string(),
    appVersion: z.string(),
    model: z.string().optional(),
    brand: z.string().optional(),
  }),
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validated = AnonymousLoginSchema.parse(body);

    // Find device with anonymous user
    const device = await prisma.device.findUnique({
      where: { deviceId: validated.deviceInfo.deviceId },
      include: {
        user: true,
      },
    });

    if (!device || !device.user.isAnonymous) {
      return NextResponse.json(
        {
          success: false,
          error: 'Anonymous user not found',
        },
        { status: 404 }
      );
    }

    const user = device.user;

    // Update device last seen
    await prisma.device.update({
      where: { id: device.id },
      data: {
        lastSeen: new Date(),
        osVersion: validated.deviceInfo.osVersion,
        appVersion: validated.deviceInfo.appVersion,
      },
    });

    // Update user last activity
    await prisma.user.update({
      where: { id: user.id },
      data: { updatedAt: new Date() },
    });

    // Get subscription
    let subscription = await prisma.subscription.findFirst({
      where: {
        userId: user.id,
        status: { in: ['active', 'trial'] },
      },
    });

    if (!subscription) {
      // Create free trial if none exists
      subscription = await prisma.subscription.create({
        data: {
          userId: user.id,
          tier: 'free',
          status: 'trial',
          platform: validated.deviceInfo.platform,
          trialEndsAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          currentPeriodStart: new Date(),
          currentPeriodEnd: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        },
      });
    }

    // Create JWT tokens
    const token = sign(
      {
        userId: user.id,
        isAnonymous: true,
        deviceId: validated.deviceInfo.deviceId,
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    const refreshToken = sign(
      {
        userId: user.id,
        isAnonymous: true,
      },
      JWT_SECRET,
      { expiresIn: '90d' }
    );

    // Log telemetry
    try {
      await prisma.telemetryLog.create({
        data: {
          userId: user.id,
          eventType: 'anonymous_login',
          eventData: {
            deviceId: device.id,
            platform: validated.deviceInfo.platform,
            timestamp: new Date().toISOString(),
          },
        },
      });
    } catch (telemetryError) {
      console.error('[TELEMETRY_ERROR]', telemetryError);
    }

    console.log('[ANONYMOUS_LOGIN] Success:', {
      userId: user.id,
      deviceId: device.deviceId,
    });

    return NextResponse.json({
      success: true,
      data: {
        token,
        refreshToken,
        userId: user.id,
        isAnonymous: true,
        user: {
          id: user.id,
          name: user.name,
        },
        device: {
          id: device.id,
        },
        subscription: {
          tier: subscription.tier,
          status: subscription.status,
          trialEndsAt: subscription.trialEndsAt,
        },
      },
    });
  } catch (error) {
    console.error('[ANONYMOUS_LOGIN_ERROR]', error);

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
        error: 'Anonymous login failed',
      },
      { status: 500 }
    );
  }
}