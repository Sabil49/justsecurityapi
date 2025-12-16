// app/api/auth/anonymous-register/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/prisma';
import { sign } from 'jsonwebtoken';
import { randomUUID } from 'crypto';

const JWT_SECRET = process.env.JWT_SECRET!;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

const AnonymousRegisterSchema = z.object({
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
    const validated = AnonymousRegisterSchema.parse(body);

    // Check if device already exists
    const existingDevice = await prisma.device.findUnique({
      where: { deviceId: validated.deviceInfo.deviceId },
      include: {
        user: true,
      },
    });

    let user, device, subscription;

    if (existingDevice) {
      // Device exists - check if it belongs to anonymous or registered user
      
      if (existingDevice.user.isAnonymous) {
        // Device has anonymous user, return existing session
        console.log('[ANONYMOUS_REGISTER] Existing anonymous user found:', existingDevice.userId);
        
        user = existingDevice.user;
        device = existingDevice;

        // Update device last seen
        device = await prisma.device.update({
          where: { id: device.id },
          data: {
            lastSeen: new Date(),
            osVersion: validated.deviceInfo.osVersion,
            appVersion: validated.deviceInfo.appVersion,
          },
        });

        // Get subscription
        subscription = await prisma.subscription.findFirst({
          where: {
            userId: user.id,
            status: { in: ['active', 'trial'] },
          },
        });

        if (!subscription) {
          // Create free trial for existing anonymous user without subscription
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
      } else {
        // Device has registered user, return that user's session
        console.log('[ANONYMOUS_REGISTER] Device belongs to registered user:', existingDevice.userId);
        
        user = existingDevice.user;
        device = existingDevice;

        // Update device last seen
        device = await prisma.device.update({
          where: { id: device.id },
          data: {
            lastSeen: new Date(),
            osVersion: validated.deviceInfo.osVersion,
            appVersion: validated.deviceInfo.appVersion,
          },
        });

        // Get subscription
        subscription = await prisma.subscription.findFirst({
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
      }
    } else {
      // No existing device, create new anonymous user
      console.log('[ANONYMOUS_REGISTER] Creating new anonymous user');
      
      const result = await prisma.$transaction(async (tx) => {
        // Create anonymous user
        const user = await tx.user.create({
          data: {
            id: randomUUID(),
            email: null,
            name: `Guest-${validated.deviceInfo.deviceId.slice(0, 8)}`,
            authProvider: 'anonymous',
            passwordHash: null,
            isAnonymous: true,
          },
        });

        // Create device
        const device = await tx.device.create({
          data: {
            userId: user.id,
            deviceId: validated.deviceInfo.deviceId,
            deviceName: validated.deviceInfo.deviceName,
            platform: validated.deviceInfo.platform,
            osVersion: validated.deviceInfo.osVersion,
            appVersion: validated.deviceInfo.appVersion,
            lastSeen: new Date(),
          },
        });

        // Create free trial subscription
        const subscription = await tx.subscription.create({
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

        return { user, device, subscription };
      });

      user = result.user;
      device = result.device;
      subscription = result.subscription;
    }

    // Create JWT tokens
    const token = sign(
      {
        userId: user.id,
        isAnonymous: user.isAnonymous,
        deviceId: validated.deviceInfo.deviceId,
      },
      JWT_SECRET,
      { expiresIn: '30d' } // Longer expiry for guest accounts
    );

    const refreshToken = sign(
      {
        userId: user.id,
        isAnonymous: user.isAnonymous,
      },
      JWT_SECRET,
      { expiresIn: '90d' } // Longer refresh for guest accounts
    );

    // Log telemetry
    try {
      await prisma.telemetryLog.create({
        data: {
          userId: user.id,
          eventType: 'anonymous_register',
          eventData: {
            deviceId: device.id,
            platform: validated.deviceInfo.platform,
            isNewUser: !existingDevice,
            timestamp: new Date().toISOString(),
          },
        },
      });
    } catch (telemetryError) {
      console.error('[TELEMETRY_ERROR]', telemetryError);
      // Continue even if telemetry fails
    }

    console.log('[ANONYMOUS_REGISTER] Success:', {
      userId: user.id,
      isNewUser: !existingDevice,
    });

    return NextResponse.json(
      {
        success: true,
        data: {
          token,
          refreshToken,
          userId: user.id,
          isAnonymous: user.isAnonymous,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
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
      },
      { status: 201 }
    );
  } catch (error) {
    console.error('[ANONYMOUS_REGISTER_ERROR]', error);

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
        error: 'Anonymous registration failed',
      },
      { status: 500 }
    );
  }
}