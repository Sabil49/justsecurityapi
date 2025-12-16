// app/api/auth/verify/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/prisma';
import { createAuthToken } from '@/lib/auth';
import { OAuth2Client } from 'google-auth-library';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { randomUUID } from 'crypto';

interface VerifiedIdentity {
  email: string | null;
  providerId: string;
  name?: string | null;
}

const VerifySchema = z.object({
  idToken: z.string().min(1),
  provider: z.enum(['google', 'apple', 'email']),
  deviceInfo: z.object({
    deviceId: z.string(),
    deviceName: z.string(),
    platform: z.enum(['ios', 'android']),
    osVersion: z.string(),
    appVersion: z.string(),
  }),
});

const googleClient = new OAuth2Client(process.env.GOOGLE_OAUTH_CLIENT_ID);

// Apple JWKS client
const appleKeys = jwksClient({
  jwksUri: 'https://appleid.apple.com/auth/keys',
});

// Helper: get Apple signing key
function getAppleSigningKey(header: jwt.JwtHeader, callback: (err: Error | null, key?: string) => void) {
  appleKeys.getSigningKey(header.kid as string, (err, key) => {
    if (err) return callback(err);
    const signingKey = key?.getPublicKey();
    callback(null, signingKey);
  });
}

async function verifyGoogleToken(idToken: string): Promise<VerifiedIdentity> {
  const ticket = await googleClient.verifyIdToken({
    idToken,
    audience: process.env.GOOGLE_OAUTH_CLIENT_ID,
  });

  const payload = ticket.getPayload();

  if (!payload?.email) {
    throw new Error('Google token verification failed');
  }

  return {
    email: payload.email,
    providerId: payload.sub,
    name: payload.name ?? null,
  };
}

interface AppleTokenPayload {
  email?: string;
  sub: string;
  name?: string;
}

async function verifyAppleToken(idToken: string): Promise<VerifiedIdentity> {
  return new Promise((resolve, reject) => {
    jwt.verify(
      idToken,
      getAppleSigningKey,
      {
        algorithms: ['RS256'],
        issuer: 'https://appleid.apple.com',
      },
      (err, decoded) => {
        if (err) return reject(new Error('Invalid Apple ID token'));

        const payload = decoded as AppleTokenPayload;
        resolve({
          email: payload.email ?? null,
          providerId: payload.sub,
          name: payload.name ?? null,
        });
      }
    );
  });
}

async function verifyProviderToken(
  token: string,
  provider: 'google' | 'apple'
): Promise<VerifiedIdentity> {
  if (provider === 'google') return await verifyGoogleToken(token);
  if (provider === 'apple') return await verifyAppleToken(token);

  throw new Error('Unsupported provider');
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validated = VerifySchema.parse(body);

    // Verify ID token using real provider verification (Google / Apple)
    const verified = await verifyProviderToken(
      validated.idToken,
      validated.provider as 'google' | 'apple'
    );

    // Extract verified identity
    const { email, providerId, name } = verified;

    // If for any reason verification returned invalid data
    if (!email || !providerId) {
      throw new Error('Failed to verify identity token');
    }

    // Check if device belongs to an anonymous user that we should convert
    const existingDevice = await prisma.device.findUnique({
      where: { deviceId: validated.deviceInfo.deviceId },
      include: { user: true },
    });

    let shouldConvertAnonymous = false;
    let anonymousUserId: string | undefined;

    if (existingDevice?.user.isAnonymous) {
      // Device has anonymous user - we'll convert it
      shouldConvertAnonymous = true;
      anonymousUserId = existingDevice.userId;
      console.log('[AUTH_VERIFY] Converting anonymous user to registered:', {
        anonymousUserId,
        email,
      });
    }

    // Upsert user
    const result = await prisma.$transaction(async (tx) => {
      let user;

      if (shouldConvertAnonymous && anonymousUserId) {
        // Convert anonymous user to registered user
        user = await tx.user.update({
          where: { id: anonymousUserId },
          data: {
            email,
            name,
            authProvider: validated.provider,
            authProviderId: providerId,
            isAnonymous: false,
            updatedAt: new Date(),
          },
        });
        
        console.log('[AUTH_VERIFY] Anonymous user converted successfully');
      } else {
        // Regular upsert for non-anonymous users
        user = await tx.user.upsert({
          where: { email },
          update: {
            updatedAt: new Date(),
          },
          create: {
            id: randomUUID(),
            email,
            name,
            authProvider: validated.provider,
            authProviderId: providerId,
            isAnonymous: false,
          },
        });
      }

      // Verify provider ID matches (security check)
      if (user.authProviderId && user.authProviderId !== providerId) {
        throw new Error('Provider ID mismatch');
      }

      // Update provider ID if it was null (converted anonymous user)
      if (!user.authProviderId) {
        user = await tx.user.update({
          where: { id: user.id },
          data: { authProviderId: providerId },
        });
      }

      // Upsert device
      const currentDevice = await tx.device.findUnique({
        where: { deviceId: validated.deviceInfo.deviceId },
      });

      // If device exists and belongs to different non-anonymous user, error
      if (currentDevice && currentDevice.userId !== user.id) {
        const deviceUser = await tx.user.findUnique({
          where: { id: currentDevice.userId },
        });
        
        if (deviceUser && !deviceUser.isAnonymous) {
          throw new Error('Device belongs to another user');
        }
      }

      const device = await tx.device.upsert({
        where: { deviceId: validated.deviceInfo.deviceId },
        update: {
          userId: user.id,
          lastSeen: new Date(),
          osVersion: validated.deviceInfo.osVersion,
          appVersion: validated.deviceInfo.appVersion,
        },
        create: {
          userId: user.id,
          deviceId: validated.deviceInfo.deviceId,
          deviceName: validated.deviceInfo.deviceName,
          platform: validated.deviceInfo.platform.toUpperCase() as 'IOS' | 'ANDROID',
          osVersion: validated.deviceInfo.osVersion,
          appVersion: validated.deviceInfo.appVersion,
        },
      });

      // Check/create subscription
      let subscription = await tx.subscription.findFirst({
        where: { userId: user.id, status: { in: ['active', 'trial'] } },
        orderBy: { createdAt: 'desc' },
      });

      if (!subscription) {
        subscription = await tx.subscription.create({
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

      return { user, device, subscription };
    });

    // Create JWT
    const token = createAuthToken(result.user.id, result.user.email);

    // Log telemetry
    try {
      await prisma.telemetryLog.create({
        data: {
          userId: result.user.id,
          eventType: shouldConvertAnonymous ? 'anonymous_upgrade_social' : 'social_login',
          eventData: {
            provider: validated.provider,
            wasAnonymous: shouldConvertAnonymous,
            deviceId: result.device.id,
            timestamp: new Date().toISOString(),
          },
        },
      });
    } catch (telemetryError) {
      console.error('[TELEMETRY_ERROR]', telemetryError);
    }

    return NextResponse.json({
      success: true,
      data: {
        token,
        refreshToken: token, // You can generate separate refresh token if needed
        user: {
          id: result.user.id,
          email: result.user.email,
          name: result.user.name,
        },
        device: {
          id: result.device.id,
        },
        subscription: {
          tier: result.subscription.tier,
          status: result.subscription.status,
          trialEndsAt: result.subscription.trialEndsAt,
        },
      },
    });
  } catch (error) {
    console.error('[AUTH_VERIFY_ERROR]', {
      message: error instanceof Error ? error.message : 'Unknown error',
      type: error instanceof Error ? error.constructor.name : typeof error,
    });

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { success: false, error: 'Invalid request data' },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { success: false, error: 'Authentication failed' },
      { status: 401 }
    );
  }
}