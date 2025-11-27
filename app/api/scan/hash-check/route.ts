// app/api/scan/hash-check/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/prisma';
import { verifyAuth } from '@/lib/auth';
import { rateLimit } from '@/lib/rate-limit';
import { Redis } from '@upstash/redis';

if (!process.env.UPSTASH_REDIS_REST_URL || !process.env.UPSTASH_REDIS_REST_TOKEN) {
  throw new Error('Missing required Redis environment variables');
}
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const HashCheckSchema = z.object({
  hashes: z.array(z.string().length(64)).min(1).max(100), // SHA-256 hashes
  deviceId: z.string(),
});

interface ThreatResult {
  hash: string;
  isThreat: boolean;
  threatName?: string;
  severity?: string;
  category?: string;
}

export async function POST(request: NextRequest) {
  try {
    const user = await verifyAuth(request);
    console.log('Authenticated user:', user);

    // Rate limit
    const { success } = await rateLimit(`hash_check:${user.userId}`, 50, 60);
    if (!success) {
      return NextResponse.json(
        { success: false, error: 'Too many requests' },
        { status: 429 }
      );
    }

    const body = await request.json();
    const validated = HashCheckSchema.parse(body);
    console.log('Request body validated:', validated);

    // Validate device ownership
    const device = await prisma.device.findFirst({
      where: {
        deviceId: validated.deviceId,
        userId: user.userId,
      },
    });

    if (!device) {
      return NextResponse.json(
        { success: false, error: 'Device not found' },
        { status: 404 }
      );
    }

    const results: ThreatResult[] = [];
    const uncachedHashes: string[] = [];

    // Try cache
    try {
      const cacheKeys = validated.hashes.map(h => `threat:${h}`);
      const cachedResults = await redis.mget<(ThreatResult | null)[]>(...cacheKeys);

      validated.hashes.forEach((hash, i) => {
        const cached = cachedResults[i];
        if (cached) {
          console.log(`Cache hit: ${hash}`);
          results.push(cached);
        } else {
          uncachedHashes.push(hash);
        }
      });
    } catch (err) {
      console.error('[REDIS_ERROR]', err);
      uncachedHashes.push(...validated.hashes);
    }

    // If everything was cached, return early
    if (uncachedHashes.length === 0) {
      const threatsFound = results.filter(r => r.isThreat).length;

      return NextResponse.json({
        success: true,
        data: {
          results,
          scanned: validated.hashes.length,
          threatsFound,
        },
      });
    }
    console.log('Uncached hashes to check:', uncachedHashes.length);
    // Query uncached hashes
    const threats = await prisma.threatSignature.findMany({
      where: {
        signature: { in: uncachedHashes },
        type: 'HASH',
        isActive: true,
      },
      select: {
        signature: true,
        threatName: true,
        severity: true,
        category: true,
      },
    });

    console.log('Threats found in database:', threats.length);

    const threatMap = new Map(
      threats.map(t => [t.signature, t])
    );

    const pipeline = redis.pipeline();

    for (const hash of uncachedHashes) {
      const threat = threatMap.get(hash);

      const result: ThreatResult = threat
        ? {
            hash,
            isThreat: true,
            threatName: threat.threatName ?? undefined,
            severity: threat.severity ?? undefined,
            category: threat.category ?? undefined,
          }
        : {
            hash,
            isThreat: false,
          };

      results.push(result);

      // Cache result
      pipeline.setex(`threat:${hash}`, 3600, JSON.stringify(result));
    }
    console.log('Caching results for uncached hashes');
    await pipeline.exec();

    const threatsFound = results.filter(r => r.isThreat).length;
    console.log('Total threats found:', threatsFound);
    // Telemetry only if threats found
    if (threatsFound > 0) {
      await prisma.telemetryLog.create({
        data: {
          userId: user.userId,
          eventType: 'threats_detected',
          eventData: {
            deviceId: device.id,
            count: threatsFound,
            timestamp: new Date(),
          },
        },
      });
    }
    console.log('Telemetry log created for threats detected');
    // ALWAYS RETURN HERE
    return NextResponse.json({
      success: true,
      data: {
        results,
        scanned: validated.hashes.length,
        threatsFound,
      },
    });

  } catch (error) {
    console.error('[HASH_CHECK_ERROR]', error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { success: false, error: 'Invalid request data' },
        { status: 400 }
      );
    }
    console.log('Unhandled error:', error);
    return NextResponse.json(
      { success: false, error: 'Hash check failed' },
      { status: 500 }
    );
  }
}
