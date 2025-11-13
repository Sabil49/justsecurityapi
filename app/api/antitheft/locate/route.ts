import { NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { prisma } from '@/lib/db';

export default async function POST(req: Request) {
  if (req.method !== 'POST') {
    return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
  }

  try {
    const user = await verifyToken(req);
    const body = await req.json();
    const { deviceId, latitude, longitude } = body;
  if (!deviceId || latitude === undefined || longitude === undefined) {
    return NextResponse.json({ error: 'Missing required fields: deviceId, latitude, longitude' }, { status: 400 });
  }
     // Validate coordinate types and ranges
    const lat = Number(latitude);
    const lng = Number(longitude);
   if (isNaN(lat) || isNaN(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
      return NextResponse.json({ error: 'Invalid latitude or longitude values' }, { status: 400 });
   }
    // Store device location
    await prisma.deviceLocation.create({
      data: {
        userId: user.id,
        deviceId,
        latitude,
        longitude,
        timestamp: new Date(),
      },
    });

    // Get latest location
    const latestLocation = await prisma.deviceLocation.findFirst({
      where: {
        userId: user.id,
        deviceId,
      },
      orderBy: {
        timestamp: 'desc',
      },
    });
  } catch (error) {
    console.error('Locate device error:', error instanceof Error ? error.message : 'Unknown error');
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}