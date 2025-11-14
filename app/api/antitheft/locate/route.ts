import { NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { prisma } from '@/lib/db';

export async function POST(req: Request) {
  try {
    const user = await verifyToken(req);

    const { deviceId, latitude, longitude } = await req.json();

    // Validate required fields
    if (!deviceId || latitude === undefined || longitude === undefined) {
      return NextResponse.json(
        { error: 'Missing required fields: deviceId, latitude, longitude' },
        { status: 400 }
      );
    }

    // Validate coordinates
    const lat = Number(latitude);
    const lng = Number(longitude);

    if (
      isNaN(lat) ||
      isNaN(lng) ||
      lat < -90 ||
      lat > 90 ||
      lng < -180 ||
      lng > 180
    ) {
      return NextResponse.json(
        { error: 'Invalid latitude or longitude values' },
        { status: 400 }
      );
    }

    // Store device location
    await prisma.deviceLocation.create({
      data: {
        userId: user.id,
        deviceId,
        latitude: lat,
        longitude: lng,
        timestamp: new Date(),
      },
    });

    // Fetch latest location for confirmation
    const latestLocation = await prisma.deviceLocation.findFirst({
      where: { userId: user.id, deviceId },
      orderBy: { timestamp: 'desc' },
    });

    return NextResponse.json(
      {
        message: 'Location updated successfully',
        latestLocation,
      },
      { status: 200 }
    );
  } catch (error) {
    console.error(
      'Locate device error:',
      error instanceof Error ? error.message : error
    );

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
