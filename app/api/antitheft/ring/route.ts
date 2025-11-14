import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { prisma } from '@/lib/db';

export async function POST(req: NextRequest) {
  try {
    const user = await verifyToken(req);
    const body = await req.json();
    const { deviceId } = body;
    // Log ring command
    await prisma.antiTheftCommand.create({
      data: {
        userId: user.id,
        deviceId,
        commandType: 'ring',
        commandData: {},
        executedAt: new Date(),
      },
    });

    // In production, send push notification to device to trigger ring
    // using Firebase Cloud Messaging or Apple Push Notification service

    return NextResponse.json({
      success: true,
      message: 'Ring command sent to device',
      status: 200,
    });
  } catch (error) {
    console.error('Ring command error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
