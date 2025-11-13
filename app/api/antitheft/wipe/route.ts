import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { prisma } from '@/lib/db';

export async function POST(req: NextRequest) {
  if (req.method !== 'POST') {
    return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
  }

  try {
    const user = await verifyToken(req);
    const body = await req.json();
    const { deviceId, confirmationCode } = body;

    if (!deviceId || typeof deviceId !== 'string') {
      return NextResponse.json({ error: 'Valid deviceId is required' }, { status: 400 });
    }

    if (!confirmationCode || typeof confirmationCode !== 'string') {
      return NextResponse.json({ error: 'Valid confirmationCode is required' }, { status: 400 });
    }
    // Verify confirmation code for extra security
    if (confirmationCode !== user.id.substring(0, 6)) {
      return NextResponse.json({ error: 'Invalid confirmation code' }, { status: 403 });
    }
    
    // Store wipe command
    await prisma.antiTheftCommand.create({
      data: {
        userId: user.id,
        deviceId,
        commandType: 'wipe',
        executedAt: new Date(),
      },
    });

    // Log critical action
    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'device_wipe_initiated',
        deviceId,
        timestamp: new Date(),
      },
    });

    return NextResponse.json({ message: 'Wipe command issued successfully' }, { status: 200 });
  } catch (error) {
    console.error('Wipe command error:', error instanceof Error ? error.message : 'Unknown error');
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}