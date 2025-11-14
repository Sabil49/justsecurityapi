import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { prisma } from '@/lib/db';
import { encrypt } from '@/lib/encryption';

export async function POST(req: NextRequest) {
  try {
    const user = await verifyToken(req);
    const { deviceId, message } = await req.json();
    // Validate inputs
   if (!deviceId || typeof deviceId !== 'string' || !message || typeof message !== 'string') {
       return NextResponse.json({ error: 'deviceId and message are required' }, { status: 400 });
     }
     if (message.length > 1000) {
       return NextResponse.json({ error: 'Message too long (max 1000 characters)' }, { status: 400 });
     }

    // Verify device ownership
    const device = await prisma.device.findFirst({
      where: { id: deviceId, ownerId: user.id }
    });
    
    if (!device) {
      return NextResponse.json({ error: 'Device not found or unauthorized' }, { status: 404 });
    }   
    const encryptedMessage = encrypt(message);

    // Store lock command
    await prisma.antiTheftCommand.create({
      data: {
        userId: user.id,
        deviceId,
        commandType: 'lock',
        commandData: { message: encryptedMessage },
        createdAt: new Date(),
        executedAt: null,
      },
    });

    return NextResponse.json({
      success: true,
      message: 'Lock command sent to device',
    });
  } catch (error) {
    console.error('Lock command error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}