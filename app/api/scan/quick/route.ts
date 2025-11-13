import { NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { prisma } from '@/lib/db';

export async function POST(req: Request) {
  interface AuthenticatedUser {
  id: string;
  email: string;
}
  // Authenticate
  let user: AuthenticatedUser;
  try {
    user = await verifyToken(req);
  } catch (authErr) {
    console.error('Quick scan auth error:', authErr);
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const body = await req.json();
    const { deviceId, results } = body ?? {};

    // Validate deviceId
    if (typeof deviceId !== 'string' || deviceId.trim() === '') {
      return NextResponse.json({ error: 'Invalid deviceId' }, { status: 400 });
    }

    // Validate results shape: expect object with numeric threatsFound, scannedFiles, duration
    if (
      !results ||
      typeof results !== 'object' ||
      typeof results.threatsFound !== 'number' ||
      typeof results.scannedFiles !== 'number' ||
      typeof results.duration !== 'number'
    ) {
      return NextResponse.json(
        { error: 'Invalid results: expected { threatsFound:number, scannedFiles:number, duration:number }' },
        { status: 400 }
      );
    }

    await prisma.$transaction([
      prisma.scanLog.create({
        data: {
          userId: user.id,
          deviceId,
          scanType: 'quick',
          threatsFound: results.threatsFound,
          filesScanned: results.scannedFiles,
          duration: results.duration,
          timestamp: new Date(),
        },
      }),
      prisma.user.update({
        where: { id: user.id },
        data: {
          totalScans: { increment: 1 },
          totalThreatsBlocked: { increment: results.threatsFound },
          lastScanDate: new Date(),
        },
      }),
    ]);

    return NextResponse.json({ success: true, message: 'Scan completed successfully' }, { status: 200 });
  } catch (error) {
    console.error('Quick scan error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}