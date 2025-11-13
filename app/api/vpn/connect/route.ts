import { NextRequest, NextResponse } from 'next/server';
import { verifyToken } from '@/lib/auth';
import { prisma } from '@/lib/db';

export async function POST(req: NextRequest) {
  try {
    const user = await verifyToken(req);
    const body = await req.json();
    const { location } = body;
    
    if (!location || typeof location !== 'string' || location.trim().length === 0) {
      return NextResponse.json({ error: 'Invalid location parameter' }, { status: 400 });
    }
    const userProfile = await prisma.user.findUnique({
      where: { id: user.id },
    });
    if (!userProfile) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }
    if (!userProfile.isPremium) {
      return NextResponse.json({ error: 'VPN service is available for premium users only' }, { status: 403 });
    }
    // In production, integrate with actual VPN provider (WireGuard, OpenVPN, etc.)
    // This is a simplified example
    const vpnSession = await prisma.vPNSession.create({
      data: {
        userId: user.id,
        serverLocation: location,
        connectedAt: new Date(),
        isActive: true,
      },
    });

    return NextResponse.json({
      success: true,
      sessionId: vpnSession.id,
      serverLocation: location,
      serverIp: '198.51.100.1', // Example IP
      message: 'VPN connected successfully',
    });
  } catch (error) {
    console.error('VPN connect error:', error instanceof Error ? error.message : 'Unknown error');
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}