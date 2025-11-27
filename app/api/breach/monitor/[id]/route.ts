"use server";
// app/api/breach/monitor/[id]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { verifyAuth } from '@/lib/auth';
import { prisma } from "@/lib/prisma"

export async function DELETE(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const user = await verifyAuth(request);

    const monitoredEmail = await prisma.monitoredEmail.findFirst({
      where: {
        id: params.id,
        userId: user.userId,
      },
    });

    if (!monitoredEmail) {
      return NextResponse.json(
        { success: false, error: 'Monitored email not found' },
        { status: 404 }
      );
    }

    await prisma.monitoredEmail.update({
      where: { id: params.id },
      data: { isMonitored: false },
    });

    return NextResponse.json({
      success: true,
      message: 'Email removed from monitoring',
    });
  } catch (error) {
    console.error('[DELETE_MONITORED_EMAIL_ERROR]', error);

    return NextResponse.json(
      { success: false, error: 'Failed to remove email monitoring' },
      { status: 500 }
    );
  }
}