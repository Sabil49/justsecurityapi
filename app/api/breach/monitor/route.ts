// app/api/breach/monitor/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { verifyAuth } from '@/lib/auth';
import {prisma} from "@/lib/prisma";

const MonitorEmailSchema = z.object({
  email: z.email({ message: 'Invalid email address' }),
});

export async function POST(request: NextRequest) {
  try {
    const user = await verifyAuth(request);

    const body = await request.json();
    const validated = MonitorEmailSchema.parse(body);

    // Check if already monitoring
    const existing = await prisma.monitoredEmail.findFirst({
      where: {
        userId: user.userId,
        email: validated.email,
      },
    });

    if (existing) {
      return NextResponse.json({
        success: true,
        data: {
          monitoredEmail: existing,
        },
      });
    }

    // Create monitored email
    const monitoredEmail = await prisma.monitoredEmail.create({
      data: {
        userId: user.userId,
        email: validated.email,
        breachCount: 0,
        lastChecked: new Date(),
        isMonitored: true,
      },
    });

    return NextResponse.json({
      success: true,
      data: {
        monitoredEmail,
      },
    });
  } catch (error) {
    console.error('[MONITOR_EMAIL_ERROR]', error);

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { success: false, error: 'Invalid request data' },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { success: false, error: 'Failed to add email monitoring' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    const user = await verifyAuth(request);

    const emails = await prisma.monitoredEmail.findMany({
      where: {
        userId: user.userId,
        isMonitored: true,
      },
      orderBy: {
        lastChecked: 'desc',
      },
    });

    return NextResponse.json({
      success: true,
      data: { emails },
    });
  } catch (error) {
    console.error('[GET_MONITORED_EMAILS_ERROR]', error);

    return NextResponse.json(
      { success: false, error: 'Failed to get monitored emails' },
      { status: 500 }
    );
  }
}