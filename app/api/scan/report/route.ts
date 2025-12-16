// app/api/scan/report/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/prisma';
import { verifyAuth } from '@/lib/auth';
import { randomUUID } from 'crypto';


const ScanReportSchema = z.object({
  deviceId: z.string(),
  scanType: z.enum(['quick', 'full', 'custom']),
  status: z.enum(['completed', 'failed', 'cancelled']),
  filesScanned: z.number().int().min(0),
  threatsFound: z.number().int().min(0),
  startedAt: z.iso.datetime(),
  completedAt: z.iso.datetime().optional(),
  threats: z
    .array(
      z.object({
        fileName: z.string(),
        filePath: z.string(),
        fileHash: z.string(),
        threatName: z.string(),
        severity: z.enum(['low', 'medium', 'high', 'critical']),
      })
    )
    .optional(),
});
console.log('ScanReportSchema defined:', ScanReportSchema);
export async function POST(request: NextRequest) {
  try {
    const user = await verifyAuth(request);
    console.log('Authenticated user:', user);
    if (!user) {
      return NextResponse.json(
        { success: false, error: 'Unauthorized' },
        { status: 401 }
      );
    }

    const body = await request.json();
    console.log('Request body:', body);
    const validated = ScanReportSchema.parse(body);
    console.log('Request body validated:', validated);
    // Verify device ownership
    const device = await prisma.device.findFirst({
      where: {
        deviceId: validated.deviceId,
        userId: user.userId,
      },
    });
    console.log('Device lookup result:', device);
    if (!device) {
      return NextResponse.json(
        { success: false, error: 'Device not found' },
        { status: 404 }
      );
    }
    console.log('Device lookup result:', device);
    const startedAt = new Date(validated.startedAt);
    const completedAt = validated.completedAt
      ? new Date(validated.completedAt)
      : new Date();
    
    if (startedAt > completedAt) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid timestamps: startedAt must be before or equal to completedAt',
        },
        { status: 400 }
      );
    }
    console.log('Timestamp validation passed:', { startedAt, completedAt });

    const duration = completedAt.getTime() - startedAt.getTime();
    console.log('Calculated scan duration (ms):', duration);
    // Create scan log + quarantine + telemetry
    const scanLog = await prisma.$transaction(async (tx) => {
      const scanLog = await tx.scanLog.create({
        data: {
          deviceId: device.id,
          scanType: validated.scanType,
          status: validated.status,
          filesScanned: validated.filesScanned,
          threatsFound: validated.threatsFound,
          startedAt,
          completedAt:
            validated.status === 'completed' ? completedAt : null,
          duration:
            validated.status === 'completed' ? duration : null,
          metadata: validated.threats
            ? { threats: validated.threats }
            : undefined,
        },
      });
      console.log('Scan log created:', scanLog);
      // If threats exist → save to quarantine
      if (validated.threats && validated.threats.length > 0) {
        await tx.quarantine.createMany({
          data: validated.threats.map((threat) => ({
            deviceId: device.id,
            fileName: threat.fileName,
            filePath: threat.filePath,
            fileSize: 0,
            fileHash: threat.fileHash,
            threatName: threat.threatName,
            threatSignatureId: randomUUID(),
            severity: threat.severity.toUpperCase() as
              | 'LOW'
              | 'MEDIUM'
              | 'HIGH'
              | 'CRITICAL',
            status: 'QUARANTINED',
          })),
        });
      }
      console.log('Quarantine entries created for threats');
      // Always log telemetry
      await tx.telemetryLog.create({
        data: {
          userId: user.userId,
          eventType: 'scan_completed',
          eventData: {
            scanType: validated.scanType,
            filesScanned: validated.filesScanned,
            threatsFound: validated.threatsFound,
            duration,
          },
        },
      });
      console.log('Telemetry log created for scan completion');
      return scanLog;
    });

    return NextResponse.json({
      success: true,
      data: {
        scanLogId: scanLog.id,
      },
    });
  } catch (error: unknown) {
    console.error('[SCAN_REPORT_ERROR]', error);
    console.log('Error details:', error);
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { success: false, error: 'Invalid request data' },
        { status: 400 }
      );
    }
    console.log('Unhandled error:', error);
    return NextResponse.json(
      { success: false, error: 'Scan report failed' },
      { status: 500 }
    );
  }
}
