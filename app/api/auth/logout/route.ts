import { NextRequest, NextResponse } from "next/server";
import { verifyAuth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function POST(request: NextRequest) {
  try {
    let userId: string | null = null;

    // Try to verify JWT (but don't fail if invalid)
    try {
      const authUser = await verifyAuth(request);
      userId = authUser.userId;
    } catch (err) {
      console.warn("[LOGOUT] Token already invalid or missing.");
    }

    // Optional: Remove device from DB if deviceId provided
    const { deviceId } = await request.json().catch(() => ({}));

    if (deviceId && userId) {
      await prisma.device.deleteMany({
        where: { deviceId, userId },
      });
    }

    return NextResponse.json({
      success: true,
      message: "Logged out successfully.",
    });
  } catch (err) {
    console.error("[LOGOUT_ERROR]", err);
    return NextResponse.json(
      { success: false, error: "Logout failed" },
      { status: 500 }
    );
  }
}
