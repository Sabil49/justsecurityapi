import { NextRequest, NextResponse } from "next/server";
import { verifyAuth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function GET(request: NextRequest) {
  try {
    // Validate token from Authorization: Bearer <token>
    const authUser = await verifyAuth(request);

    // Fetch user from DB (extra safety — optional)
    const user = await prisma.user.findUnique({
      where: { id: authUser.userId },
      select: {
        id: true,
        email: true,
        name: true,
      },
    });

    if (!user) {
      return NextResponse.json({ valid: false }, { status: 401 });
    }

    return NextResponse.json({
      valid: true,
      user,
    });
  } catch (err) {
    return NextResponse.json({ valid: false }, { status: 401 });
  }
}
