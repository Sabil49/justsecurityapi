"use server";

import { NextRequest, NextResponse } from "next/server";
import { verifyAuth } from "@/lib/auth";

const HIBP_API_KEY = process.env.HIBP_API_KEY!;
const HIBP_API = "https://haveibeenpwned.com/api/v3";

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ name: string }> }
) {
  try {
    await verifyAuth(request);

    const { name } = await context.params;

    const response = await fetch(
      `${HIBP_API}/breach/${encodeURIComponent(name)}`,
      {
        headers: {
          "hibp-api-key": HIBP_API_KEY,
          "user-agent": "AVG-Antivirus-App",
        },
      }
    );

    if (response.status === 404) {
      return NextResponse.json(
        { success: false, error: "Breach not found" },
        { status: 404 }
      );
    }

    if (!response.ok) {
      throw new Error(`HIBP API error: ${response.status}`);
    }

    const breach = await response.json();

    return NextResponse.json({
      success: true,
      data: { breach },
    });
  } catch (error) {
    console.error("[GET_BREACH_DETAILS_ERROR]", error);

    return NextResponse.json(
      { success: false, error: "Failed to get breach details" },
      { status: 500 }
    );
  }
}
