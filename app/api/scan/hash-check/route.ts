import { NextRequest, NextResponse } from 'next/server';
export async function GET() {
 return NextResponse.json({ success: true, message: 'Scan hash-check endpoint is working' }); 
}