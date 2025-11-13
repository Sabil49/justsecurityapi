import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { prisma } from '@/lib/db';

const JWT_SECRET = process.env.JWT_SECRET as string;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}
export async function POST(req: NextRequest) {
  if (req.method !== 'POST') {
    return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
  }

  try {
    const { email, password, name } = await req.json();

    if (!email || !password || !name) {
      return NextResponse.json({ error: 'All fields are required' }, { status: 400 });
    }
    // Validate email format
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
if (!emailRegex.test(email)) {
  return NextResponse.json({ error: 'Invalid email format' }, { status: 400 });
}

// Validate password strength
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
if (!passwordRegex.test(password)) {
  return NextResponse.json({ 
    error: 'Password must be at least 8 characters and contain uppercase, lowercase, number, and special character' 
  }, { status: 400 });
}
// Validate name length
if (name.length < 2 || name.length > 100) {
  return NextResponse.json({ error: 'Name must be between 2 and 100 characters' }, { status: 400 });
}

// Check if user exists
const existingUser = await prisma.user.findUnique({
  where: { email },
});

    if (existingUser) {
      return NextResponse.json({ error: 'User already exists' }, { status: 400 });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
        isPremium: false,
        totalScans: 0,
        totalThreatsBlocked: 0,
      },
    });

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    return NextResponse.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        isPremium: user.isPremium,
      },
    });
  } catch (error) {
     if (process.env.NODE_ENV === 'development') {
    console.error('Registration error:', error);
  } else {
    // Use structured logging in production with PII redaction
    console.error('Registration error:', { message: error instanceof Error ? error.message : 'Unknown error' });
  }
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}