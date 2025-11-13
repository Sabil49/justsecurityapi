import { NextRequest, NextResponse } from 'next/server';

export async function GET(req: NextRequest) {

  try {
    const plans = [
      {
        id: 'monthly',
        name: 'Premium Monthly',
        price: 299,
        currency: 'INR',
        interval: 'month',
        features: [
          'Real-time Protection',
          'Secure VPN',
          'App Lock',
          'Scheduled Scans',
          'Ad-free Experience',
          'Priority Support',
        ],
      },
      {
        id: 'yearly',
        name: 'Premium Yearly',
        price: 2499,
        currency: 'INR',
        interval: 'year',
        features: [
          'Real-time Protection',
          'Secure VPN',
          'App Lock',
          'Scheduled Scans',
          'Ad-free Experience',
          'Priority Support',
          'Save 30%',
        ],
        discount: 30,
      },
    ];

    return NextResponse.json({ plans }, { status: 200 });
  } catch (error) {
    console.error('Get plans error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}