import { NextResponse,NextRequest} from 'next/server';
import { verifyToken } from '@/lib/auth';
import { checkThreatDatabase } from '@/lib/threatIntelligence';


export default async function POST(req: NextRequest) {
  if (req.method !== 'POST') {
    return NextResponse.json({ error: 'Method not allowed' }, { status: 405 });
  }
  try {
    const body = await req.json();
    const hash = body.hash;
      try {
    const user = await verifyToken(req);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    if (!hash) {
      return NextResponse.json({ error: 'Hash is required' }, { status: 400 });
    }

    if (typeof hash !== 'string' || !/^[a-fA-F0-9]{32,128}$/.test(hash)) {
      return NextResponse.json({ error: 'Invalid hash format. Expected hex string.' }, { status: 400 });
    }
    // Check against threat intelligence database
    const threat = await checkThreatDatabase(hash);

    if (threat) {
      return NextResponse.json({
        isThreat: true,
        type: threat.type,
        severity: threat.severity,
        name: threat.name,
        description: threat.description,
      });
    }

    return NextResponse.json({ isThreat: false });
  } catch (error) {
    // Authentication errors should return 401
    if (error instanceof Error && error.message.includes('auth')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    console.error('Hash check error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
  } catch (error) {
    console.error('Hash check route error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
