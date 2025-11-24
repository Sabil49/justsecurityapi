import { PrismaClient, UserRole, ThreatType, Platform, ThreatSeverity, ThreatCategory, QuarantineStatus, AntiTheftCommandType, CommandStatus, AdminAction } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  console.log("🌱 Seeding database...");

  /**
   * ===========================
   * 1. CREATE SUPERADMIN
   * ===========================
   */
  const password = "Admin@123";
  const hashedPassword = await bcrypt.hash(password, 12);

  const admin = await prisma.user.upsert({
    where: { email: "admin@example.com" },
    update: {},
    create: {
      id: "superadmin-1",
      email: "admin@example.com",
      name: "Super Administrator",
      role: UserRole.SUPERADMIN,

      authProvider: "credentials",
      authProviderId: null,
      passwordHash: hashedPassword,
    }
  });
  console.log(`✔ SUPERADMIN created: ${admin.email}`);


  /**
   * ===========================
   * 2. CREATE A NORMAL USER
   * ===========================
   */
  const user = await prisma.user.upsert({
    where: { email: "user@example.com" },
    update: {},
    create: {
      id: "user-001",
      email: "user@example.com",
      name: "Test User",
      role: UserRole.USER,

      authProvider: "google",
      authProviderId: "google-user-id",
      passwordHash: null
    }
  });
  console.log(`✔ User created: ${user.email}`);



  /**
   * ===========================
   * 3. CREATE DEVICE
   * ===========================
   */
  const device = await prisma.device.create({
    data: {
      userId: user.id,
      deviceId: "device-001",
      deviceName: "Pixel 9 Pro",
      platform: Platform.ANDROID,
      osVersion: "14.0",
      appVersion: "1.0.0",
    }
  });
  console.log(`✔ Device created: ${device.deviceName}`);


  /**
   * ===========================
   * 4. CREATE PUSH TOKEN
   * ===========================
   */
  await prisma.pushToken.create({
    data: {
      deviceId: device.id,
      token: "push-token-xyz",
      platform: "android",
    }
  });
  console.log("✔ PushToken created");


  /**
   * ===========================
   * 5. CREATE THREAT SIGNATURES
   * ===========================
   */
  const threatSignature1 = await prisma.threatSignature.create({
    data: {
      type: ThreatType.HASH,
      signature: "a".repeat(64),
      threatName: "Trojan.Android.Generic",
      severity: ThreatSeverity.CRITICAL,
      category: ThreatCategory.TROJAN,
      description: "Highly dangerous malware targeting Android devices.",
      metadata: { info: "initial seed" }
    }
  });

  const threatSignature2 = await prisma.threatSignature.create({
    data: {
      type: ThreatType.PACKAGE,
      signature: "com.fake.adware",
      threatName: "Android.Popup.Adware",
      severity: ThreatSeverity.MEDIUM,
      category: ThreatCategory.ADWARE,
      description: "Annoying popup adware.",
      metadata: { info: "initial seed" } as InputJsonValue | undefined
    }
  });

  console.log("✔ Threat signatures created");



  /**
   * ===========================
   * 6. CREATE SCAN LOG
   * ===========================
   */
  const scanLog = await prisma.scanLog.create({
    data: {
      deviceId: device.id,
      scanType: "full",
      status: "completed",
      filesScanned: 1220,
      threatsFound: 1,
      startedAt: new Date(),
      completedAt: new Date(),
      duration: 2000,
      metadata: { details: "Scan completed successfully" }
    }
  });

  console.log("✔ ScanLog created");



  /**
   * ===========================
   * 7. CREATE QUARANTINE ITEM
   * ===========================
   */
  await prisma.quarantine.create({
    data: {
      deviceId: device.id,
      fileName: "malware.apk",
      filePath: "/storage/emulated/0/Download/malware.apk",
      fileSize: 4024,
      fileHash: "deadbeefcafebabef00df00df00df00d",
      severity: ThreatSeverity.HIGH,
      status: QuarantineStatus.QUARANTINED,

      threatSignatureId: threatSignature1.id,

      storageKey: "quarantine/malware.apk",
      storageUrl: "https://storage.example.com/malware.apk",
      uploadStatus: "uploaded",

      metadata: { quarantineReason: "Detected trojan" }
    }
  });

  console.log("✔ Quarantine item created");



  /**
   * ===========================
   * 8. ANTI-THEFT COMMAND
   * ===========================
   */
  await prisma.antiTheftCommand.create({
    data: {
      deviceId: device.id,
      commandType: AntiTheftCommandType.LOCATE,
      status: CommandStatus.PENDING,
      issuedBy: admin.id,
      metadata: { reason: "Security test" }
    }
  });
  console.log("✔ Anti-theft command created");



  /**
   * ===========================
   * 9. SUBSCRIPTION
   * ===========================
   */
  await prisma.subscription.create({
    data: {
      userId: user.id,
      tier: "free",
      status: "active",
      platform: "android",
      currentPeriodStart: new Date(),
      currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });
  console.log("✔ Subscription created");



  /**
   * ===========================
   * 10. TELEMETRY LOG
   * ===========================
   */
  await prisma.telemetryLog.create({
    data: {
      userId: user.id,
      eventType: "scan_completed",
      eventData: { scanned: 1220, threats: 1 }
    }
  });
  console.log("✔ TelemetryLog created");



  /**
   * ===========================
   * 11. ADMIN AUDIT LOG
   * ===========================
   */
  await prisma.adminAuditLog.create({
    data: {
      adminId: admin.id,
      action: AdminAction.THREAT_UPLOAD,
      targetId: threatSignature1.id,
      metadata: { note: "Initial malware DB import" },
      ipAddress: "127.0.0.1"
    }
  });

  console.log("✔ AdminAuditLog created");


  console.log("🎉 Database seeding complete!");
}


main()
  .catch((e) => {
    console.error("❌ Seed error:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
