/*
  Warnings:

  - You are about to drop the column `role` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "role";

-- CreateTable
CREATE TABLE "MonitoredEmail" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "breachCount" INTEGER NOT NULL DEFAULT 0,
    "lastChecked" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "isMonitored" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MonitoredEmail_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "MonitoredEmail_userId_idx" ON "MonitoredEmail"("userId");

-- CreateIndex
CREATE INDEX "MonitoredEmail_email_idx" ON "MonitoredEmail"("email");

-- CreateIndex
CREATE INDEX "MonitoredEmail_isMonitored_idx" ON "MonitoredEmail"("isMonitored");

-- CreateIndex
CREATE UNIQUE INDEX "MonitoredEmail_userId_email_key" ON "MonitoredEmail"("userId", "email");

-- AddForeignKey
ALTER TABLE "MonitoredEmail" ADD CONSTRAINT "MonitoredEmail_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
