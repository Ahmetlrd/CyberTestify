-- AlterTable
ALTER TABLE "Report" ADD COLUMN     "incomplete" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "incompleteReason" TEXT;
