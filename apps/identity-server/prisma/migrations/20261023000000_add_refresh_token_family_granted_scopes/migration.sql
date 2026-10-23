-- AlterTable
ALTER TABLE "refresh_token_families" ADD COLUMN     "granted_scopes" TEXT[] DEFAULT ARRAY[]::TEXT[];
