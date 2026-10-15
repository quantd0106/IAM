-- CreateEnum
CREATE TYPE "ClientType" AS ENUM ('PUBLIC', 'CONFIDENTIAL');

-- CreateTable
CREATE TABLE "clients" (
    "id" UUID NOT NULL,
    "client_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "client_type" "ClientType" NOT NULL,
    "client_secret_hash" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "access_token_ttl" INTEGER NOT NULL DEFAULT 600,
    "refresh_token_ttl" INTEGER NOT NULL DEFAULT 2592000,

    CONSTRAINT "clients_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "clients_client_id_key" ON "clients"("client_id");
