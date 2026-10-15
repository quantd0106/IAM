-- CreateTable
CREATE TABLE "scopes" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,

    CONSTRAINT "scopes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "client_scopes" (
    "client_id" UUID NOT NULL,
    "scope_id" UUID NOT NULL,

    CONSTRAINT "client_scopes_pkey" PRIMARY KEY ("client_id","scope_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "scopes_name_key" ON "scopes"("name");

-- AddForeignKey
ALTER TABLE "client_scopes" ADD CONSTRAINT "client_scopes_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "clients"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "client_scopes" ADD CONSTRAINT "client_scopes_scope_id_fkey" FOREIGN KEY ("scope_id") REFERENCES "scopes"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
