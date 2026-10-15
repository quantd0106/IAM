-- CreateTable
CREATE TABLE "client_redirect_uris" (
    "id" UUID NOT NULL,
    "client_id" UUID NOT NULL,
    "redirect_uri" TEXT NOT NULL,

    CONSTRAINT "client_redirect_uris_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "client_redirect_uris_client_id_redirect_uri_key" ON "client_redirect_uris"("client_id", "redirect_uri");

-- AddForeignKey
ALTER TABLE "client_redirect_uris" ADD CONSTRAINT "client_redirect_uris_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "clients"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
