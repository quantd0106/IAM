-- Nullable issuance configuration only; existing registrations remain unconfigured.
ALTER TABLE "clients" ADD COLUMN "access_token_audience" TEXT;
