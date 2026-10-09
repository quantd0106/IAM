import 'dotenv/config';
import { runSeed } from './seed.runner.js';

try {
  const datasetsApplied = await runSeed(process.env.DATABASE_URL);
  console.log(`Seed completed: ${datasetsApplied} datasets applied.`);
} catch {
  // Never print caught errors: driver messages can contain connection secrets.
  console.error(
    process.env.DATABASE_URL?.trim()
      ? 'Seed failed: check database configuration and connectivity.'
      : 'Seed failed: DATABASE_URL is required.',
  );
  process.exitCode = 1;
}
