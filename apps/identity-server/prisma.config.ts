import 'dotenv/config';
import { defineConfig } from 'prisma/config';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: {
    // Generation needs no live database or URL; connection commands require it.
    url: process.env.DATABASE_URL ?? '',
  },
});
