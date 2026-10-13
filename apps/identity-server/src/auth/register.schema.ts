import { z } from 'zod';

export const registerSchema = z.strictObject({
  email: z.string().trim().pipe(z.email()),
  username: z.string().trim().min(1),
  // Password policy belongs to later application decisions, not this baseline.
  password: z.string().min(1),
});

export type RegisterInput = z.infer<typeof registerSchema>;
