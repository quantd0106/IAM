import { z } from 'zod';

export const loginSchema = z.strictObject({
  identifier: z.strictObject({
    type: z.enum(['email', 'username']),
    value: z.string().min(1),
  }),
  password: z.string().min(1),
});
