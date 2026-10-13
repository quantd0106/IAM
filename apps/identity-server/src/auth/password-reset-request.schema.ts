import { z } from 'zod';

export const passwordResetRequestSchema = z.strictObject({
  email: z.string().trim().pipe(z.email()),
});
