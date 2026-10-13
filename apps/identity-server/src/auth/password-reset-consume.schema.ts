import { z } from 'zod';

export const passwordResetConsumeSchema = z.strictObject({
  token: z.string().min(1),
  // Both values are opaque: do not trim, normalize or impose complexity rules.
  newPassword: z.string().min(1),
});
