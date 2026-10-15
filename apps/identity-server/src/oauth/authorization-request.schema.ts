import { z } from 'zod';

const opaque = z.string().min(1);
// RFC 6749 section 3.3: scope-token *( SP scope-token ). No trim/filter/defaults.
const scope = opaque
  .transform((value) => value.split(' '))
  .pipe(
    z.array(
      z
        .string()
        .min(1)
        .refine((token) => !/[^\x21\x23-\x5B\x5D-\x7E]/.test(token)),
    ),
  );

// OAuth ignores unrecognized parameters. Known parameters must remain scalar;
// Express/framework decoding is the only decoding performed at this boundary.
export const authorizationRequestSchema = z
  .object({
    response_type: opaque,
    client_id: opaque,
    redirect_uri: opaque,
    scope,
    state: opaque,
    nonce: opaque.optional(),
    code_challenge: opaque.optional(),
    code_challenge_method: z.literal('S256').optional(),
  })
  .superRefine((input, context) => {
    if (input.scope.includes('openid') && input.nonce === undefined)
      context.addIssue({
        code: 'custom',
        path: ['nonce'],
        message: 'Required.',
      });
    if (
      input.code_challenge !== undefined &&
      input.code_challenge_method !== 'S256'
    )
      context.addIssue({
        code: 'custom',
        path: ['code_challenge_method'],
        message: 'S256 required.',
      });
  });

export type AuthorizationRequest = z.infer<typeof authorizationRequestSchema>;
