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
    // Scalar shape only; the resolved-client PKCE policy owns pair/method/format.
    code_challenge: z.string().optional(),
    code_challenge_method: z.string().optional(),
  })
  .superRefine((input, context) => {
    if (input.scope.includes('openid') && input.nonce === undefined)
      context.addIssue({
        code: 'custom',
        path: ['nonce'],
        message: 'Required.',
      });
  });

export type AuthorizationRequest = z.infer<typeof authorizationRequestSchema>;
