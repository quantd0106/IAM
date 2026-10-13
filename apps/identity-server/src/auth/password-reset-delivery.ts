export interface PasswordResetDelivery {
  deliver(input: { email: string; token: string }): Promise<void>;
}

export const PASSWORD_RESET_DELIVERY = Symbol('PASSWORD_RESET_DELIVERY');

// Out-of-band delivery is deliberately not integrated in M2.8.
// Never expose tokens through HTTP or logs to compensate for this placeholder.
export const noOpPasswordResetDelivery: PasswordResetDelivery = {
  deliver: () => Promise.resolve(),
};
