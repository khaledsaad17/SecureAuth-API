import { registerAs } from '@nestjs/config';

export const TwoFactorEncryptionKey = registerAs('2faSecret', () => ({
  secret: process.env.TOW_FACTOR_AUTH_ENCRYPT_KEY!,
}));
