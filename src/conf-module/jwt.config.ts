import { registerAs } from '@nestjs/config';

export const jwtConfig = registerAs('jwt', () => ({
  accessTokenSecret: process.env.JWT_ACCESS_TOKEN_SECRET_KEY!,
  refreshTokenSecret: process.env.JWT_REFRESH_TOKEN_SECRET_KEY!,
  accessTokenExpiresIn: process.env.ACCESS_TOKEN_EXPIRED_IN!,
  refreshTokenExpiresIn: process.env.REFRESH_TOKEN_EXPIRED_IN!,
  verifyEmailSecret: process.env.VERIFY_EMAIL_SECRET_KEY!,
  resetPasswordSecret: process.env.RESET_PASSWORD_SECRET!,
}));
