import { registerAs } from '@nestjs/config';

export const VerifyEmail = registerAs('verify_email', () => ({
  mailPass: process.env.MAIL_PASS!,
  mailUser: process.env.MAIL_USER!,
  mailPort: parseInt(process.env.MAIL_PORT!),
  mailHost: process.env.MAIL_HOST!,
}));
