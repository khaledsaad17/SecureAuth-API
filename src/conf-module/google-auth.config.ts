import { registerAs } from '@nestjs/config';

export const GoogleAuthConfig = registerAs('googleAuth', () => ({
  clientID: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  callbackURL: process.env.GOOGLE_CALLBACK_URL!,
}));
