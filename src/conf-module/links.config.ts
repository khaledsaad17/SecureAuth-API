import { registerAs } from '@nestjs/config';

export const LinksUrl = registerAs('link', () => ({
  backendUrl: process.env.BACKEND_URL!,
  frontendUrl: process.env.FRONTEND_URL!,
}));
