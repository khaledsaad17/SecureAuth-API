import { registerAs } from '@nestjs/config';

export const databaseConfig = registerAs('db', () => ({
  database_url: process.env.DB_URL!,
  database_name: process.env.DB_NAME!,
}));
