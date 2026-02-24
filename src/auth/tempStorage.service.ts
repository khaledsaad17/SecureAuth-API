/* eslint-disable @typescript-eslint/no-unsafe-return */
import { Injectable, BadRequestException } from '@nestjs/common';
import Redis from 'ioredis';

@Injectable()
export class tempStorageService {
  private redis: Redis;

  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'redis',
      port: Number(process.env.REDIS_PORT) || 6379,
    });
  }

  async createTempToken(tokens: { accessToken: string; refreshToken: string }) {
    const tempId = crypto.randomUUID();
    await this.redis.set(
      `oauth:${tempId}`,
      JSON.stringify(tokens),
      'EX',
      300, // مدة الصلاحية بالثواني
    );
    return tempId;
  }

  async consumeTempToken(tempId: string) {
    const data = await this.redis.get(`oauth:${tempId}`);
    if (!data) throw new BadRequestException('Invalid or expired tempId');

    await this.redis.del(`oauth:${tempId}`); // one-time use
    return JSON.parse(data);
  }
}
