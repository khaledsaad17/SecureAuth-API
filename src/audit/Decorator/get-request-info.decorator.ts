import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UAParser } from 'ua-parser-js';
import { Request } from 'express';

export interface RequestInfo {
  ipAddress: string;
  userAgent: string;
  deviceName: string;
  browser: string;
  os: string;
  rawHeaders: any;
}

export const GetRequestInfo = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): RequestInfo => {
    const request: Request = ctx.switchToHttp().getRequest();

    const ip =
      (request.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      request.socket.remoteAddress ||
      request.ip;

    const userAgent = request.headers['user-agent'] || '';

    const parser = new UAParser(userAgent);
    const result = parser.getResult();

    const deviceName = result.device.model || result.device.type || 'Desktop';

    const browser = `${result.browser.name || ''} ${result.browser.version || ''}`;
    const os = `${result.os.name || ''} ${result.os.version || ''}`;

    return {
      ipAddress: ip || 'not found',
      userAgent,
      deviceName,
      browser,
      os,
      rawHeaders: request.headers,
    };
  },
);
