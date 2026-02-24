/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { Injectable } from '@nestjs/common';

@Injectable()
export class TwoFaService {
  /**
   * here we should not store secret to database untill user used qrcode and store first code correct
   */
  async generateTwoFactorSecret(email: string) {
    const secret = speakeasy.generateSecret({
      length: 20,
      name: 'SecureAuth',
      issuer: email,
    });

    if (!secret.otpauth_url) {
      throw new Error('Failed to generate OTP auth URL');
    }

    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    return {
      secret: secret.base32,
      qrCode,
    };
  }

  verifyCode(secret: string, token: string) {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1,
    });
  }
}
