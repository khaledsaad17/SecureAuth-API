import { Inject, Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import * as config_1 from '@nestjs/config';
import { TwoFactorEncryptionKey } from 'src/conf-module/TwoFactor-Encryption-secert.config';

@Injectable()
export class TwoFactorEncryptionService {
  private logger = new Logger(TwoFactorEncryptionService.name);
  private algorithm = 'aes-256-cbc';
  private key: Buffer;
  constructor(
    @Inject(TwoFactorEncryptionKey.KEY)
    private readonly config: config_1.ConfigType<typeof TwoFactorEncryptionKey>,
  ) {
    this.key = crypto.createHash('sha256').update(config.secret).digest();
  }
  encrypt(text: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);

    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return iv.toString('hex') + ':' + encrypted.toString('hex');
  }

  decrypt(encryptedText: string): string {
    const [ivHex, encryptedHex] = encryptedText.split(':');

    const iv = Buffer.from(ivHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');

    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);

    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString();
  }
}
