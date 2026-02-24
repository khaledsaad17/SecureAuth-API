/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import {
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import * as config_1 from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import SMTPTransport from 'nodemailer/lib/smtp-transport';
import { Transporter } from 'nodemailer';
import { VerifyEmail } from 'src/conf-module/verify-mail.config';
import { join } from 'path';
import { existsSync, readFileSync } from 'fs';
import { LinksUrl } from 'src/conf-module/links.config';
@Injectable()
export class MailService {
  private readonly transporter: Transporter;
  private readonly logger = new Logger(MailService.name);

  constructor(
    @Inject(VerifyEmail.KEY)
    private readonly mailConfig: config_1.ConfigType<typeof VerifyEmail>,
    @Inject(LinksUrl.KEY)
    private readonly linkConfig: config_1.ConfigType<typeof LinksUrl>,
  ) {
    const transportOptions: SMTPTransport.Options = {
      host: this.mailConfig.mailHost,
      port: this.mailConfig.mailPort,
      secure: false,
      auth: {
        user: this.mailConfig.mailUser,
        pass: this.mailConfig.mailPass,
      },
    };
    this.transporter = nodemailer.createTransport(transportOptions);
  }
  /**
   * send verification email
   * @param to email of user
   * @param ProjectName type of project need to send verify email
   * @param verificationToken the token to make verification
   */
  async sendVerificationEmail(
    to: string,
    verificationToken: string,
    ProjectName: string = 'Testing Verification Email',
  ) {
    try {
      const templatePath = join(
        __dirname,
        'html/users/mails/html/verify-templet.html',
      );
      let html = readFileSync(templatePath, 'utf8');

      const verificationLink = `${this.linkConfig.backendUrl}/verify-email?token=${verificationToken}`;

      // replace placeholders
      html = html
        .replace('{{APP_NAME}}', ProjectName)
        .replace('{{VERIFY_LINK}}', verificationLink);

      await this.transporter.sendMail({
        from: `"My SecureAuth Api App" <${this.mailConfig.mailUser}>`,
        to,
        subject: 'Verify Your Email',
        html,
      });
      this.logger.log(`Verification email sent to ${to}`);
    } catch (error) {
      this.logger.error(error);
    }
  }

  /** send reset password mail */
  async sendResetPasswordMail(to: string, resetLink: string) {
    const expirationDate = new Date();
    expirationDate.setHours(expirationDate.getHours() + 2); // 2 hours from now
    try {
      const templatePath = join(
        __dirname,
        'html/users/mails/html/reset-password-tmeplet.html',
      );
      let html = readFileSync(templatePath, 'utf8');

      // replace placeholders
      html = html
        .replace('{{reset_link}}', resetLink)
        .replace('{{expiry_duration}}', ' 2 hours ')
        .replace(
          '{{expiry_date}}',
          expirationDate.toLocaleString('en-US', {
            month: 'long',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            timeZoneName: 'short',
          }),
        );

      const info = await this.transporter.sendMail({
        from: `"SecureAuth" <${this.mailConfig.mailUser}>`,
        to,
        subject: 'Password Reset Request',
        html,
      });

      this.logger.log(`📨 Reset mail sent to ${to}`);
      return info;
    } catch (error) {
      this.logger.error('❌ Failed to send reset email', error);
      throw new InternalServerErrorException();
    }
  }
}
