/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import { Inject, Injectable } from '@nestjs/common';
import * as config_1 from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-google-oauth20';
import { GoogleAuthConfig } from 'src/conf-module/google-auth.config';
import { AuthService } from '../auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'googleAuth') {
  constructor(
    @Inject(GoogleAuthConfig.KEY)
    private readonly config: config_1.ConfigType<typeof GoogleAuthConfig>,
    /** identify auth service */ private readonly authSerivce: AuthService,
  ) {
    super({
      clientID: config.clientID,
      clientSecret: config.clientSecret,
      callbackURL: config.callbackURL,
      scope: ['profile', 'email'],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: Profile) {
    const email = await profile.emails?.[0]?.value;
    const username = await profile.displayName;

    //  find or add user in database
    return await this.authSerivce.loginOrCreateUserUsingGooglAuth(
      email,
      username,
    );
  }
}
