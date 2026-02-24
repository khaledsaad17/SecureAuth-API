import { Inject, Injectable, Logger } from '@nestjs/common';
import * as config_1 from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { jwtConfig } from 'src/conf-module/jwt.config';
import { TokenPayload } from '../DTO/payload.interface';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'refreshToken',
) {
  private logger = new Logger(RefreshTokenStrategy.name);
  constructor(
    @Inject(jwtConfig.KEY)
    private readonly config: config_1.ConfigType<typeof jwtConfig>,
  ) {
    super({
      secretOrKey: config.refreshTokenSecret,
      ignoreExpiration: false,
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    });
  }
  validate(payload: TokenPayload): TokenPayload {
    this.logger.log(
      `user with this email = ${payload.email} send refresh token to generate new and valid accessToken`,
    );
    return payload;
  }
}
