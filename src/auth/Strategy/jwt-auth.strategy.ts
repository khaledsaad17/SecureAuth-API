import { Inject, Injectable, Logger } from '@nestjs/common';
import * as config_1 from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { TokenPayload } from '../DTO/payload.interface';
import { jwtConfig } from 'src/conf-module/jwt.config';

@Injectable()
export class JwtAuthStrategy extends PassportStrategy(Strategy, 'JwtVerify') {
  private logger = new Logger(JwtAuthStrategy.name);
  constructor(
    @Inject(jwtConfig.KEY)
    private readonly config: config_1.ConfigType<typeof jwtConfig>,
  ) {
    super({
      secretOrKey: config.accessTokenSecret,
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
    });
  }

  validate(payload: TokenPayload): TokenPayload {
    this.logger.log('this user info intered system with this info', payload);
    return payload;
  }
}
