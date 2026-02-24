import { Module } from '@nestjs/common';
import { ConfModuleService } from './conf-module.service';
import { ConfigModule, ConfigType } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { jwtConfig } from './jwt.config';
import { databaseConfig } from './database.config';
import { VerifyEmail } from './verify-mail.config';
import { LinksUrl } from './links.config';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    /**
     * environment variable config settings
     */
    ConfigModule.forRoot({
      load: [jwtConfig, databaseConfig, VerifyEmail, LinksUrl],
      isGlobal: true,
    }),
    /**
     * database config settings
     */
    MongooseModule.forRootAsync({
      inject: [databaseConfig.KEY],
      useFactory: (config: ConfigType<typeof databaseConfig>) => ({
        uri: config.database_url,
        dbName: config.database_name,
      }),
    }),
    /**
     * Jwt token config settings
     */
    JwtModule.registerAsync({
      inject: [jwtConfig.KEY],
      useFactory: (config: ConfigType<typeof jwtConfig>) => ({
        secret: config.accessTokenSecret,
        global: true,
        signOptions: { expiresIn: '7d' },
      }),
    }),
    /**
     *  Rate limit configuration
     */
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 10000,
          limit: 20,
        },
      ],
    }),
  ],
  providers: [
    ConfModuleService,
    { provide: APP_GUARD, useClass: ThrottlerGuard }, // make throtle run in every route ( global )
  ],
})
export class ConfModuleModule {}
