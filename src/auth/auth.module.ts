import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtAuthStrategy } from './Strategy/jwt-auth.strategy';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGard } from './guards/auth.guard';
import { ConfigModule } from '@nestjs/config';
import { UsersModule } from 'src/users/users.module';
import { JwtService } from '@nestjs/jwt';
import { TwoFactorEncryptionService } from 'src/common/encryption/TwoFactor-Encryption-secert.service';
import { TwoFactorEncryptionKey } from 'src/conf-module/TwoFactor-Encryption-secert.config';
import { RefreshTokenStrategy } from './Strategy/refresh-auth.strategy';
import { RefreshTokenGuard } from './guards/refresh-token.guard';
import { GoogleAuthConfig } from 'src/conf-module/google-auth.config';
import { GoogleStrategy } from './Strategy/google-auth.strategy';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { tempStorageService } from './tempStorage.service';
import { TwoFaModule } from 'src/two-fa/two-fa.module';
import { UsersProjectsModule } from 'src/users-projects/users-projects.module';
import { AuditModule } from 'src/audit/audit.module';

@Module({
  imports: [
    AuditModule,
    ConfigModule.forFeature(TwoFactorEncryptionKey), //this for encryption key more secure here than make it global
    ConfigModule.forFeature(GoogleAuthConfig),
    PassportModule,
    UsersModule,
    TwoFaModule,
    UsersProjectsModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtService,
    JwtAuthStrategy,
    RefreshTokenStrategy,
    RefreshTokenGuard,
    GoogleStrategy,
    GoogleAuthGuard,
    tempStorageService,
    TwoFactorEncryptionService,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGard,
    },
  ],
})
export class AuthModule {}
