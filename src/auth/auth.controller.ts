/* eslint-disable @typescript-eslint/no-unsafe-return */
import {
  Body,
  Controller,
  Get,
  Inject,
  Logger,
  Post,
  Query,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SkipAuth } from './Decorator/Skip-auth.decorator';
import { CreateUserDto } from '../users/DTO/user-register.dto';
import { GetUser } from './Decorator/get-user.decorator';
import { LoginUserDto } from 'src/users/DTO/user-login.dto';
import { RefreshTokenGuard } from './guards/refresh-token.guard';
import * as payload from './DTO/payload.interface';
import { VerifyTwoFaDto } from './DTO/verify-towfa.dto';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { tempStorageService } from './tempStorage.service';
import type { Response } from 'express';
import { LinksUrl } from 'src/conf-module/links.config';
import * as config_1 from '@nestjs/config';
import { EmailVerifyDto } from './DTO/email-verify.dto';
import { ResetPasswordDto } from 'src/users/DTO/reset-password.dto';
import { GetRequestInfo } from 'src/audit/Decorator/get-request-info.decorator';
import type { RequestInfo } from 'src/audit/Decorator/get-request-info.decorator';
import { AuditAction, AuditStatus } from 'src/audit/DTO/audit-action.enum';
import { AuditService } from 'src/audit/audit.service';
import { ApiBearerAuth } from '@nestjs/swagger';

@Controller('auth')
@SkipAuth(true)
export class AuthController {
  private logger = new Logger(AuthController.name);
  constructor(
    /** identify auth service */ private readonly authService: AuthService,
    /** identiry temp sotrage service */ private readonly tempStorageService: tempStorageService,
    /** identify audit serivce */ private readonly auditService: AuditService,
    /** identify redirect links config */
    @Inject(LinksUrl.KEY)
    private readonly config: config_1.ConfigType<typeof LinksUrl>,
  ) {}

  /**create new user */
  @Post('register')
  register(@Body() body: CreateUserDto, @GetRequestInfo() info: RequestInfo) {
    return this.authService.registerUser(
      body.userName,
      body.email,
      body.password,
      body.project_identify,
      info,
    );
  }

  /**verify email */
  @Get('/verify-email')
  verifyUser(@Query('token') token: string) {
    return this.authService.verifyUserAccount(token);
  }

  /** login route */
  @Post('/login')
  login(@Body() body: LoginUserDto, @GetRequestInfo() info: RequestInfo) {
    return this.authService.loginUser(
      body.email,
      body.password,
      body.project_identify,
      info,
    );
  }

  /**  verify 2FA while login
   *   need email send with otp to complete verifictaion
   */
  @Post('/verify-2FA-login')
  verifyTowFactorAfterLogin(
    @Body() body: VerifyTwoFaDto,
    @Body() email: EmailVerifyDto,
    @Body() projectName: string,
    @GetRequestInfo() info: RequestInfo,
  ) {
    return this.authService.verifyOTPWhileLogin(
      email.email,
      body.OTP,
      projectName,
      info,
    );
  }

  /** use refresh token to generate accesstoken */
  @ApiBearerAuth()
  @Get('/refresh')
  @UseGuards(RefreshTokenGuard)
  createAccessToken(@GetUser() user: payload.TokenPayload) {
    // after sure that token is valid then generate an accessToken and send it to response
    const payload: payload.TokenPayload = {
      sub: user.sub,
      email: user.email,
      userName: user.userName,
      role: user.role,
      projectName: user.projectName,
    };
    return this.authService.generateNewAccessToken(payload);
  }

  /**
   *  enable 2fa auth route
   *  first i should finish login routes because i want accesstoken to use it
   */
  @ApiBearerAuth()
  @Get('/enable-2fa')
  @SkipAuth(false)
  enable2FaAndSendQrCode(@GetUser() user: payload.TokenPayload) {
    // send Qr-code with response but first store secret to database and make 2fa is enable
    // and user have to send an secert first to verify
    return this.authService.getQRcodeWithSecret(user.email, user.sub);
  }

  /** here we verify OTP code */
  @ApiBearerAuth()
  @Post('/verify-2fa')
  @SkipAuth(false)
  verifyOtp(
    @GetUser() user: payload.TokenPayload,
    @Body() body: VerifyTwoFaDto,
    @GetRequestInfo() info: RequestInfo,
  ) {
    return this.authService.verifyTowFactorAuth(body.OTP, user.email, info);
  }

  /** authorize user by google auth
   *  using this route for both login and register
   */
  @Get('/google')
  @UseGuards(GoogleAuthGuard)
  googleAuth() {}

  /** auth google callback  */
  @Get('google/callback')
  @UseGuards(GoogleAuthGuard)
  async googleCallback(
    @GetUser() user: payload.TokenPayload,
    @Res() res: Response,
  ) {
    // generate access and refresh token and send them back
    const accessToken = await this.authService.createAccessToken(user);
    const refreshToken = await this.authService.createRefreshToken(user);
    // here we will use redis for store the jwt tokens for little pit of second to make redirect and then get it
    const tempId = this.tempStorageService.createTempToken({
      accessToken,
      refreshToken,
    });

    // now redirect with tempId in Query param
    return res.redirect(
      `${this.config.frontendUrl}/oauth-success?tempId=${(await tempId).toString()}`,
    );
  }

  /** get auth tokens */
  @Get('/oauth')
  async getTokens(@Query('tempId') tempId: string) {
    return await this.tempStorageService.consumeTempToken(tempId);
  }

  /** logout */
  // here we will build a logic but first we should end session in sessions module it self
  // this return is no thing
  @ApiBearerAuth()
  @Get('/logout')
  @SkipAuth(false)
  async logoutUser(@GetUser() user: payload.TokenPayload, info: RequestInfo) {
    // here the frontend remove access and refresh token with this user can not see protected routes
    const log = {
      info,
      email: user.email,
      projectName: user.projectName,
      action: AuditAction.LOGOUT,
      status: AuditStatus.SUCCESS,
      moreInfo: 'user log out ',
    };
    await this.auditService.log(log);
    return { message: 'user log out successfully' };
  }

  /** forgot password & send mail to reset it */
  @Post('/forgot-password')
  forgotPassword(
    @Body() body: EmailVerifyDto,
    @GetRequestInfo() info: RequestInfo,
  ) {
    return this.authService.forgetPassword(body.email, info);
  }

  /** reset process and validation */
  @Post('/reset-password')
  resetPassword(
    @Body() body: ResetPasswordDto,
    @GetRequestInfo() info: RequestInfo,
  ) {
    return this.authService.resetPassword(body.token, body.newPassword, info);
  }

  /** return user info */
  @ApiBearerAuth()
  @SkipAuth(false)
  @Get('/me')
  getUserInfo(@GetUser() user: payload.TokenPayload) {
    return user;
  }
}
