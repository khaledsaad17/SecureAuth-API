/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import * as config_1 from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { DbName } from 'src/common/types/database-name.enum';
import { jwtConfig } from 'src/conf-module/jwt.config';
import { UsersService } from 'src/users/users.service';
import { TokenPayload } from './DTO/payload.interface';
import { TwoFactorEncryptionService } from 'src/common/encryption/TwoFactor-Encryption-secert.service';
import { TwoFaService } from 'src/two-fa/two-fa.service';
import { UsersProjectsService } from 'src/users-projects/users-projects.service';
import { RequestInfo } from 'src/audit/Decorator/get-request-info.decorator';
import { AuditService } from 'src/audit/audit.service';
import { AuditAction, AuditStatus } from 'src/audit/DTO/audit-action.enum';
import { AuthProvider } from 'src/common/types/user-auth-provider.enum';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    /**identify users service */ private readonly usersService: UsersService,
    /**identify auth service */ private readonly jwtService: JwtService,
    /**identiry 2fa service */ private readonly towFactorService: TwoFaService,
    /**identify enc and dec 2fa secret */ private readonly towFactorSecretEncryptionService: TwoFactorEncryptionService,
    /**identiry users projects service */ private readonly userProjectsService: UsersProjectsService,
    /**identify audit logs serivce */ private readonly auditService: AuditService,

    @Inject(jwtConfig.KEY)
    private readonly config: config_1.ConfigType<typeof jwtConfig>,
  ) {}

  /** create an account for user first should verify email end then entered system using login route */
  async registerUser(
    userName: string,
    email: string,
    password: string,
    projectName: string,
    info: RequestInfo,
  ) {
    // first should check if email exist
    const user = await this.usersService.findUserByEmail(
      email,
      DbName.mainUser,
    );
    if (user) {
      // make logs
      const log = {
        info,
        email,
        projectName,
        action: AuditAction.REGISTER,
        status: AuditStatus.FAILED,
      };
      await this.auditService.log(log);
      this.logger.error(
        `user with email = ${email} is already regitered in system`,
      );
      throw new ConflictException('Invalid Input');
    }

    // get verification token
    const token = await this.createVerifyEmailToken(
      email,
      userName,
      projectName,
    );

    // create user in pending database & send verification mail
    await this.usersService.createNewUser(
      userName,
      email,
      password,
      token,
      projectName,
    );

    this.logger.log('Verification Mail Send Successfully');
    return { message: 'Verification Mail Send Successfully' };
  }

  /** create token and send it through mail to reset it */
  async forgetPassword(email: string, info: RequestInfo) {
    // check if user is exist in main database or not
    const user = await this.usersService.findUserByEmail(
      email,
      DbName.mainUser,
    );
    if (!user || user.provider === AuthProvider.GOOGLE) {
      // make logs
      const log = {
        info,
        email,
        action: AuditAction.FORGOT_PASSWORD,
        status: AuditStatus.FAILED,
        moreInfo:
          'user tryed to reset password but he does not registerd yet or he used google Oauth to register and login',
      };
      await this.auditService.log(log);
      this.logger.error(
        `user with email ${email} tryed to reset password but he does not registerd yet, or he used google Oauth to register and login`,
      );
      throw new ConflictException('This Email Not Valid');
    }
    // check user reset password in database
    const isHaveResetToken = await this.usersService.checkUserResetPassword(
      user._id.toString(),
    );

    // genrate reset password token
    const resetToken = await this.generateResetPasswordToken(
      email,
      user._id.toString(),
    );

    if (!isHaveResetToken) {
      // create reset token and store it in database
      await this.usersService.addResetPasswordToken(
        user._id.toString(),
        resetToken,
      );
    } else {
      // update reset pasword token in database
      await this.usersService.updateResetPasswordToken(
        user._id.toString(),
        resetToken,
      );
    }
    await this.usersService.sendResetPasswordMail(resetToken, email);
    return {
      message:
        'Password reset mail sent Successfully ,Please Check Your email And Verify Now',
    };
  }

  /** reset password  */
  async resetPassword(token: string, newPassword: string, info: RequestInfo) {
    // verify if token valid or not
    const isExist: any = await this.usersService.checkUserResetPassword(
      undefined,
      token,
    );

    if (!isExist || isExist.expires_at < new Date()) {
      throw new BadRequestException('Invalid or expired token');
    }

    // check if token is used befor or not
    if (isExist?.used === true) {
      throw new BadRequestException(' Token Are Used Before ');
    }

    // hashing new password
    const newPasswordHash =
      await this.usersService.hashingPassword(newPassword);

    const user = await this.usersService.updateUserPassword(
      isExist.userId,
      newPasswordHash,
    );

    await this.usersService.updateUsedInUserResetPasswordDatabase(isExist._id);

    const log = {
      info,
      email: user?.email,
      action: AuditAction.RESET_PASSWORD,
      status: AuditStatus.SUCCESS,
      moreInfo: 'user change his password ',
    };
    await this.auditService.log(log);
    return {
      message: 'Password reset successful',
    };
  }

  /** login to system and check login credintial */
  async loginUser(
    email: string,
    password: string,
    projectName: string,
    info: RequestInfo,
  ) {
    // check if user exist or not
    const result = await this.usersService.login(email, password, projectName);
    if (result.towFaStatus) {
      return {
        message: 'We Need OTP To Verify 2FA To Complete Login',
      };
    }

    // create both access,refresh token and send them in response
    const accessToken = await this.createAccessToken(result.tokenPayload!);
    const refreshToken = await this.createRefreshToken(result.tokenPayload!);

    // make logs
    const log = {
      info,
      email,
      projectName,
      action: AuditAction.LOGIN,
      status: AuditStatus.SUCCESS,
    };
    await this.auditService.log(log);
    this.logger.log(`user with email = ${email} login Successfully`);
    return {
      message: 'User Login Successfully',
      tokens: { accessToken, refreshToken },
    };
  }

  /** verifing OTP after login */
  async verifyOTPWhileLogin(
    email: string,
    OTP: string,
    projectName: string,
    info: RequestInfo,
  ) {
    // get OTP secret and verify it
    const user = await this.getOTPSecretAndVerifyIt(email, OTP);

    // get user

    // create both access,refresh token and send them in response
    const tokenPayload: TokenPayload = {
      sub: user._id.toString(),
      email,
      userName: user.userName,
      role: user.role,
      projectName,
    };
    const accessToken = await this.createAccessToken(tokenPayload);
    const refreshToken = await this.createRefreshToken(tokenPayload);

    // make logs
    const log = {
      info,
      email,
      projectName,
      action: AuditAction.LOGIN,
      status: AuditStatus.SUCCESS,
      moreInfo: 'using 2fa OTP',
    };
    await this.auditService.log(log);
    this.logger.log(`user with email = ${email} login Successfully`);
    return {
      message: 'User Login Successfully',
      tokens: { accessToken, refreshToken },
    };
  }

  /**get QR code */
  async getQRcodeWithSecret(email: string, userId: string) {
    // get secret and QR code
    const { secret, qrCode } =
      await this.towFactorService.generateTwoFactorSecret(email);

    // encode secret
    const encryptedSecret =
      this.towFactorSecretEncryptionService.encrypt(secret);

    // and store secret in user database but still 2fa not enabled
    await this.usersService.findUserAndUpdateTowFactorSecret(
      userId,
      encryptedSecret,
    );
    return qrCode;
  }

  /** verify 2fa auth using secret code and update user data (2fa = true) */
  async verifyTowFactorAuth(OTP: string, email: string, info: RequestInfo) {
    // get secret from database and verify it
    const user = await this.getOTPSecretAndVerifyIt(email, OTP);

    // update 2fa to true
    await this.usersService.findUserAndUpdateTowFactorVerificationCheck(
      user._id.toString(),
    );

    // make logs
    const log = {
      info,
      email,
      action: AuditAction.TWO_FA_ENABLED,
      status: AuditStatus.SUCCESS,
    };
    await this.auditService.log(log);
    this.logger.log(`user with email = ${email} is enable 2FA successfully`);
    return { message: 'Congratulation Now 2FA Is Enable' };
  }

  /** generate an access token valid and new */
  async generateNewAccessToken(payload: TokenPayload) {
    // call create accessToken fun
    const accessToken = await this.createAccessToken(payload);
    this.logger.log('accessToken generate successfully');
    return { message: 'accessToken generate successfully', accessToken };
  }

  /**verification user & store it in database  */
  async verifyUserAccount(token: string) {
    // check if token is valid or not
    const userInfo = await this.verifyJwtToken(token);
    // store user in main database
    const { userName, email } = await this.usersService.addVerifiedUsers(
      userInfo.email,
      userInfo.projectName,
    );

    // make log that user is verified successfully
    this.logger.log(
      `${userName} with this email = ${email} is verified successfully`,
    );
    return { message: 'user is verified successfully' };
  }

  /** check token validation */
  async verifyJwtToken(token: string) {
    try {
      const userInfo = await this.jwtService.verifyAsync(token, {
        secret: this.config.verifyEmailSecret,
      });
      const verifiedToken: any = await this.usersService.findUserByEmail(
        userInfo.email,
        DbName.pendingUser,
      );
      if (!verifiedToken || token !== verifiedToken.verificationToken) {
        throw new Error(
          `in pendding database there is know document for this email = ${userInfo.email}`,
        );
      }
      return userInfo;
    } catch (error) {
      this.logger.error(error.message);
      throw new UnauthorizedException(
        'Verification Is Expired Try SignUp Again',
      );
    }
  }

  /**create verify token */
  async createVerifyEmailToken(
    email: string,
    userName: string,
    projectName: string,
  ): Promise<string> {
    return await this.jwtService.signAsync(
      { email, userName, projectName },
      {
        secret: this.config.verifyEmailSecret,
        expiresIn: '2h',
      },
    );
  }

  /** create user access token */
  async createAccessToken(payload: TokenPayload): Promise<string> {
    return await this.jwtService.signAsync(payload, {
      secret: this.config.accessTokenSecret,
      expiresIn: '1h',
    });
  }

  /** create user refresh token */
  async createRefreshToken(payload: TokenPayload): Promise<string> {
    return await this.jwtService.signAsync(payload, {
      secret: this.config.refreshTokenSecret,
      expiresIn: '1w',
    });
  }

  /** get secret from database */
  async getOTPSecretAndVerifyIt(email: string, OTP: string) {
    const user = await this.usersService.findUserByEmail(
      email,
      DbName.mainUser,
    );
    if (!user || user.twoFactorSecret === null) {
      this.logger.error(
        `user with email = ${email} tried to use verifyTowFactorAuth method but user not exist in database`,
      );
      throw new UnauthorizedException();
    }

    // decode secret
    const decodedSecret = this.towFactorSecretEncryptionService.decrypt(
      user.twoFactorSecret,
    );

    // check of secret code is correct or not
    const isValid = this.towFactorService.verifyCode(decodedSecret, OTP);
    if (!isValid) {
      this.logger.error(
        `user with email = ${email} entered invalid secret code to verify`,
      );
      throw new ConflictException(
        'Wrong Inpute Please make sure of code and try again',
      );
    }
    return user;
  }

  /** create user using google auth */
  async loginOrCreateUserUsingGooglAuth(email: string, userName: string) {
    // first check if user is exist or not
    const user = await this.usersService.findUserByEmail(
      email,
      DbName.mainUser,
    );

    // if not
    if (!user) {
      // create a new database user
      const newUser = await this.usersService.addUserUsingGoogleAuth(
        email,
        userName,
      );
      return { sub: newUser._id.toString(), email, userName };
    }

    return { sub: user._id.toString(), email, userName };
  }

  /** generate token to use it in reset password */
  async generateResetPasswordToken(email: string, sup: string) {
    return await this.jwtService.signAsync(
      { email, sup },
      { secret: this.config.resetPasswordSecret, expiresIn: '2h' },
    );
  }
}
