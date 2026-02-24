/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Model } from 'mongoose';
import { UserDocument, UsersEntity } from './schema/user-entity&schema';
import { InjectModel } from '@nestjs/mongoose';
import {
  PendingUserDocument,
  PendingUserVerificationEntity,
} from './schema/user-pending-verification';
import bcrypt from 'bcrypt';
import { MailService } from './mails/mail.service';
import { DbName } from 'src/common/types/database-name.enum';
import { AuthProvider } from 'src/common/types/user-auth-provider.enum';
import { UsersProjectsService } from 'src/users-projects/users-projects.service';
import { TokenPayload } from 'src/auth/DTO/payload.interface';
import { ResetPasswordEntity } from './schema/reset-password.schema';
import { LinksUrl } from 'src/conf-module/links.config';
import * as config_1 from '@nestjs/config';
import { RequestInfo } from 'src/audit/Decorator/get-request-info.decorator';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);
  constructor(
    /** identify users database collection */ @InjectModel(UsersEntity.name)
    private readonly usersModel: Model<UsersEntity>,
    /** identify pendding users database */ @InjectModel(
      PendingUserVerificationEntity.name,
    )
    private readonly pendingUserModel: Model<PendingUserVerificationEntity>,
    /** identify mail service */ private readonly mailService: MailService,
    /**identiry users projects service */ private readonly userProjectsService: UsersProjectsService,
    /** identify reset password model */ @InjectModel(ResetPasswordEntity.name)
    private readonly resetPasswordModel: Model<ResetPasswordEntity>,
    /** identify links url config */ @Inject(LinksUrl.KEY)
    private readonly urlConfig: config_1.ConfigType<typeof LinksUrl>,
  ) {}

  /** create new user in pendding database */
  async createNewUser(
    userName: string,
    email: string,
    password: string,
    verificationToken: string,
    projectName: string,
  ) {
    // check if email exist or not & store it in pending collection until he verify it
    const user = await this.findUserByEmail(email, DbName.mainUser);
    if (user) {
      this.logger.error('this email is already exist');
      throw new ConflictException(' Invalid Inputs ');
    }

    // hashing password
    const passwordHash = await this.hashingPassword(password);

    // store user in pendding database
    try {
      // create user and update it if exist
      await this.pendingUserModel.findOneAndUpdate(
        { email },
        {
          $set: {
            userName,
            passwordHash,
            createdAt: Date.now(),
            verificationToken,
          },
        },
        { upsert: true, setDefaultsOnInsert: true },
      );

      //send verification mail
      await this.mailService.sendVerificationEmail(
        email,
        verificationToken,
        projectName,
      );
    } catch (error) {
      this.logger.error(error);
      throw new InternalServerErrorException();
    }
  }

  /** add verified user and update pendding user database */
  async addVerifiedUsers(email: string, projectName: string) {
    // get user info from pending database
    const penddingUser = await this.pendingUserModel.findOne({ email });
    // create user in main users database
    try {
      const realUser = await this.usersModel.create({
        userName: penddingUser?.userName,
        email,
        passwordHash: penddingUser?.passwordHash,
      });

      // update user projects database
      await this.userProjectsService.addOrUpdateUsersProjects(
        realUser._id.toString(),
        projectName,
      );
      return realUser;
    } catch (error) {
      this.logger.error(error.message);
      if (error.code === 11000) {
        throw new ConflictException(' Invalid Inputs ');
      }
      throw new InternalServerErrorException();
    }
  }

  /** login function */
  async login(email: string, password: string, projectName: string) {
    // check if user exist or not
    const user = await this.findUserByEmail(email, DbName.mainUser);
    if (!user) {
      // make logs

      this.logger.error(
        `user with email = ${email} not regitered yet and tried to login`,
      );
      throw new BadRequestException('Please try to register First');
    }

    // check password is equal or not
    if (!(await this.comparePassword(user.passwordHash, password))) {
      this.logger.error(`user with email = ${email} entered wronge password`);
      throw new UnauthorizedException(
        ' Email or Password Not Valid Please Check Your Inputs',
      );
    }

    // check if user project is exist or not and update his project list
    await this.userProjectsService.addOrUpdateUsersProjects(
      user._id.toString(),
      projectName,
    );

    // check if user enable 2fa auth
    // if not
    if (!user.twoFactorEnabled) {
      const tokenPayload: TokenPayload = {
        sub: user._id.toString(),
        email,
        userName: user.userName,
        role: user.role,
        projectName,
      };
      return { towFaStatus: false, tokenPayload };
    }

    // if yes
    return { towFaStatus: true };
  }

  async findUserByEmail(
    email: string,
    databaseName: DbName.mainUser,
  ): Promise<UserDocument | null>;

  async findUserByEmail(
    email: string,
    databaseName: DbName.pendingUser,
  ): Promise<PendingUserDocument | null>;

  async findUserByEmail(email: string, databaseName: DbName) {
    if (databaseName === DbName.mainUser) {
      return this.usersModel.findOne({ email });
    }

    if (databaseName === DbName.pendingUser) {
      return this.pendingUserModel.findOne({ email });
    }
    return null;
  }

  async findUserAndUpdateTowFactorSecret(
    userId: string,
    twoFactorSecret: string,
  ) {
    try {
      await this.usersModel.findOneAndUpdate(
        { _id: userId },
        { $set: { twoFactorSecret } },
      );
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }

  async findUserAndUpdateTowFactorVerificationCheck(userId: string) {
    try {
      await this.usersModel.findOneAndUpdate(
        { _id: userId },
        { $set: { twoFactorEnabled: true } },
      );
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }

  /** hashing password */
  async hashingPassword(password: string) {
    const password_hashed = await bcrypt.hash(password, 10);
    return password_hashed;
  }

  /** verifing password */
  async comparePassword(
    hashingPassword: string,
    password: string,
  ): Promise<boolean> {
    return await bcrypt.compare(password, hashingPassword);
  }

  /** update user password */
  async updateUserPassword(userId: string, passwordHash: string) {
    try {
      return await this.usersModel.findOneAndUpdate(
        { _id: userId },
        { passwordHash: passwordHash },
      );
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }

  /**  update database that this token is used */
  async updateUsedInUserResetPasswordDatabase(id: string) {
    try {
      await this.resetPasswordModel.findOneAndUpdate(
        { _id: id },
        { used: true },
      );
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }

  /** add user in database */
  async addUserUsingGoogleAuth(email: string, userName: string) {
    // add user to database
    try {
      return await this.usersModel.create({
        email,
        userName,
        provider: AuthProvider.GOOGLE,
      });
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }

  /** send mail with token to reset password */
  async checkUserResetPassword(userId?: string, token?: string) {
    // check if the email is exist or not
    // check the user is have an reset token before or not
    const filter: any = {};
    if (userId) {
      filter.userId = userId;
    }
    if (token) {
      filter.token = token;
    }
    return await this.resetPasswordModel.findOne(filter);
  }

  /** send mail to reset password */
  async sendResetPasswordMail(resetToken: string, email: string) {
    // send mail to user with link to reset password
    const resetLink = `${this.urlConfig.frontendUrl}/reset-password?token=${resetToken}`;
    await this.mailService.sendResetPasswordMail(email, resetLink);
    return {
      message: 'Password reset email sent',
    };
  }
  async addResetPasswordToken(userId: string, token: string) {
    try {
      await this.resetPasswordModel.create({
        userId,
        token,
        expires_at: new Date(Date.now() + 60 * 60 * 1000 * 2),
      });
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }
  async updateResetPasswordToken(userId: string, token: string) {
    try {
      await this.resetPasswordModel.updateOne(
        {
          userId,
        },
        {
          used: false,
          token,
          expires_at: new Date(Date.now() + 60 * 60 * 1000 * 2),
        },
      );
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }
}
