import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersEntity, UsersSchema } from './schema/user-entity&schema';
import {
  PendingUserSchema,
  PendingUserVerificationEntity,
} from './schema/user-pending-verification';
import { MailService } from './mails/mail.service';
import { UsersProjectsModule } from 'src/users-projects/users-projects.module';
import {
  ResetPasswordEntity,
  ResetPasswordSchema,
} from './schema/reset-password.schema';

@Module({
  imports: [
    UsersProjectsModule,
    MongooseModule.forFeature([
      {
        name: UsersEntity.name,
        schema: UsersSchema,
      },
      {
        name: PendingUserVerificationEntity.name,
        schema: PendingUserSchema,
      },
      {
        name: ResetPasswordEntity.name,
        schema: ResetPasswordSchema,
      },
    ]),
  ],
  controllers: [UsersController],
  providers: [UsersService, MailService],
  exports: [UsersService],
})
export class UsersModule {}
