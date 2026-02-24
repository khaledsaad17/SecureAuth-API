import { Module } from '@nestjs/common';
import { UsersProjectsService } from './users-projects.service';
import { MongooseModule } from '@nestjs/mongoose';
import {
  UsersProjectsEntity,
  UsersProjectsSchema,
} from './Schema/users-projects.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: UsersProjectsEntity.name,
        schema: UsersProjectsSchema,
      },
    ]),
  ],
  providers: [UsersProjectsService],
  exports: [UsersProjectsService],
})
export class UsersProjectsModule {}
