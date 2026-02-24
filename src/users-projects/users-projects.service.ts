/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import {
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { UsersProjectsEntity } from './Schema/users-projects.schema';
import { Model } from 'mongoose';

@Injectable()
export class UsersProjectsService {
  private logger = new Logger(UsersProjectsService.name);
  constructor(
    /** identify user Project database */
    @InjectModel(UsersProjectsEntity.name)
    private readonly usersProjectModel: Model<UsersProjectsEntity>,
  ) {}

  /** add project to user list and create a document if not exist yet */
  async addOrUpdateUsersProjects(userId: string, newProjectName: string) {
    try {
      // check if user project exist or not
      const userProjects = await this.usersProjectModel.findOne({ userId });
      if (!userProjects) {
        // now create it
        const newUserProjects = await this.usersProjectModel.create({
          userId,
          projectName: [newProjectName],
        });
        return { newUserProjects };
      }

      // now update porjects
      const updateUserProjects = await this.usersProjectModel.findOneAndUpdate(
        { userId },
        { $addToSet: { projectName: newProjectName } },
        { new: true },
      );
      return { updateUserProjects };
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }
}
