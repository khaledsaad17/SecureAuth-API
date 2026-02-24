/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import {
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { AuditLogEntity } from './Schema/audit-logs.schema';
import { Model } from 'mongoose';

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);
  constructor(
    @InjectModel(AuditLogEntity.name)
    private readonly auditLogModel: Model<AuditLogEntity>,
  ) {}

  /** create log */
  async log(data: any) {
    try {
      await this.auditLogModel.create({
        email: data.email,
        action: data.action,
        status: data.status,
        projectName: data.projectName ?? 'not found',
        ipAddress: data.info.ipAddress ?? 'null',
        userAgent: data.info.userAgent,
        metadata: {
          deviceName: data.info.deviceName,
          browser: data.info.browser,
          os: data.info.os,
          moreInfo: data?.moreInfo || null,
        },
      });
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }

  /** get specific log */
  async getLogsByEmail(email: string) {
    try {
      return await this.auditLogModel.find({ email });
    } catch (error) {
      this.logger.error(error.message);
      throw new InternalServerErrorException();
    }
  }
}
