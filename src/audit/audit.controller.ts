import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuditService } from './audit.service';
import { GetUser } from 'src/auth/Decorator/get-user.decorator';
import * as payload from 'src/auth/DTO/payload.interface';
import { RoleAdminGuard } from 'src/auth/guards/role-admin.guard';
import { ApiBearerAuth } from '@nestjs/swagger';

@Controller('audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  /** get all logs for specific user
   * this route specified for admin
   */
  @ApiBearerAuth('this for admin only')
  @UseGuards(RoleAdminGuard)
  @Get('/admin/logs/:userId')
  getUserLogsForAdmin(@GetUser() user: payload.TokenPayload) {
    return this.auditService.getLogsByEmail(user.email);
  }

  /** get all logs for current user */
  @ApiBearerAuth()
  @Get('/logs')
  getUserLogs(@GetUser() user: payload.TokenPayload) {
    return this.auditService.getLogsByEmail(user.email);
  }
}
