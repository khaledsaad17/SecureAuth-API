import { Module } from '@nestjs/common';
import { AuditService } from './audit.service';
import { AuditController } from './audit.controller';
import { RoleAdminGuard } from 'src/auth/guards/role-admin.guard';
import { MongooseModule } from '@nestjs/mongoose';
import { AuditLogEntity, AuditLogSchema } from './Schema/audit-logs.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: AuditLogEntity.name,
        schema: AuditLogSchema,
      },
    ]),
  ],
  providers: [AuditService, RoleAdminGuard],
  controllers: [AuditController],
  exports: [AuditService],
})
export class AuditModule {}
