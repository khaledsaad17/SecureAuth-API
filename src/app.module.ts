import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfModuleModule } from './conf-module/conf-module.module';
import { UsersModule } from './users/users.module';
import { TwoFaModule } from './two-fa/two-fa.module';
import { UsersProjectsModule } from './users-projects/users-projects.module';
import { AuditModule } from './audit/audit.module';

@Module({
  imports: [
    AuthModule,
    ConfModuleModule,
    UsersModule,
    TwoFaModule,
    UsersProjectsModule,
    AuditModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
