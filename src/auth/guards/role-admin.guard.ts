/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Role } from 'src/common/types/user-role.enum';

@Injectable()
export class RoleAdminGuard implements CanActivate {
  private readonly logger = new Logger(RoleAdminGuard.name);
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    //  here we check if this route is admin or not
    const req = context.switchToHttp().getRequest();
    const role = req.user?.role;
    if (role === Role.ADMIN) {
      return true;
    }
    this.logger.error(
      `user with email = ${req.user.email} tried to acess admin route but this is normal user not admin`,
    );
    throw new UnauthorizedException();
  }
}
