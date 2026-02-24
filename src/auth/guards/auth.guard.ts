import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';
import { SkipAuth } from '../Decorator/Skip-auth.decorator';

@Injectable()
export class JwtAuthGard extends AuthGuard('JwtVerify') {
  constructor(private readonly reflector: Reflector) {
    super();
  }
  /**
   * here we check if route is public or not using skip decorator
   */
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(SkipAuth, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }
    // this for make passport work and pass payload of jwt token after decode it
    return super.canActivate(context);
  }
}
