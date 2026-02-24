/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { createParamDecorator } from '@nestjs/common';
import { TokenPayload } from '../DTO/payload.interface';

export const GetUser = createParamDecorator((data, context) => {
  const Req: any = context.switchToHttp().getRequest();
  const user: TokenPayload = Req.user;
  return user;
});
