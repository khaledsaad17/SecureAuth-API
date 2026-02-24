import { Reflector } from '@nestjs/core';

export const SkipAuth = Reflector.createDecorator<boolean>();
