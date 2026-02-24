import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class EmailVerifyDto {
  @ApiProperty({ example: 'abdo@gmail.com' })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
