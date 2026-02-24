import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsStrongPassword,
} from 'class-validator';

export class LoginUserDto {
  @ApiProperty({ example: 'abdo@gmail.com' })
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'ABdo123***' })
  @IsStrongPassword(
    {},
    {
      message:
        'Password Must Contain Letters (LowerCase & UpperCase), Numbers And Symbols',
    },
  )
  password: string;

  @IsString()
  @IsNotEmpty()
  project_identify: string;
}
