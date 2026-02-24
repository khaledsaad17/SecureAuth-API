import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  IsString,
  IsStrongPassword,
  MaxLength,
  MinLength,
} from 'class-validator';

export class CreateUserDto {
  @ApiProperty({ example: 'abdojon' })
  @IsString()
  @IsNotEmpty()
  @MinLength(4, { message: 'UserName Is So Small' })
  @MaxLength(30, { message: 'UserName Is So Big' })
  userName: string;

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

  @ApiProperty({ example: 'shoping project' })
  @IsString()
  @IsNotEmpty()
  project_identify: string;

  @ApiProperty({ example: '01123665489' })
  @IsOptional()
  @IsPhoneNumber('EG')
  phone?: number;
}
