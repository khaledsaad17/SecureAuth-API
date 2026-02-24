import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsStrongPassword } from 'class-validator';

export class ResetPasswordDto {
  @ApiProperty({
    example:
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2OTk3N2U1OGIzOGFlZjE1OWRjYWQyMzIiLCJlbWFpbCI6ImtoYWxlZHNhYWRfMTdAb3V0bG9vay5jb20iLCJ1c2VyTmFtZSI6ImtoYWxlZCBzYWFkIDE3Iiwicm9sZSI6InVzZXIiLCJpYXQiOjE3NzE1MzU5ODQsImV4cCI6MTc3MTUzOTU4NH0.sMPa_naVusfp96ja4KlV0HfuLPlXDMJJ3puye40YVoI',
  })
  @IsString()
  @IsNotEmpty()
  token: string;

  @ApiProperty({ example: 'ABdo123***' })
  @IsNotEmpty()
  @IsStrongPassword(
    {},
    {
      message:
        'Password Must Contain Letters (LowerCase & UpperCase), Numbers And Symbols',
    },
  )
  newPassword: string;
}
