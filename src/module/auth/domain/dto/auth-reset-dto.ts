import { IsJWT, IsNotEmpty, IsString } from 'class-validator';

export class AuthResetDTO {
  @IsString()
  @IsNotEmpty()
  password!: string;

  @IsJWT()
  @IsNotEmpty()
  token!: string;
}
