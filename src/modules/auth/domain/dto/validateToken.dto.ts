import { IsBoolean, IsNotEmpty, IsOptional } from 'class-validator';

export interface JwtPayload {
  name: string;
  iat?: number;
  expiresIn?: number;
  issuer?: string;
  sub: string;
  audience?: string;
}

export class ValidateTokenDTO {
  @IsBoolean()
  @IsNotEmpty()
  valid: boolean;

  decoded?: JwtPayload;

  @IsNotEmpty()
  @IsOptional()
  message?: string;
}
