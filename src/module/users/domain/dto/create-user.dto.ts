import { IsString, IsInt, IsNotEmpty, IsEnum } from 'class-validator';
import { Role } from '../../../../generated/prisma/enums';

export class CreateUserDTO {
  @IsString()
  @IsNotEmpty()
  name!: string;

  @IsString()
  @IsNotEmpty()
  email!: string;

  @IsString()
  @IsNotEmpty()
  password!: string;

  @IsEnum(Role)
  @IsNotEmpty()
  role!: Role;
}
