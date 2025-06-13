import { IsEmail, IsEnum, IsNotEmpty, isString, IsString } from "class-validator";
import { Role } from "generated/prisma";

export class CreateUserDTO {
    @IsString()
    @IsNotEmpty()
    name: string;

    @IsEmail()
    @IsNotEmpty()
    email: string;
    
    @IsString()
    @IsNotEmpty()
    password: string;
    
    @IsString()
    @IsEnum(Role)
    role: Role
}