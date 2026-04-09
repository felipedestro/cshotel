import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Role, User } from '../../generated/prisma/client';
import { UserService } from '../users/user.service';
import { AuthLoginDTO } from './domain/dto/login-dto';
import { AuthRegisterDTO } from './domain/dto/register-user-dto';
import { CreateUserDTO } from '../users/domain/dto/create-user.dto';
import { AuthResetDTO } from './domain/dto/auth-reset-dto';
import { ValidateTokenDTO } from './domain/dto/validate-token-dto';
import { AuthForgotPasswordDTO } from './domain/dto/auth-forgot-password-dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}

  async generateToken(
    user: User,
    expiresIn: JwtSignOptions['expiresIn'] = '1d',
  ) {
    const payload = { sub: user.id, name: user.name };
    const options: JwtSignOptions = {
      expiresIn: expiresIn,
      issuer: 'cshotel',
      audience: 'users',
    };

    return {
      access_token: this.jwtService.sign(payload, options),
    };
  }

  async login({ email, password }: AuthLoginDTO) {
    const user = await this.userService.findByEmail(email);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Email or password is incorrect');
    }

    return await this.generateToken(user);
  }

  async register(body: AuthRegisterDTO) {
    const newUser: CreateUserDTO = {
      name: body.name!,
      email: body.email!,
      password: body.password!,
      role: body.role ?? Role.USER,
    };

    const user = await this.userService.create(newUser);

    return await this.generateToken(user);
  }

  async reset({ token, password }: AuthResetDTO) {
    const { valid, decoded } = await this.validateToken(token);

    if (!valid || !decoded) throw new UnauthorizedException('Invalid token');

    const user = await this.userService.update(Number(decoded!.sub), {
      password,
    });

    return await this.generateToken(user);
  }

  async forgotPassword({ email }: AuthForgotPasswordDTO) {
    const user = await this.userService.findByEmail(email);

    if (!user) throw new UnauthorizedException('Email is incorrect');

    return await this.generateToken(user, '30m');
  }

  async validateToken(token: string): Promise<ValidateTokenDTO> {
    try {
      const decoded = await this.jwtService.verifyAsync(token, {
        secret: process.env.JWT_SECRET,
        issuer: 'cshotel',
        audience: 'users',
      });

      return {
        valid: true,
        decoded,
      };
    } catch (error: any) {
      return {
        valid: false,
        message: error,
      };
    }
  }
}
