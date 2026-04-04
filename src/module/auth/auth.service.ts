import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Role, User } from '../../generated/prisma/client';
import { UserService } from '../users/user.service';
import { AuthLoginDTO } from './domain/dto/login-dto';
import { AuthRegisterDTO } from './domain/dto/register-user-dto';
import { CreateUserDTO } from '../users/domain/dto/create-user.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}

  async generateToken(user: User) {
    const payload = { sub: user.id, name: user.name };
    const options: JwtSignOptions = {
      expiresIn: '1d',
      issuer: 'cshotel',
      audience: 'users',
    };

    return {
      access_token: this.jwtService.sign(payload, options),
    };
  }

  async login({ email, password }: AuthLoginDTO) {
    const user = await this.userService.findByEmail(email);

    if (!user || (await bcrypt.compare(password, user.password))) {
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
}
