import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Patch,
  Post,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthLoginDTO } from './domain/dto/login-dto';
import { AuthRegisterDTO } from './domain/dto/register-user-dto';
import { AuthResetDTO } from './domain/dto/auth-reset-dto';
import { AuthForgotPasswordDTO } from './domain/dto/auth-forgot-password-dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() body: AuthLoginDTO) {
    return this.authService.login(body);
  }

  @Post('register')
  register(@Body() body: AuthRegisterDTO) {
    return this.authService.register(body);
  }

  @Patch('reset-password')
  resetPassword(@Body() body: AuthResetDTO) {
    return this.authService.reset(body);
  }

  @Post('forgot-password')
  forgotPassword(@Body() email: AuthForgotPasswordDTO) {
    return this.authService.forgotPassword(email);
  }
}
