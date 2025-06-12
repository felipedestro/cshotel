import { Body, Controller, HttpCode, Patch, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthLoginDTO } from './domain/dto/authLogin.dto';
import { AuthRegisterDTO } from './domain/dto/authRegister.dto';
import { AuthResetPasswordDTO } from './domain/dto/authResetPassword.dto';
import { AuthForgotPasswordDTO } from './domain/dto/authForgotPassword.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(200)
  login(@Body() body: AuthLoginDTO) {
    return this.authService.login(body);
  }

  @Post('register')
  register(@Body() body: AuthRegisterDTO) {
    return this.authService.register(body);
  }

  @Post('forgot-password')
  forgot(@Body() { email }: AuthForgotPasswordDTO) {
    return this.authService.forgot(email);
  }

  @Patch('reset-password')
  resetPassword(@Body() { token, password }: AuthResetPasswordDTO) {
    return this.authService.reset({ token, password });
  }
}
