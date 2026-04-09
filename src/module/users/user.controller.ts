import {
  Body,
  Controller,
  Delete,
  Get,
  Patch,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ParamId } from '../../shared/decorators/params-id.decorator';
import { CreateUserDTO } from './domain/dto/create-user.dto';
import { UpdateUserDTO } from './domain/dto/update-user.dto';
import { UserService } from './user.service';
import { AuthGuard } from '../../shared/guards/auth.guard';
import { User } from '../../shared/decorators/user.decorator';
import type { User as UserType } from '../../generated/prisma/client';

@UseGuards(AuthGuard)
@Controller('users')
export class UserController {
  constructor(private userService: UserService) {}

  @Get()
  list(@User('email') user: UserType) {
    console.log(user);
    return this.userService.list();
  }

  @Get(':id')
  show(@ParamId() id: number) {
    return this.userService.show(id);
  }

  @Post()
  createUser(@Body() body: CreateUserDTO) {
    return this.userService.create(body);
  }

  @Patch(':id')
  updateUser(@ParamId() id: number, @Body() body: UpdateUserDTO) {
    return this.userService.update(id, body);
  }

  @Delete(':id')
  deleteUser(@ParamId() id: number) {
    return this.userService.delete(id);
  }
}
