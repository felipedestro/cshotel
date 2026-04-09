import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDTO } from './domain/dto/create-user.dto';
import { UpdateUserDTO } from './domain/dto/update-user.dto';
import * as bcrypt from 'bcrypt';
import { userSelectFields } from '../prisma/util/user-select-fields';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async list() {
    return await this.prisma.user.findMany({
      select: userSelectFields,
    });
  }

  async show(id: number) {
    return await this.findUser(id);
  }

  async create(body: CreateUserDTO) {
    const user = await this.findByEmail(body.email);

    if (user) {
      throw new BadRequestException('User already exists');
    }

    body.password = await this.hashPassword(body.password);
    return await this.prisma.user.create({
      data: body,
      select: userSelectFields,
    });
  }

  async update(id: number, body: UpdateUserDTO) {
    await this.findUser(id);

    if (body.password) {
      body.password = await this.hashPassword(body.password);
    }

    return await this.prisma.user.update({
      where: { id: Number(id) },
      data: body,
      select: userSelectFields,
    });
  }

  async delete(id: number) {
    await this.findUser(id);

    return await this.prisma.user.delete({
      where: { id },
      select: userSelectFields,
    });
  }

  async findByEmail(email: string) {
    return await this.prisma.user.findUnique({
      where: { email },
    });
  }

  private async findUser(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: userSelectFields,
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  private async hashPassword(password: string) {
    return await bcrypt.hash(password, 10);
  }
}
