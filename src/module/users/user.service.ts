import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDTO } from './domain/dto/create-user.dto';
import { UpdateUserDTO } from './domain/dto/update-user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  private async hashPassword(password: string) {
    return await bcrypt.hash(password, 10);
  }

  private async findUser(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async list() {
    return await this.prisma.user.findMany();
  }

  async show(id: number) {
    return await this.findUser(id);
  }

  async create(body: CreateUserDTO) {
    body.password = await this.hashPassword(body.password);
    return await this.prisma.user.create({ data: body });
  }

  async update(id: number, body: UpdateUserDTO) {
    await this.findUser(id);

    if (body.password) {
      body.password = await this.hashPassword(body.password);
    }

    return await this.prisma.user.update({
      where: { id: Number(id) },
      data: body,
    });
  }

  async delete(id: number) {
    await this.findUser(id);

    return await this.prisma.user.delete({ where: { id } });
  }
}
