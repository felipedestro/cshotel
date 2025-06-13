import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { User } from 'generated/prisma';
import { PrismaService } from '../prisma/prisma.service';
import { UpdateUserDTO } from './domain/dto/updateUser.dto';
import { CreateUserDTO } from './domain/dto/createUser.dto';
import * as bcrypt from 'bcrypt';
import { userSelectFields } from '../prisma/utils/userSelectFields';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}
  async create(body: CreateUserDTO): Promise<User> {
    const user = await this.prisma.user.findUnique({
      where: { email: body.email },
    });

    if (user) {
      throw new HttpException('User already exists', HttpStatus.BAD_REQUEST);
    }

    body.password = await this.hashPassword(body.password);

    return await this.prisma.user.create({
      data: body,
      select: userSelectFields,
    });
  }
  async update(id: number, body: UpdateUserDTO) {
    await this.isIdExists(id);

    if (body.password) {
      body.password = await this.hashPassword(body.password);
    }

    return await this.prisma.user.update({
      where: { id },
      data: body,
      select: userSelectFields,
    });
  }
  async delete(id: number) {
    await this.isIdExists(id);
    return await this.prisma.user.delete({ where: { id } });
  }
  async list() {
    return await this.prisma.user.findMany({
      select: userSelectFields,
    });
  }
  async show(id: number) {
    const user = await this.isIdExists(id);
    return user;
  }

  async findByEmail(email: string) {
    return await this.prisma.user.findUnique({
      where: { email },
    });
  }

  private async isIdExists(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: userSelectFields,
    });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    return user;
  }

  private async hashPassword(password: string) {
    const hashPassword = await bcrypt.hash(password, 10);
    return hashPassword;
  }
}
