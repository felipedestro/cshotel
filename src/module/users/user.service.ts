import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  private async findUser(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: Number(id) },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async list() {
    return await this.prisma.user.findMany();
  }

  async show(id: string) {
    return await this.findUser(id);
  }

  async create(body: any) {
    return await this.prisma.user.create({ data: body });
  }

  async update(id: string, body: any) {
    await this.findUser(id);

    return await this.prisma.user.update({
      where: { id: Number(id) },
      data: body,
    });
  }

  async delete(id: string) {
    await this.findUser(id);

    return await this.prisma.user.delete({ where: { id: Number(id) } });
  }
}
