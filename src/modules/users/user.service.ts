import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { User } from "generated/prisma";
import { PrismaService } from "../prisma/prisma.service";

@Injectable()
export class UserService {
    constructor(private readonly prisma: PrismaService) {}
    async create(body: any): Promise<User> {
        const user = await this.prisma.user.findUnique({ where: { email: body.email } });

        if (user) {
            throw new HttpException("User already exists", HttpStatus.BAD_REQUEST);
        }

       return await this.prisma.user.create({ data: body });
    }
    async update(id: string, body: any) {
        await this.isIdExists(id);
        return await this.prisma.user.update({ where: { id: Number(id) }, data: body });
    }
    async delete(id: string) {
        await this.isIdExists(id);
        return await this.prisma.user.delete({ where: { id: Number(id) } });
    }
    async list() {
        return await this.prisma.user.findMany();
    }
    async show(id: string) {
        const user = await this.isIdExists(id);
        return user;
    }

    private async isIdExists(id: string) {
        const user = await this.prisma.user.findUnique({ where: { id: Number(id) } });

         if (!user) {
            throw new HttpException("User not found", HttpStatus.NOT_FOUND);
        }

        return user;
    }
}