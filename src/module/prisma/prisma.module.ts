import { Module } from '@nestjs/common';
import { PrismaService } from './prisma.services';

@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
