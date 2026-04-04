import { Module } from '@nestjs/common';
import { PrismaModule } from './module/prisma/prisma.module';
import { UserModule } from './module/users/user.module';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './module/auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    PrismaModule,
    UserModule,
    AuthModule,
  ],
})
export class AppModule {}
