import {
  createParamDecorator,
  ExecutionContext,
  NotFoundException,
} from '@nestjs/common';

export const User = createParamDecorator(
  (filter: string, context: ExecutionContext) => {
    const user = context.switchToHttp().getRequest().user;

    if (!user) throw new NotFoundException('User not found');

    if (filter && !user?.[filter]) {
      throw new NotFoundException(`User ${filter} not found`);
    }

    return filter ? user[filter] : user;
  },
);
