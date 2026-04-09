import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';

@Injectable()
export class UserMatchGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const paramsId = request.params.id;
    const user = request.user;

    if (user.id !== Number(paramsId)) {
      throw new UnauthorizedException(
        'You are allowed to perform this operation',
      );
    }

    return true;
  }
}
