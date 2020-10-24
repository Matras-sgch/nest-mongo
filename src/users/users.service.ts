import { Injectable } from '@nestjs/common';
import { SignupRsp } from './interfaces/user';
import { CreateUserDTO } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  // tslint:disable-next-line:no-empty
  constructor() {}
  async signup(user: CreateUserDTO): Promise<SignupRsp> {
    throw new Error('Signup not implemented');
  }
}
