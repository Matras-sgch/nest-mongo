import { Injectable } from '@nestjs/common';
import { SignupRsp, User } from './interfaces/user';
import { CreateUserDTO } from './dto/create-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@Injectable()
export class UsersService {
  // tslint:disable-next-line:no-empty
  constructor(
    @InjectModel('Users')
    private readonly userModel: Model<User>,
  ) {}
  async signup(doc: CreateUserDTO): Promise<SignupRsp> {
    const newUser = new this.userModel(doc);
    return await newUser.save();
  }
}
