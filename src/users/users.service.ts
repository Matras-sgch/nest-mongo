import { Injectable, UnauthorizedException } from '@nestjs/common';
import { SignupRsp, User } from './interfaces/user';
import { CreateUserDTO } from './dto/create-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { PasswordHasherService } from './auth/password-hasher/password-hasher.service';

@Injectable()
export class UsersService {
  // tslint:disable-next-line:no-empty
  constructor(
    @InjectModel('Users')
    private readonly userModel: Model<User>,
    private hasherService: PasswordHasherService
  ) {}
  async signup(doc: CreateUserDTO): Promise<SignupRsp> {
    // if user has already creted with this email
    // send the error
    const user = await this.userModel.findOne({ email: doc.email })
    if (user) {
      throw new UnauthorizedException(`User already created with this email: ${doc.email}`)
    }

    // encrypt the user password before saving to database
    const encryptedPassword = await this.hasherService.hashPassword(doc.password)
    const newUser = new this.userModel({ email: doc.email, password: encryptedPassword });
    await newUser.save()
    return { email: newUser.email}
  }
}
