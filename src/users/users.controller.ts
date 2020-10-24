import { Controller, Post, Body } from '@nestjs/common';
import { User, SignupRsp } from './interfaces/user';
import { UsersService } from './users.service';
import { CreateUserDTO } from './dto/create-user.dto';

@Controller('users')
export class UsersController {
  constructor(private userService: UsersService) {}
  @Post('signup')
  async signUp(@Body() user: CreateUserDTO): Promise<SignupRsp> {
    return await this.userService.signup(user);
  }
}
