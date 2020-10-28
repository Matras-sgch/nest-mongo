import { Controller, Post, Body, Get, Request, UseGuards } from '@nestjs/common';
import { User, SignupRsp, LoginRsp } from './interfaces/user';
import { UsersService } from './users.service';
import { CreateUserDTO } from './dto/create-user.dto';
import { AuthGuard } from '@nestjs/passport';
import { ApiBearerAuth } from '@nestjs/swagger';

@Controller('users')
export class UsersController {
  constructor(private userService: UsersService) {}
  @Post('signup')
  async signUp(@Body() user: CreateUserDTO): Promise<SignupRsp> {
    return await this.userService.signUp(user);
  }

  @Post('login')
  async logIn(@Body() user: CreateUserDTO): Promise<LoginRsp> {
    return await this.userService.logIn(user)
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @Get('profile')
  async profile(@Request() req) {
    return req.user
  }
}
