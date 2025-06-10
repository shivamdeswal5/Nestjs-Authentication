import { Controller, Post, Get, Patch, Delete, Param, Body, Query, HttpException } from '@nestjs/common';
import { UserService } from './user.service';
import { UserDto } from './dto/user.dto';
import { RequestTokenDto } from './dto/requestToken.dto';
import { OTPType } from 'src/otp/type/otpType';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register')
  async register(@Body() userDto: UserDto) {
    await this.userService.registerUser(userDto);
    return { message: 'User registered successfully and OTP sent to email' };
  }

  @Post('request-otp')
  async requestOTP(@Body() dto: RequestTokenDto){
    const {email} = dto;
    const user = await this.userService.findByEmail(email);

    if(!user){
      throw new HttpException('User not Found',404);
    }
    await this.userService.emailVerification(user,OTPType.OTP);
    return {message:'OTP Sent successfully ..'}
    
  }

  @Post('forget-password')
  async forgotPassword(@Body() dto: RequestTokenDto){
    const {email} = dto;
    const user = await this.userService.findByEmail(email);

    if(!user){
      throw new HttpException('User not Found',404);
    }

    await this.userService.emailVerification(user,OTPType.RESET_LINK);
    return {
      message: 'Password Rest Link has Been sent'
    }
    
  }

}