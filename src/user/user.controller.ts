import { Controller, Post, Body, HttpException, UseInterceptors, Res, Get, UploadedFile, Param, Patch } from '@nestjs/common';
import { UserService } from './user.service';
import { UserDto } from './dto/user.dto';
import { RequestTokenDto } from './dto/requestToken.dto';
import { OTPType } from 'src/otp/type/otpType';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { Response } from 'express';
import * as path from "path";
import { FileParam } from './dto/fileParam';

@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
  ) {}

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

  @Post('/upload')
  @UseInterceptors(FileInterceptor('image',{
    storage: diskStorage({
      destination: './uploads',
      filename: (req,file,cb) =>{
        cb(null,`${file.originalname}`)
      }
    })
  }))
  async uploadFiles(){
    return 'Success';
  }

  @Get('/get-file')
  getFile(@Res() res:Response, @Body() file:FileParam){
    console.log(file.fileName)
    res.sendFile(path.join(__dirname,"../uploads/"+ file.fileName));    
  }

  @Post('upload-image')
  @UseInterceptors(FileInterceptor('file'))
  uploadImage(@UploadedFile() file: Express.Multer.File) {
    console.log("file received from ",file);    
    return this.userService.handleUpload(file);
  }

  @Patch('add-profile-Image/:id')
  @UseInterceptors(FileInterceptor('file'))
  addProfileImage(@Param('id') id:string, @UploadedFile() file: Express.Multer.File) {
    return this.userService.addProfilePicture(id,file);
  }

  @Get('test-mail')
  testMail(){
    return this.userService.testMail();
  }

}