import { BadRequestException, HttpException, Injectable, NotFoundException } from '@nestjs/common';
import { UserRepository } from './user.repository';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';
import { UserDto } from './dto/user.dto';
import { OTPService } from '../otp/otp.service';
import { OTPType } from '../otp/type/otpType';
import { EmailService } from 'src/email/email.service';
import { ConfigService } from '@nestjs/config';
import { CloudinaryService } from 'src/cloudinary/cloudinary.service';
import { MailerService } from '@nestjs-modules/mailer';


@Injectable()
export class UserService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly otpService: OTPService,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
    private readonly cloudinaryService: CloudinaryService,
    private readonly mailerService: MailerService

  ) {}

  //register user
  async registerUser(dto: UserDto) {
    const { email, password } = dto;
    const existingUser = await this.userRepository.findOne({ where: { email } });
    if (existingUser) {
      throw new HttpException('User already exists', 400);
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = this.userRepository.create({
      email,
      password: hashedPassword,
    });

    await this.userRepository.save(newUser);
    return this.emailVerification(newUser, OTPType.OTP);

  }

  async addProfilePicture(userId: string,file:Express.Multer.File) {
    const user = await this.userRepository.findOne({ where: { id: userId } });
    if(!user){
      throw new NotFoundException('User Not Found ..')
    }
    const { message, url } = await this.handleUpload(file);
    console.log("Image Url: ",url);
    user.profileImg = url;
    return this.userRepository.save(user);
  }

  async emailVerification(user: User, otpType: OTPType) {
    const token = await this.otpService.generateToken(user, otpType);
    if (otpType === OTPType.OTP) {
      const emailDto = {
        recipient: [user.email],
        subject: 'OTP for verification',
        html: `Your OTP is ${token}. It is valid for 5 minutes.`,
      }
        const emailData = {
        to: user.email,
        from: 'deswalworks@gmail.com',
        subject: 'OTP for verification',
        html: `Your OTP is ${token}. It is valid for 5 minutes.`,
      }
      return await this.mailerService.sendMail(emailData);
    }
    else if (otpType === OTPType.RESET_LINK) {
      const resetLink = `${this.configService.get<string>('RESET_PASSWORD_URL')}?token=${token}`;
      console.log(this.configService.get<string>('RESET_PASSWORD_URL'))
      console.log(resetLink);

      const emailDto = {
        recipient: [user.email],
        subject: 'Password Reset Link',
        html: `Click Given Link To Change Password:
        <p><a href = "${resetLink}">Reset Password</a></P>`,
      }
      const emailData = {
        to: user.email,
        from: 'deswalworks@gmail.com',
        subject: 'Password Reset Link',
        html: `Click Given Link To Change Password:
        <p><a href = "${resetLink}">Reset Password</a></P>`,
      }
      // return await this.emailService.sendMail(emailDto);
      return this.mailerService.sendMail(emailData);

    }

  }

  async findByEmail(email: string): Promise<User> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new HttpException('User not found', 404);
    }
    return user;
  }

  async handleUpload(file:Express.Multer.File){
     if (!file) {
      throw new BadRequestException('no file uploaded');
    }
    const allowedImageMimeTypes = ['image/jpeg', 'image/png', 'image/avif'];
    if (!allowedImageMimeTypes.includes(file.mimetype)) {
      throw new BadRequestException('Invalid file type');
    }
    const maxSize = 5 * 1024 * 1024; 
    if (file.size > maxSize) {
      throw new BadRequestException('File is to large, Please Compress and try again ...!');
    }

    const result =  this.cloudinaryService.uploadImage(file);
    const imageUrl = (await result).url

    // const emailDto = {
    //     recipient: ['shivam.1171@zenmonk.tech'],
    //     subject: 'Image Uploaded To Cloudinary',
    //     html: `File Has Been Uploaded to Cloudinary. Link Of Uploaded File:
    //     <p><a href = "${imageUrl}">File Url</a></P>`,
    //   }
    //   this.emailService.sendMail(emailDto);

      const emailData = {
        to:'deswalworks@gmail.com',
        from: 'deswalworks@gmail.com',
        subject: 'Image Uploaded To Cloudinary',
        html: `File Has Been Uploaded to Cloudinary. Link Of Uploaded File:
        <p><a href = "${imageUrl}">File Url</a></P>`
      }

      this.mailerService.sendMail(emailData);

      return {
        message: 'Image Uploaded Successfully, Please Check your mail',
        url: (await result).secure_url
      };
  }

  async testMail(){
    try{
      await this.mailerService.sendMail({
      to:'deswalworks@gmail.com',
      from: 'deswalworks@gmail.com',
      subject: 'Testing Nest MailerModule',
      text: 'welcome',
      html: '<b>Mailer Moduler</b>'
    })
    }catch(error){
    console.log(error);
    throw error;
  }
}

}
