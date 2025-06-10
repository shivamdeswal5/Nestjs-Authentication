import { HttpException, Injectable } from '@nestjs/common';
import { UserRepository } from './user.repository';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcrypt';
import { UserDto } from './dto/user.dto';
import { OTPService } from '../otp/otp.service';
import { OTPType } from '../otp/type/otpType';
import { EmailService } from 'src/email/email.service';
import { ConfigService } from '@nestjs/config';


@Injectable()
export class UserService {
  constructor(
    private readonly userRepository: UserRepository,
    private readonly otpService: OTPService,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService
  ) { }

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

  async emailVerification(user: User, otpType: OTPType) {

    const token = await this.otpService.generateToken(user, otpType);

    if (otpType === OTPType.OTP) {
      const emailDto = {
        recipient: [user.email],
        subject: 'OTP for verification',
        html: `Your OTP is ${token}. It is valid for 5 minutes.`,
      }
      return await this.emailService.sendMail(emailDto);
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

      return await this.emailService.sendMail(emailDto);

    }

  }

  async findByEmail(email: string): Promise<User> {
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) {
      throw new HttpException('User not found', 404);
    }
    return user;
  }
}
