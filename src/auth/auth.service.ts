import { BadRequestException, HttpException, Injectable, UnauthorizedException } from '@nestjs/common';
import { loginDto } from './dto/login.dto';
import { UserRepository } from 'src/user/user.repository';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { OTPService } from 'src/otp/otp.service';
import { User } from 'src/user/entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class AuthService {
    constructor(
        private readonly userRepository: UserRepository,
        private readonly jwtService: JwtService,
        private readonly otpService: OTPService,
        private readonly configService: ConfigService
    ) { }

    async login(dto: loginDto, res) {
        const { email, password, otp } = dto;
        try {
            const user = await this.userRepository.findOne({ where: { email } });
            if (!user) {
                throw new HttpException('User not found', 404);
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                throw new HttpException('Invalid password', 401);
            }

            console.log("Login User: ", user);

            if (user.accountStatus === 'unverified') {
                console.log("OTP is: ", otp)
                if (!otp) {
                    return {
                        message: `Your Account is not Verifed. Please provide otp to verify you account`
                    }
                } else {
                    console.log("verifying token: ");
                    await this.verifyToken(user.id, otp);
                }
            }

            //generate JWT token
            const payload = { id: user.id, email: user.email };
            const accessToken = this.jwtService.sign(payload);
            console.log("ACCESS TOKEN", accessToken)

            return {
                accessToken,
                userId: user.id,
                email: user.email
            };

        } catch (error) {
            if (error instanceof HttpException || error instanceof UnauthorizedException) {
                throw error
            }
        }

    }

    async verifyToken(userId: string, token: string): Promise<User> {
        await this.otpService.validateOtp(userId, token);
        const user = await this.userRepository.findOne({
            where: {
                id: userId
            }
        })
        if (!user) {
            throw new UnauthorizedException('user not found')
        }

        user.accountStatus = 'verified'
        await this.userRepository.save(user);
        console.log("USER: ", user);
        return user;
    }


    async resetPassword(token: string, newPassword: string) {
        const userId = await this.otpService.validateResetPassword(token);

        const user = await this.userRepository.findOne({ where: { id: userId } });

        if (!user) {
            throw new BadRequestException('User not found');
        }
        user.password = await bcrypt.hash(newPassword, 10);
        await this.userRepository.save(user);

        return 'Password reset successfully';
    }


    async getMovies(req:Request) {
        const token = req.cookies['accessToken']
        try {
            
            const decoded = this.jwtService.verify(token, {
                secret: this.configService.get<string>('JWT_SECRET'),
            });

            const userDetails = {
                id: decoded.id,
                email: decoded.email,
            };

            return {
                user: userDetails,
                movies: ['Avengers','Squid Game']

            };
        } catch (error) {
            throw new UnauthorizedException('Invalid or expired token');
        }
    }

}


