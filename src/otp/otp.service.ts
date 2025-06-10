import { BadRequestException, HttpException, Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { OTP } from "./entities/otp.entity";
import { MoreThan, Repository } from "typeorm";
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import { OTPType } from "./type/otpType";
import { User } from "src/user/entities/user.entity";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class OTPService {
    constructor(
        @InjectRepository(OTP)
        private otpRepository: Repository<OTP>,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService
    ) { }

    async generateToken(user: User, type: OTPType) {

        if (type === OTPType.OTP) {
            const otp = crypto.randomInt(100000, 999999).toString();
            const hashedOtp = await bcrypt.hash(otp, 10);
            const now = new Date();
            const expiresAt = new Date(now.getTime() + 5 * 60 * 1000); // OTP valid for 5 minutes

            const existingOTP = await this.otpRepository.findOne({
                where: { user: { id: user.id }, type }
            })

            if (existingOTP) {
                existingOTP.token = hashedOtp;
                existingOTP.expiresAt = expiresAt;
                await this.otpRepository.save(existingOTP)
            } else {
                const otpEntity = this.otpRepository.create({
                    user,
                    token: hashedOtp,
                    type,
                    expiresAt,
                })

                await this.otpRepository.save(otpEntity);
            }

            const otpEntity = this.otpRepository.create({
                user,
                token: hashedOtp,
                type,
                expiresAt
            });
            await this.otpRepository.save(otpEntity);
            return otp;
        } else if (type === OTPType.RESET_LINK) {
            const resetToken = this.jwtService.sign(
                { id: user.id, email: user.email },
                {
                    secret: this.configService.get<string>('JWT_RESET_SECRET'),
                    expiresIn: '15m',
                }
            )

            return resetToken;
        }
    }

    async validateOtp(userId: string, token: string): Promise<Boolean> {
        const validToken = await this.otpRepository.findOne({
            where: {
                user: { id: userId },
                expiresAt: MoreThan(new Date()),
            }
        });
        if (!validToken) {
            throw new HttpException('Otp is Expired. Request a new one', 401);
        }

        const isMatch = await bcrypt.compare(token, validToken.token);
        if (!isMatch) {
            throw new HttpException('Invalid OTP try again ..', 401);
        }

        return true;

    }

    async validateResetPassword(token: string) {
        try {
            const decoded = this.jwtService.verify(token, {
                secret: this.configService.get<string>('JWT_RESET_SECRET'),
            });

            return decoded.id;
        } catch (error) {
            if (error?.name === 'TokenExpiredError') {
                throw new BadRequestException(
                    'The reset token has expired.Please request a new one',
                );
            }
            throw new BadRequestException('Invalid or malformed reset token');
        }

    }
}
