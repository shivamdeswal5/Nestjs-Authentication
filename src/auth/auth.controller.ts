import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { loginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
<<<<<<< HEAD
import { JwtAuthGuard } from './guards/jwt-auth.guard';
=======
import { JwtAuthGuard } from './guards/jwt-auth-guard';
>>>>>>> e1773fb8a27198e9440686a2f81e0d358e109d47

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
    ) { }

    @Post('login')
    login(@Body() dto: loginDto) {
        return this.authService.login(dto);
    }

    @Post('reset-password')
    async resetPassword(@Body() { token, password }: { token: string; password: string }) {
        return this.authService.resetPassword(token, password);
    }

    @UseGuards(JwtAuthGuard)
    @Get('profile')
    getProfile(@Req() request) {
        return {
            message: 'Welcome to profile',
            user: request.user, //fetch user from request
        };
    }

    @UseGuards(JwtAuthGuard)
    @Get('profile')
    getProfile(@Req() request){
        return{
            message:'welcome to profile',
            user: request.user, // fetch user from request
        }
    }
}
