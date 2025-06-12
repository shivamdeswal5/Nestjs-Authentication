import { Body, Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common';
import { loginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth-guard';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
    ) { }

    @Post('login')
    async login(@Body() dto: loginDto, @Res({ passthrough: true }) res) {
        const result = await this.authService.login(dto, res);
        res.cookie('accessToken', result?.accessToken, {
            httpOnly: true,
            expires: new Date(new Date().getTime() + 15 * 60 * 1000)
        });

        res.send({
            ...result
        })
    }

    @Post('reset-password')
    async resetPassword(@Body() { token, password }: { token: string; password: string }) {
        return this.authService.resetPassword(token, password);
    }

    // @UseGuards(JwtAuthGuard)
    @Get('profile')
    getProfile(@Req() request) {
        return {
            message: 'Welcome to profile',
            // user: request.user, 
            user: request['user']
        };
    }

    @Get('/get_cookies')
    getGetCookies(@Req() req): string {
        return req.cookies
    }
    @Get('movies')
    getMovies(@Req() req: Request) {
        // const token = req.cookies['accessToken'];
        // console.log('Token',token)
        return this.authService.getMovies(req);
    }
}

