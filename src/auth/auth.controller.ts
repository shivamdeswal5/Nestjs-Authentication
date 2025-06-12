import { Body, Controller, Get, Post, Req, Res, Session, UseGuards } from '@nestjs/common';
import { loginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth-guard';
import { Request } from 'express';
import { access } from 'fs';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
    ) { }

    @Post('login')
    async login(@Body() dto: loginDto, @Res({ passthrough: true }) res,@Req() req) {
        const result = await this.authService.login(dto);
        res.cookie('accessToken', result?.accessToken, {
            httpOnly: true,
            expires: new Date(new Date().getTime() + 15 * 60 * 1000)
        })
        .cookie("refreshToken",result?.refreshToken);

        req.session.user = (result?.user) 

        res.send({
            accessToken: result?.accessToken,
            refreshToken: result?.refreshToken,
            userId: result?.user?.id,
            email:result?.user?.email,
            message: "User Logged In Successfully"
        })
    }

    @Post('refresh-token')
    refreshToken(@Req() request:Request){
        return this.authService.refreshAccessToken(request)

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
        return this.authService.getMovies(req);
    }

    @Get('songs')
    async getSongs(
        @Session() session : Record<string,any>
    ){
       return this.authService.getSongs(session);
    }

    @Get('session')
    async getAuthSession(
        @Session() session : Record<string,any>
    ){
        return {
            session : session,
            sessionId: session.id
        };

    }

    // @Get('jwt')
    // getTokens(){
    //     const userId = 'c4358ae3-c7e3-453a-8f0b-09ad3e7416f0'
    //     return this.authService.generateAccessAndRefershToken(userId);
    // }
}

