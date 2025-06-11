import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EmailModule } from './email/email.module';
import { UserModule } from './user/user.module';
import { OtpModule } from './otp/otp.module';
import { AuthModule } from './auth/auth.module';
import { CloudinaryModule } from './cloudinary/cloudinary.module';
import { MailerModule } from '@nestjs-modules/mailer';
import { PugAdapter } from '@nestjs-modules/mailer/dist/adapters/pug.adapter';
import * as path from 'path';
import * as dotenv from 'dotenv';
dotenv.config();
 
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: () => ({
          type: 'postgres',
          host: process.env.DB_HOST,
          port: Number(process.env.DB_PORT),
          username: process.env.DB_USERNAME,
          password: process.env.DB_PASSWORD,
          database: process.env.DB_DATABASE,
          synchronize: false,
          entities: [__dirname + '/**/entities/*.entity{.ts,.js}'],
          migrations: [path.resolve(__dirname, '../database/migrations/*-migration.ts')],
          autoLoadEntities: true,
      }
    ),
    }),

    MailerModule.forRootAsync({
      useFactory: ()=>({
        transport: {
          host: process.env.MAIL_HOST,
          port: process.env.MAIAL_PORT,
          auth:{
            user: process.env.MAIL_USERNAME,
            pass:process.env.MAIL_PASSWORD,
          },
        },
        default: '"No Reply" <deswalworks@gmail.com>',
      })
      
    }),
    
    EmailModule,
    UserModule,
    OtpModule,
    AuthModule,
    CloudinaryModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
