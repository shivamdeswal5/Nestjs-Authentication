import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as path from "path";
import * as cookieParser from 'cookie-parser';
import * as session from 'express-session';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.useStaticAssets(path.join(__dirname,"../uploads"));
  app.enableCors();
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true, 
    forbidNonWhitelisted: true,
    transform: true,
  }));
  
  app.use(cookieParser());
    app.use(
    session({
      name:'NESTJS_SESSION_ID',
      secret: 'cbwcwbvccwuvusv',
      resave: true,
      saveUninitialized:false,
      cookie:{
        maxAge: 60000,
      }

    })
  )

  await app.listen(process.env.PORT ?? 3000); 
}
bootstrap();
