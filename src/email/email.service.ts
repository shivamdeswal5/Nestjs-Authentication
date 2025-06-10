import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { sendEmailDto } from './dto/email.dto';

@Injectable()
export class EmailService {
    private transporter = nodemailer.createTransport({
    service:'gmail',
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT ,
    auth: {
      user: process.env.MAIL_USERNAME,
      pass: process.env.MAIL_PASSWORD,
    },
  });

  async sendMail(dto:sendEmailDto) {
    await this.transporter.sendMail({
      from: `'"Zenmonk" <${process.env.MAIL_USERNAME}>`,
      to: dto.recipient,
      subject: dto.subject,
      html: dto.html,
    });
  }

}