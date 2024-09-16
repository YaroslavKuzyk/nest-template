import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';
import { Transporter } from 'nodemailer';
import activation from './templates/activation';

@Injectable()
export class MailerService {
  private transporter: Transporter;
  readonly smtpEmail: string;
  readonly baseUrl: string;
  readonly frontendUrl: string;

  constructor(private configService: ConfigService) {
    this.smtpEmail = this.configService.get<string>('SMTP_EMAIL');
    this.baseUrl = this.configService.get<string>('BASE_APP_URL');
    this.frontendUrl = this.configService.get<string>('BASE_FRONT_URL');

    this.transporter = nodemailer.createTransport({
      host: this.configService.get<string>('SMTP_HOST'),
      port: this.configService.get<string>('SMTP_PORT'),
      secure: false,
      auth: {
        user: this.smtpEmail,
        pass: this.configService.get<string>('SMTP_PASSWORD'),
      },
    });
  }

  sendActivationEmail(email: string, token: string) {
    const url = `${this.baseUrl}/api/confirm-email?email=${email}&token=${token}`;
    const mailOptions = {
      from: this.smtpEmail,
      to: email,
      subject: 'Confirm your email',
      template: 'activation-email',
      html: activation(url, email),
    };

    return this.transporter.sendMail(mailOptions);
  }
  sendForgotPasswordEmail(email: string, token: string) {
    const url = `${this.frontendUrl}/reset-password?email=${email}&token=${token}`;
    const mailOptions = {
      from: this.smtpEmail,
      to: email,
      subject: 'Reset your password',
      html: `Click <a href="${url}">here</a> to reset your password.`,
    };

    return this.transporter.sendMail(mailOptions);
  }
}
