import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';
import {
  CreateUserDto,
  LoginUserDto,
  ForgotPasswordDto,
  ResetPasswordDto,
} from './Dtos/user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './Entities/user.entity';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as uuid from 'uuid';
import { MailerService } from '../mailer/mailer.service';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
    private mailerService: MailerService,
  ) {}

  async signUp(data: CreateUserDto) {
    try {
      const { email, password } = data;
      const candidate = await this.usersRepository.findOne({
        where: { email },
      });

      if (candidate) {
        throw new HttpException(
          'User with this email already exists',
          HttpStatus.BAD_REQUEST,
        );
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const activated_token = uuid.v4();

      const user = this.usersRepository.create({
        email,
        password: hashedPassword,
        activated_token,
      });

      await this.usersRepository.save(user);

      this.mailerService.sendActivationEmail(email, activated_token);
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async signIn(data: LoginUserDto) {
    try {
      const { email, password } = data;
      const user = await this.usersRepository.findOne({ where: { email } });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        const errors = {
          error: 'Unprocessable Entity',
          message: [
            {
              field: 'password',
              errors: ['Invalid email or password'],
            },
          ],
          statusCode: 422,
        };
        throw new UnprocessableEntityException(errors);
      }
      const token = this.jwtService.sign({ id: user.id }, { expiresIn: '1h' });
      user.token = token;
      await this.usersRepository.save(user);
      return { token };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async forgotPassword(data: ForgotPasswordDto) {
    try {
      const { email } = data;
      const user = await this.usersRepository.findOne({ where: { email } });
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
      const reset_token = uuid.v4();
      user.reset_token = reset_token;
      user.reset_token_expiration = new Date(Date.now() + 3600000);
      await this.usersRepository.save(user);
      this.mailerService.sendForgotPasswordEmail(email, reset_token);
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async resetPassword(data: ResetPasswordDto) {
    try {
      const { password, email, token } = data;
      const user = await this.usersRepository.findOne({ where: { email } });

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      if (
        user.reset_token !== token ||
        user.reset_token_expiration < new Date()
      ) {
        throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
      user.reset_token = null;
      user.reset_token_expiration = null;

      await this.usersRepository.save(user);

      return 'Password reset successfully';
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async confirmEmail(email: string, token: string) {
    try {
      const candidate = await this.usersRepository.findOne({
        where: { email },
      });

      if (!candidate) {
        return new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      if (candidate.activated_token !== token) {
        return new HttpException('Invalid token', HttpStatus.BAD_REQUEST);
      }

      candidate.is_active = true;
      candidate.activated_token = null;

      await this.usersRepository.save(candidate);

      return 'Email confirmed';
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async getAllUsers() {
    try {
      return await this.usersRepository.find();
    } catch (error) {
      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async getUser(token: string) {
    try {
      const candidate = await this.usersRepository.findOne({
        where: { token },
      });

      if (!candidate) {
        throw new UnauthorizedException('Invalid token');
      }

      const { id, email, is_active } = candidate;

      return {
        id,
        email,
        is_active,
      };
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(
        'Internal server error',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}
