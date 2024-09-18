import {
  Body,
  Controller,
  Post,
  Get,
  UsePipes,
  Query,
  Res,
  UseGuards,
  Req,
} from '@nestjs/common';
import {
  CreateUserDto,
  LoginUserDto,
  ForgotPasswordDto,
  ResetPasswordDto,
} from './Dtos/user.dto';
import { CustomValidationPipe } from '../utils/validators/CustomValidationPipe';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';

@Controller('api')
export class AuthController {
  readonly frontendUrl: string =
    this.configService.get<string>('BASE_FRONT_URL');

  constructor(
    private readonly authService: AuthService,
    private configService: ConfigService,
  ) {}

  @Get('/test')
  async test(@Res() res: Response) {
    return res.status(200).json({ message: 'test successfully' });
  }

  @Post('sign-up')
  @UsePipes(new CustomValidationPipe())
  async signUp(@Body() CreateUserDto: CreateUserDto) {
    return await this.authService.signUp(CreateUserDto);
  }

  @Get('confirm-email')
  async confirmEmail(
    @Res() res: Response,
    @Query('email') email: string,
    @Query('token') token: string,
  ) {
    const message = await this.authService.confirmEmail(email, token);
    res.redirect(`${this.frontendUrl}/sign-in`);

    return message;
  }

  @Post('sign-in')
  @UsePipes(new CustomValidationPipe())
  async signIn(@Res() res: Response, @Body() LoginUserDto: LoginUserDto) {
    const { token } = await this.authService.signIn(LoginUserDto);

    return res.status(200).json({ token, message: 'Signed in successfully' });
  }

  @Get('sign-out')
  signOut(@Res() res: Response) {
    res.clearCookie('token');

    return res.status(200).json({ message: 'Signed out successfully' });
  }

  @Post('forgot-password')
  @UsePipes(new CustomValidationPipe())
  forgotPassword(@Body() ForgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(ForgotPasswordDto);
  }

  @Post('reset-password')
  @UsePipes(new CustomValidationPipe())
  resetPassword(@Body() ResetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(ResetPasswordDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('users')
  getAllUsers() {
    return this.authService.getAllUsers();
  }

  @UseGuards(JwtAuthGuard)
  @Get('user')
  getUser(@Req() req: Request) {
    const token = req.cookies['token'];
    return this.authService.getUser(token);
  }
}
