import { IsEmail, MinLength, MaxLength, IsNotEmpty } from 'class-validator';
import { Match } from '../../utils/decorators/match.decorator';

export class CreateUserDto {
  @IsEmail(
    {},
    { message: JSON.stringify({ message: 'INVALID_EMAIL', args: [] }) },
  )
  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  email: string;

  @MinLength(6, {
    message: JSON.stringify({
      message: 'MUST_BE_AT_LEAST_CHARACTERS',
      args: [6],
    }),
  })
  @MaxLength(20, {
    message: JSON.stringify({
      message: 'MUST_BE_AT_MOST_CHARACTERS',
      args: [20],
    }),
  })
  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  password: string;

  @MinLength(6, {
    message: JSON.stringify({
      message: 'MUST_BE_AT_LEAST_CHARACTERS',
      args: [6],
    }),
  })
  @MaxLength(20, {
    message: JSON.stringify({
      message: 'MUST_BE_AT_MOST_CHARACTERS',
      args: [20],
    }),
  })
  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  @Match('password', {
    message: JSON.stringify({ message: 'PASSWORDS_ARE_DIFFERENT', args: [] }),
  })
  confirm_password: string;
}

export class LoginUserDto {
  @IsEmail(
    {},
    { message: JSON.stringify({ message: 'INVALID_EMAIL', args: [] }) },
  )
  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  email: string;

  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  password: string;
}

export class ForgotPasswordDto {
  @IsEmail(
    {},
    { message: JSON.stringify({ message: 'INVALID_EMAIL', args: [] }) },
  )
  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  email: string;
}

export class ResetPasswordDto {
  @MinLength(6, {
    message: JSON.stringify({
      message: 'MUST_BE_AT_LEAST_CHARACTERS',
      args: [6],
    }),
  })
  @MaxLength(20, {
    message: JSON.stringify({
      message: 'MUST_BE_AT_MOST_CHARACTERS',
      args: [20],
    }),
  })
  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  password: string;

  @MinLength(6, {
    message: JSON.stringify({
      message: 'MUST_BE_AT_LEAST_CHARACTERS',
      args: [6],
    }),
  })
  @MaxLength(20, {
    message: JSON.stringify({
      message: 'MUST_BE_AT_MOST_CHARACTERS',
      args: [20],
    }),
  })
  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  @Match('password', {
    message: JSON.stringify({ message: 'PASSWORDS_ARE_DIFFERENT', args: [] }),
  })
  confirm_password: string;

  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  @IsEmail(
    {},
    { message: JSON.stringify({ message: 'INVALID_EMAIL', args: [] }) },
  )
  email: string;

  @IsNotEmpty({ message: JSON.stringify({ message: 'NOT_EMPTY', args: [] }) })
  token: string;
}
