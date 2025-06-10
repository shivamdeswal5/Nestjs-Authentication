import {
  IsEmail,
  IsNotEmpty,
} from 'class-validator';

export class RequestTokenDto {

  @IsNotEmpty()
  @IsEmail()
  email: string;
}