import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  MaxLength,
} from 'class-validator';

export class UserDto {

  @IsNotEmpty()
  @IsEmail()
  email: string;
  
  @MinLength(4)
  @MaxLength(20)
  password: string;


}