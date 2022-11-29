import {
   Body,
   Controller,
   HttpCode,
   HttpStatus,
   Post,
   Req,
   UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
   constructor(private authSerivce: AuthService) {}

   @Post('local/signup')
   @HttpCode(HttpStatus.CREATED)
   signupLocal(@Body() dto: AuthDto): Promise<Tokens> {
      return this.authSerivce.signupLocal(dto);
   }

   @Post('local/signin')
   @HttpCode(HttpStatus.OK)
   signinLocal(@Body() dto: AuthDto): Promise<Tokens> {
      return this.authSerivce.signinLocal(dto);
   }

   @UseGuards(AuthGuard('jwt'))
   @Post('logout')
   @HttpCode(HttpStatus.OK)
   logout(@Req() req: Request) {
      const user = req.user;
      return this.authSerivce.logout(user['sub']);
   }

   @UseGuards(AuthGuard('jwt-refresh'))
   @Post('refresh')
   @HttpCode(HttpStatus.OK)
   refreshToken(@Req() req: Request) {
      const user = req.user;
      return this.authSerivce.refreshToken(user['sub'], user['refresh_token']);
   }
}
