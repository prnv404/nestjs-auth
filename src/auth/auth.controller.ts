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
import { publicDecrypt } from 'crypto';
import { Request } from 'express';
import {
   GetCurrentUser,
   GetCurrentUserId,
   Public,
} from 'src/common/decoraters';
import { RtGuard } from 'src/common/guards';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
   constructor(private authSerivce: AuthService) {}

   @Public()
   @Post('local/signup')
   @HttpCode(HttpStatus.CREATED)
   signupLocal(@Body() dto: AuthDto): Promise<Tokens> {
      return this.authSerivce.signupLocal(dto);
   }

   @Public()
   @Post('local/signin')
   @HttpCode(HttpStatus.OK)
   signinLocal(@Body() dto: AuthDto): Promise<Tokens> {
      return this.authSerivce.signinLocal(dto);
   }

   @Post('logout')
   @HttpCode(HttpStatus.OK)
   logout(@GetCurrentUserId() userId: number) {
      return this.authSerivce.logout(userId);
   }

   @Public()
   @UseGuards(RtGuard)
   @Post('refresh')
   @HttpCode(HttpStatus.OK)
   refreshToken(
      @GetCurrentUser('refreshToken') refreshToken: string,
      @GetCurrentUserId() userId: number,
   ) {
      return this.authSerivce.refreshToken(userId, refreshToken);
   }
}
