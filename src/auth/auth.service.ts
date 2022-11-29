import { Body, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
   constructor(private prisma: PrismaService, private jwtService: JwtService) {}

   /**
    * We create a new user in the database, get a token for the user, and then update the refresh token
    * hash in the database
    * @param {AuthDto} dto - AuthDto - this is the data that is passed in from the frontend.
    * @returns Tokens
    */

   async signupLocal(dto: AuthDto): Promise<Tokens> {
      const hash = await this.hashData(dto.password);
      const newUser = await this.prisma.user.create({
         data: {
            email: dto.email,
            hash,
         },
      });
      const tokens = await this.getToken(newUser.id, newUser.email);
      await this.updateRtHash(newUser.id, tokens.refresh_token);

      return tokens;
   }

   /**
    * It takes an email and password, finds the user in the database, checks if the password matches, and
    * if it does, it returns a set of tokens
    * @param {AuthDto} dto - AuthDto - the object that contains the email and password of the user.
    * @returns Tokens
    */
   async signinLocal(dto: AuthDto): Promise<Tokens> {
      const user = await this.prisma.user.findUnique({
         where: {
            email: dto.email,
         },
      });

      if (!user) throw new ForbiddenException('Access denied');

      const isPasswordMatch = await bcrypt.compare(dto.password, user.hash);

      if (!isPasswordMatch) throw new ForbiddenException('Access denied');

      const tokens = await this.getToken(user.id, user.email);

      await this.updateRtHash(user.id, tokens.refresh_token);

      return tokens;
   }

   /**
    * It takes a userId as an argument, and then updates the user's hashedRt to null
    * @param {number} userId - The user's id.
    */
   async logout(userId: number) {
      const user = await this.prisma.user.updateMany({
         where: {
            id: userId,
         },
         data: {
            hashedRt: null,
         },
      });
      if (!user) throw new ForbiddenException('Access denied');
   }

   /**
    * It takes a userId and a refresh token, checks if the user exists, if the refresh token matches the
    * one stored in the database, and if so, returns a new set of tokens
    * @param {number} userId - The user's id
    * @param {string} rt - refresh token
    * @returns Tokens
    */
   async refreshToken(userId: number, rt: string): Promise<Tokens> {
      const user = await this.prisma.user.findUnique({
         where: {
            id: userId,
         },
      });
      if (!user) throw new ForbiddenException('Access denied');
      const rtMatches = await bcrypt.compare(rt, user.hashedRt);

      if (!rtMatches) throw new ForbiddenException('Access denied');

      const tokens = await this.getToken(user.id, user.email);

      await this.updateRtHash(user.id, tokens.refresh_token);

      return tokens;
   }

   // Helper functions

   /**
    * It takes a userId and a refresh token, hashes the refresh token, and then updates the user's
    * hashedRt field with the hash
    * @param {number} userId - The user's id
    * @param {string} rt - The refresh token that was sent to the client.
    */
   async updateRtHash(userId: number, rt: string) {
      const hash = await this.hashData(rt);
      await this.prisma.user.update({
         where: {
            id: userId,
         },
         data: {
            hashedRt: hash,
         },
      });
   }

   /**
    * It takes a string, hashes it, and returns the hash
    * @param {string} data - The data to be hashed.
    */
   hashData(data: string) {
      return bcrypt.hash(data, 10);
   }

   /**
    * It takes a userId and email, and returns an object with an access_token and refresh_token
    * @param {number} userId - The user's ID
    * @param {string} email - The email of the user
    * @returns Tokens
    */
   async getToken(userId: number, email: string): Promise<Tokens> {
      const [at, rt] = await Promise.all([
         this.jwtService.signAsync(
            {
               sub: userId,
               email,
            },
            {
               secret: 'at-secret',
               expiresIn: 60 * 15,
            },
         ),
         this.jwtService.signAsync(
            {
               sub: userId,
               email,
            },
            {
               secret: 'rt-secret',
               expiresIn: 60 * 60 * 24 * 7,
            },
         ),
      ]);

      return {
         access_token: at,
         refresh_token: rt,
      };
   }
}
