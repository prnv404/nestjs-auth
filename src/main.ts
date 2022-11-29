import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
   const app = await NestFactory.create(AppModule);
   app.useGlobalPipes(new ValidationPipe());
   // const reflector = new Reflector();
   // app.useGlobalGuards(new AtGuard(reflector));
   await app.listen(3000);
}
bootstrap();
