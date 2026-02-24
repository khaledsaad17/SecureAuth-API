import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors();
  app.use(helmet());
  app.setGlobalPrefix('api');
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true, //remove every property with request does not in dto
      // forbidNonWhitelisted: true, // throw error if more than needed send to request
    }),
  );
  // Swagger Config
  const config = new DocumentBuilder()
    .setTitle('SecureAuth Api')
    .setDescription('API documentation for my backend project')
    .setVersion('1.0')
    .addBearerAuth() // مهم لو عندك JWT
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  await app.listen(process.env.PORT ?? 3001);
}
void bootstrap();
