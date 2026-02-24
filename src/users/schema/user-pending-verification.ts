import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, HydratedDocument } from 'mongoose';

@Schema({ timestamps: true })
export class PendingUserVerificationEntity {
  @Prop({ type: String, required: true })
  userName: string;

  @Prop({ type: String, required: true, unique: true })
  email: string;

  @Prop({ type: String, required: true })
  passwordHash: string;

  @Prop({ type: String, required: true })
  verificationToken: string;

  @Prop({ type: Date, default: Date.now, expires: 86400 }) // يتمسح بعد 24 ساعة
  createdAt: Date;
}
export const PendingUserSchema = SchemaFactory.createForClass(
  PendingUserVerificationEntity,
);

export type PendingUserDocument =
  HydratedDocument<PendingUserVerificationEntity>;
