import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document, Types } from 'mongoose';

@Schema({ timestamps: true })
export class ResetPasswordEntity extends Document {
  @Prop({
    type: mongoose.Schema.Types.ObjectId,
    ref: 'UsersEntity',
    required: true,
  })
  userId: Types.ObjectId;

  @Prop({
    type: String,
    unique: true,
    required: true,
  })
  token: string;

  @Prop({
    type: Date,
    required: true,
  })
  expires_at: Date;

  @Prop({
    type: Boolean,
    default: false,
  })
  used: boolean;
}

export const ResetPasswordSchema =
  SchemaFactory.createForClass(ResetPasswordEntity);
