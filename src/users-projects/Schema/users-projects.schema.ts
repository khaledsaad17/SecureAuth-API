import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { Document } from 'mongoose';

@Schema({ timestamps: true })
export class UsersProjectsEntity extends Document {
  @Prop({ type: mongoose.Types.ObjectId, ref: 'UsersEntity', required: true })
  userId: string;

  @Prop({ type: [String], default: [] })
  projectName: string[];
}

export const UsersProjectsSchema =
  SchemaFactory.createForClass(UsersProjectsEntity);
