import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, HydratedDocument } from 'mongoose';
import { AuthProvider } from 'src/common/types/user-auth-provider.enum';
import { Role } from 'src/common/types/user-role.enum';

@Schema({ timestamps: true })
export class UsersEntity {
  @Prop({ type: String, required: true })
  userName: string;

  @Prop({ type: String, required: true, unique: true })
  email: string;

  @Prop({ type: String, default: null })
  passwordHash: string;

  @Prop({
    type: String,
    enum: AuthProvider,
    required: true,
    default: AuthProvider.LOCAL,
  })
  provider: AuthProvider;

  @Prop({ type: String, enum: Role, default: Role.USER })
  role: string;

  @Prop({ type: Boolean, required: true, default: false })
  twoFactorEnabled: boolean;

  @Prop({ type: String, default: null })
  twoFactorSecret: string;
}

export const UsersSchema = SchemaFactory.createForClass(UsersEntity);

export type UserDocument = HydratedDocument<UsersEntity>;
