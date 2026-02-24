import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { AuditAction } from '../DTO/audit-action.enum';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class AuditLogEntity extends Document {
  @Prop({ type: String, required: true })
  email: string;

  @Prop({ type: String, required: true, enum: AuditAction })
  action: string;

  @Prop({ type: String })
  projectName?: string;

  @Prop({ type: String })
  ipAddress?: string;

  @Prop({ type: String })
  userAgent?: string;

  @Prop({ type: String })
  status?: string;

  @Prop({ type: Object })
  metadata?: Record<string, any>;
}

export const AuditLogSchema = SchemaFactory.createForClass(AuditLogEntity);
