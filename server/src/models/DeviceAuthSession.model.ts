import mongoose, { Schema, Document } from "mongoose";

export interface DeviceAuthSessionDocument extends Document {
  deviceCode: string;
  userCode: string;
  deviceId: string;
  status: "pending" | "approved" | "expired";
  expiresAt: Date;
  approvedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const DeviceAuthSessionSchema = new Schema<DeviceAuthSessionDocument>(
  {
    deviceCode: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userCode: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    deviceId: {
      type: String,
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ["pending", "approved", "expired"],
      default: "pending",
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    approvedAt: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

export const DeviceAuthSession = mongoose.model<DeviceAuthSessionDocument>(
  "DeviceAuthSession",
  DeviceAuthSessionSchema
);