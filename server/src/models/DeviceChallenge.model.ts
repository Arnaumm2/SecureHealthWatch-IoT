import mongoose, { Schema, Document } from "mongoose";

export interface DeviceChallengeDocument extends Document {
  nonce: string;
  status: "pending" | "used" | "expired";
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

const DeviceChallengeSchema = new Schema<DeviceChallengeDocument>(
  {
    nonce: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    status: {
      type: String,
      enum: ["pending", "used", "expired"],
      default: "pending",
    },
    expiresAt: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

export const DeviceChallenge = mongoose.model<DeviceChallengeDocument>(
  "DeviceChallenge",
  DeviceChallengeSchema
);