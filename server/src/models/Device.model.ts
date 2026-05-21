import mongoose, { Schema, Document } from "mongoose";

export interface DeviceDocument extends Document {
  deviceId: string;
  devicePublicKey: string;
  manufacturer: string;
  certificateFingerprint: string;
  status: "registered" | "revoked";
  createdAt: Date;
  updatedAt: Date;
}

const DeviceSchema = new Schema<DeviceDocument>(
  {
    deviceId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    devicePublicKey: {
      type: String,
      required: true,
    },
    manufacturer: {
      type: String,
      required: true,
    },
    certificateFingerprint: {
      type: String,
      required: true,
      unique: true,
    },
    status: {
      type: String,
      enum: ["registered", "revoked"],
      default: "registered",
    },
  },
  {
    timestamps: true,
  }
);

export const Device = mongoose.model<DeviceDocument>("Device", DeviceSchema);