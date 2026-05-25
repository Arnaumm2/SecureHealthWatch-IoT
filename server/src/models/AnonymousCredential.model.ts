import mongoose, { Schema, Document } from "mongoose";

export interface AnonymousCredentialDocument extends Document {
  credentialId: string;
  anonymousPublicKey: string;
  scope: "send-health-telemetry";
  issuedFor: "anonymous-smartwatch";
  expiresAt: Date;
  status: "active" | "revoked" | "expired";
  createdAt: Date;
  updatedAt: Date;
}

const AnonymousCredentialSchema = new Schema<AnonymousCredentialDocument>(
  {
    credentialId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    anonymousPublicKey: {
      type: String,
      required: true,
    },
    scope: {
      type: String,
      enum: ["send-health-telemetry"],
      required: true,
    },
    issuedFor: {
      type: String,
      enum: ["anonymous-smartwatch"],
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    status: {
      type: String,
      enum: ["active", "revoked", "expired"],
      default: "active",
    },
  },
  {
    timestamps: true,
  }
);

export const AnonymousCredential = mongoose.model<AnonymousCredentialDocument>(
  "AnonymousCredential",
  AnonymousCredentialSchema
);