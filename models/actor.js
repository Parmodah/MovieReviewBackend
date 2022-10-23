const mongoose = require("mongoose");

const actorSchema = mongoose.Schema(
  {
    name: {
      type: String,
      trim: true,
      required: true,
    },
    about: {
      type: String,
      trim: true,
      required: true,
    },
    gender: {
      type: String,
      required: true,
      enum: ["male", "female"],
    },
    avatar: {
      type: Object,
      url: String,
      public_id: String,
    },
  },
  { timestamps: true }
);

actorSchema.index({ name: "text" });

module.exports = mongoose.model("Actor", actorSchema);
