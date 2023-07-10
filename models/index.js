import mongoose from "mongoose";
import User from "./user.js";
import Plan from "./plan.js";
import Resort from "./resort.js";

const Users = mongoose.model("Users", User);
const Plans = mongoose.model("Plans", Plan);
const Resorts = mongoose.model("Resorts", Resort);

export default { Users, Plans, Resorts };