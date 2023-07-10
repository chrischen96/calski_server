import { Schema } from "mongoose";
import bcrypt from "bcrypt";
import validator from "validator";

const User = new Schema(
    {
        // username: {
        //     type: String,
        //     // required: true,
        //     unique: true
        // },
        password: {
            type: String,
            required: true,
            // validate: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/
        },
        email: {
            type: String,
            // required: true,
            unique: true,
            // validate: /[\w._%+-]+@[\w.-]+\.[a-zA-Z]{2,4}/
        },
        favResorts: {
            type: Array,
            default: []
        }
    },
    {
        timestamps: true
    }
);

//static signup method
User.statics.signup = async function(email, password) {

    //validation
    if (!email || !password) {
        throw Error("Email and password are required");
    }
    if (!validator.isEmail(email)) {
        throw Error("Email is invalid");
        }
    if (!validator.isStrongPassword(password)) {
        throw Error("Password not strong enough");
    }

    const exists = await this.findOne({ email });
    if (exists) {
        throw new Error("Email already exists");
    }
    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(password, salt);

    const User = await this.create({ email, password: hashed });

    return User;
};

//static login method
User.statics.login = async function(password, email) {

    if (!email ||!password) {
        throw Error("Email and password are required");
    }
    const user = await this.findOne({ email });
    if (!user) {
        throw Error("Incorrect email");
    }
    console.log(password, "this should be login",user);

    const Match = await bcrypt.compare(password, user.password);
    console.log(Match, "this should be match");
    if (!Match) {
        throw Error("Incorrect password");
    }

    return user;
};

export default User;