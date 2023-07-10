import { Schema } from 'mongoose'

const Plan = new Schema(
    {
        userName: {type: String, ref: 'User', required: true},
        resortName: {type: String, ref: 'Resort', required: true},
        date: {type: String, required: true},
        comment: {type: String, required: true}
    },
    {timestamps: true}
)

export default Plan