import { Schema } from'mongoose'

const Resort = new Schema (
    {
        resortName: { type: String, required: true },
        region: { type: String, required: true},
        image: { type: String, required: true },
        description: { type: String, required: true},
        verticalRise: { type: Number, required: true },
        baseElevation: { type: Number, required: true},
        summitElevation: { type: Number, required: true},
        numberOfTrails: { type: Number },
        numberOfLifts: { type: Number },
        ticketChild: { type: Number },
        ticketYouth: { type: Number },
        ticketAdult: { type: Number },
        ticketSenior: { type: Number },
        nearbyResorts: { type: Array },
        contactAddress: { type: String, required: true },
        contactEmail: { type: String, required: true },
        contactWebsite: { type: String, required: true },
        coordinates: { type: String },
        programs: { type: Object },
    },
    { timestamps: true }
)

export default Resort