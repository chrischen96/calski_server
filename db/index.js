import mongoose from "mongoose"
import dotenv from 'dotenv'
dotenv.config()

console.log(`mongodb+srv://${process.env.DATABASE_NAME}:${process.env.DATABASE_PASSWORD}@calski.lyliq7c.mongodb.net/calski`)

mongoose
    .connect(`mongodb+srv://${process.env.DATABASE_NAME}:${process.env.DATABASE_PASSWORD}@calski.lyliq7c.mongodb.net/calski`)
    .then(() => {
        console.log('Successfully connected to MongoDB.')
    })
    .catch(e => {
        console.error('Connection error', e.message)
    })

const db = mongoose.connection

export default db