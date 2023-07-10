import Models from '../models/index.js'
import db from '../db/index.js'
const { Plans } = Models

db.on('error', console.error.bind(console, 'connection error:'));

const main = async () => {

const plans = [
    {
        userName: "XinChen",
        resortName: "Bear Valley",
        date: "2023-10-20",
        comment: "Bear Valley seems to be the best place to stay in."
    },
    {
        userName: "EthanFlatt",
        resortName: "June Mountain",
        date: '2023-08-05',
        comment: "I would love to go here."
    }
  ]
  await Plans.deleteMany({})
  await Plans.insertMany(plans)
  console.log(`seeded plans`)
}

const run = async () => {   
    await main()
    db.close()
}

run() 