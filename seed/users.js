import Models from '../models/index.js'
import db from '../db/index.js'
const { Users } = Models

db.on('error', console.error.bind(console, 'connection error:'));

const main = async () => {

const users = [
    {
        
        password: "Xin12345",
        email: "xinchen@gmail.com",
        favResorts: []
    },
    {
        
        password: "Ethan1234",
        email: "ethanflatt@gmail.com",
        favResorts: []
    }
  ]
  await Users.deleteMany({})
  await Users.insertMany(users)
  console.log(`seeded users`)
}

const run = async () => {   
    await main()
    db.close()
}

run()