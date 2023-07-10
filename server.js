import express from 'express';
import AppRouter from './routes/AppRouter.js';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import cors from 'cors';
import db from './db/index.js'
import mongoose from 'mongoose';
import router from './routes/AppRouter.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.json());
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use('/api', AppRouter);

app.get('/', (req, res) => res.send('Server works'))

app.listen(PORT, () => console.log(`Server started on Port ${PORT}`))