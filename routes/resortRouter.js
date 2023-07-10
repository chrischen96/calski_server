import express from 'express';

import controllers from '../controllers/resortController.js';
const { getResorts, getResortById, createResort, updateResort, deleteResort } = controllers;

const Router = express.Router();

Router.get('/', getResorts);
Router.post('/', createResort);
Router.get('/:id', getResortById);
Router.put('/:id', updateResort);
Router.delete('/:id', deleteResort);

export default Router;


