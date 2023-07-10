import express from 'express';
import controllers from '../controllers/userController.js';
const { getUsers, getUserById, createUser, updateUser, deleteUser, loginUser, signupUser } = controllers;

const Router = express.Router();
//login route
Router.post('/login', loginUser)

//signup route
Router.post('/signup', signupUser)

Router.get('/', getUsers)
Router.get('/:id', getUserById)
Router.post('/', createUser)
Router.put('/:id', updateUser)
Router.delete('/:id', deleteUser)

export default Router

