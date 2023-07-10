// import express from 'express';
// import {getPlans, getPlanById, deletePlan, createPlan, updatePlan} from '`../controllers/planController`

// const router = express.Router();

// router.get('/getPlans', controller.getPlans);
// router.get('/getPlans/:id', controller.getPlans);
// router.post('/getAllResorts', controller.createPlan);
// router.put('/:id', controller.updatePlan);
// router.delete('/getPlans/:id', controller.deletePlan);

// export default router;


import express from 'express';
import controllers from '../controllers/planController.js'
import requireAuth from './requireAuth.js';

const { getPlans, getPlanById, createPlan, updatePlan, deletePlan } = controllers;

const Router = express.Router();

Router.use(requireAuth);

Router.get('/', getPlans)
Router.get('/:id', getPlanById)
Router.post('/', createPlan)
Router.put('/:id', updatePlan)
Router.delete('/:id', deletePlan)

export default Router