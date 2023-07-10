import models from '../models/index.js'
const { Plans } = models


const getPlans = async (req, res) => {
    try {
        const plans = await Plans.find({ userName: req.user.email })
        return res.status(200).json(plans)
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const getPlanById = async (req, res) => {
    try {
        const plan = await Plans.findById(req.params.id)
        if (plan) {
            return res.status(200).json(plan)
        } else {
            return res.status(404).json({ message: 'Plan not found' })
        }
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const deletePlan = async (req, res) => {
    try {
        const plan = await Plans.findByIdAndDelete(req.params.id)
        if (plan) {
            return res.status(200).json(plan)
        } else {
            return res.status(404).json({ message: 'Plan not found' })
        }
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const createPlan = async (req, res) => {
    try {
        console.log('line 42', req.body)
        console.log('line 43', req.user)
        const plan = await Plans.create(req.body)
        await plan.save()
        return res.status(200).json(plan)
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

const updatePlan = async (req, res) => {
    try {
        const plan = await Plans.findByIdAndUpdate(req.params.id, req.body)
        if (plan) {
            return res.status(200).json(plan)
        } else {
            return res.status(404).json({ message: 'Plan not found' })
        }
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }
}

export default { getPlans, getPlanById, deletePlan, createPlan, updatePlan }