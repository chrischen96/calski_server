import jwt from 'jsonwebtoken';
import models from '../models/index.js'
const { Users } = models

const requireAuth = async (req, res, next) => {
    const { authorization } = req.headers;
    if (!authorization) {
        return res.status(401).json({ message: 'Authorization tolen required' });
    }
    const token = authorization.split(' ')[1];
    try {
        const { _id } = jwt.verify(token, process.env.SECRET);
        req.user = await Users.findOne({ _id }).select('email');
        next();
    } catch (err) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
}

export default requireAuth;