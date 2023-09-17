const { getAll, create, getOne, remove, update, verifyEmail, login, logguedUser, resetPass, resetPassVerify } = require('../controllers/user.controller');
const express = require('express');
const verifyJWT = require('../verifyJWT');

const userRouter = express.Router();

userRouter.route('/')
    .get(verifyJWT, getAll)
    .post(create);

userRouter.route('/verify/:code')
    .get(verifyEmail)

userRouter.route('/login')
    .post(login)

userRouter.route('/me')
    .get(verifyJWT, logguedUser)

userRouter.route('/reset_password')
    .post(resetPass)
userRouter.route('/reset_password/:code')
    .post(resetPassVerify)

userRouter.route('/:id')
    .get(verifyJWT, getOne)
    .delete(verifyJWT, remove)
    .put(verifyJWT, update);

module.exports = userRouter;