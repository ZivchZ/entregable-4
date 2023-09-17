const catchError = require('../utils/catchError');
const User = require('../models/User');
const EmailCode = require('../models/EmailCode')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');


const getAll = catchError(async(req, res) => {
    const users = await User.findAll();
    return res.json(users);
});

const create = catchError(async(req, res) => {
    const { email, password, firstName, lastName, country, image, frontBaseUrl } = req.body;

    const passEncrypted = await bcrypt.hash(password, 10)
    const user = await User.create({
        email, password: passEncrypted, firstName, lastName, country, image
    });

    const code = require('crypto').randomBytes(32).toString('hex')
    const link = `${frontBaseUrl}/auth/verify_email/${code}`

    await EmailCode.create({
        code,
        userId: user.id
    });

    await sendEmail({
        to: `${email}`,
        subject: "Verificación de Usuario exitoso",
        html: `
        <h1>Hola ${firstName} ${lastName}</h1>
        <p>Confirmar el usuario a través del siguiente link:</p>
        <a href="${link}">${link}<a/>
        `
});

    return res.status(201).json(user);
});

const getOne = catchError(async(req, res) => {
    const { id } = req.params;
    const user = await User.findByPk(id);
    if(!user) return res.sendStatus(404);
    return res.json(user);
});

const remove = catchError(async(req, res) => {
    const { id } = req.params;
    await User.destroy({ where: {id} });
    return res.sendStatus(204);
});

const update = catchError(async(req, res) => {
    const { id } = req.params;
    const user = await User.update(
        req.body,
        { where: {id}, returning: true }
    );
    if(user[0] === 0) return res.sendStatus(404);
    return res.json(user[1][0]);
});

const verifyEmail = catchError(async(req, res) => {
    const { code } = req.params;
    const emailCode = await EmailCode.findOne({where: {code: code}});
    if(!emailCode) return res.status({message: "Codigo invalido"});
const user = await User.update({isVerified: true}, {where: {id: emailCode.userId}, returning: true});

await emailCode.destroy()

    return res.json(user)
});

const login = catchError(async(req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({where: {email}}); //! isVerified: true
    if(!user) return res.status(401).json({ message: "invalid credentials" });

    const isValid = await bcrypt.compare(password, user.password);
    if(!isValid) return res.status(401).json({ message: "invalid credentials" });

    const token = jwt.sign(
        {user},
        process.env.TOKEN_SECRET,
        {expiresIn: '1d'}
    )
    // const {isVerified} = req.params;
    if(!user.isVerified) return res.status(401).json({message: "El usuario no se encuentra verificado"})
    
    return res.json({user, token});
});

const logguedUser = catchError(async(req, res) => {
    const user = req.user;
    return res.json(user);
});

const resetPass = catchError(async(req, res) => {
    const { email, frontBaseUrl } = req.body;
    const user = await User.findOne({where: {email}});
    if(!user) return res.status(401).json({ message: "Usuario no encontrado" });

    const code = require('crypto').randomBytes(32).toString('hex');
    const link = `${frontBaseUrl}/auth/reset_password/${code}`

    await EmailCode.create({
        code,
        userId: user.id
    });

    await sendEmail({
        to: `${email}`,
        subject: "Recuperación de contraseña",
        html: `
        <h1>Hola ${user.firstName} ${user.lastName}</h1>
        <p>Haz click en el siguiente link para recuperar tu contraseña:</p>
        <a href="${link}">${link}<a/>
        `
});
    return res.json(user)
});

const resetPassVerify = catchError(async(req, res) => {
    const { password } = req.body;

    const { code } = req.params;
    const emailCode =  await EmailCode.findOne({where: {code: code}});
    if(!emailCode) return res.status({message: "Codigo invalido"});

    const passEncrypted =  await bcrypt.hash(password, 10);
    const user =  await User.update({password: passEncrypted}, {where: {id: emailCode.userId}, returning: true});

    await emailCode.destroy()
    return res.json(user)
});

module.exports = {
    getAll,
    create,
    getOne,
    remove,
    update,
    verifyEmail,
    login,
    logguedUser,
    resetPass,
    resetPassVerify
}