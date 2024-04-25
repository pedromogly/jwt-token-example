const express = require('express')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
require('dotenv').config()
const User = require('./models/User')

const app = express()
app.use(express.json())

app.get('/', (req,res)=>{
    res.status(200).json({msg: 'Conectado'})
})

function checkToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]
    if(!token){
        return res.status(404).json({msg: 'Acesso negado'})
    }
    
    try {
        const secret= process.env.SECRET
        jwt.verify(token, secret)
        next()
    }catch(err){
        res.status(400).json({msg: "Token invalido"})
    }
}

//rota privada
app.get('/user/:id', checkToken, async (req,res)=>{
    const id = req.params.id
    const user = await User.findByIdAndUpdate(id, '-pass')
    if(!user){
        return res.status(404).json({msg: 'usuário não encontrado'})
    }

    user.markModified('__v')
    user.__v++
    await user.save()
    res.status(200).json({msg: 'usuario logado',user})

})

app.get('/ranks', async(req,res)=>{
    let count = 0
    const users = await User.find().select('-pass -email -id').sort({__v: -1}).lean()
    const orderUsers = users.map(user=>{
        count++
        return{
            classificacao: `${count}°`,
            __v: user.__v,
            name: user.name
        }
    })

    res.status(200).json({msg: 'ranks de consultas', users: orderUsers})
})

app.post('/auth/register', async (req,res)=>{
    const {name, email, pass, confirmpass} = req.body

    if(!name){
        return res.status(422).json({msg: 'Campo nome obrigatório'})
    }
    if(!email){
        return res.status(422).json({msg: 'Campo email obrigatório'})
    }
    if(!pass){
        return res.status(422).json({msg: 'Campo senha obrigatório'})
    }
    if(!confirmpass){
        return res.status(422).json({msg: 'Campo cofirmação de senha obrigatório'})
    }

    if(pass !== confirmpass){
        return res.status(422).json({msg: 'Senhas não conferem'})
    }

    const userExists = await User.findOne({name: name})
    const emailExists = await User.findOne({email: email})
    if(userExists){
        return res.status(422).json({msg: 'Usuário já cadastrado'})
    }
    if(emailExists){
        return res.status(422).json({msg: 'Email já cadastrado'})
    }

    const salt = await bcrypt.genSalt(12)
    const passHash = await bcrypt.hash(pass, salt)

    const user = new User({
        name,
        email,
        pass: passHash,
    })

    try {
        await user.save()
        res.status(201).json({msg: 'Usuário Cadastrado'})
    }catch(err){
        console.log(err)
        res.status(500).json({msg: 'Erro ao cadastrar no banco de dados'})
    }

})

//login
app.post('/auth/login', async(req,res)=>{
    const {name, pass} = req.body
    if(!name){
        return res.status(422).json({msg: 'Campo usuário obrigatório'})
    }
    if(!pass){
        return res.status(422).json({msg: 'Campo senha obrigatório'})
    }

    const user = await User.findOne({name: name})
    if(!user){
        return res.status(404).json({msg: 'Usuário não existe'})
    }

    const checkPass = await bcrypt.compare(pass, user.pass)
    if(!checkPass){
        return res.status(422).json({msg: 'Senha inválida'})
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id
        },secret,)
        console.log(`usuario ${user.name} logado`)
        res.status(200).json({msg: 'Usuário logado com sucesso', token})
    }catch(err){
        console.log(err)
        res.status(500).json({msg: 'Erro ao logar'})
    }
})


const dbuser = process.env.DBUSER
const dbpass = process.env.DBPASS

mongoose.connect(`mongodb+srv://${dbuser}:${dbpass}@cluster0.v7vmc8j.mongodb.net/Auths`)
.then(
    console.log('db ligado'),
    app.listen(7171, (console.log('Servidor ON')))
).catch((err)=>{
    console.log(`erro ao entrar no bd: ${err}`)
})

