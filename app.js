require('dotenv').config()

const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASSWORD

app.use(express.json())

//Public Routes
app.get('/', (req, res) => {
    res.status(200).json({msg: 'Bem vindo a nossa API!'})
})

// Private Route

app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    //check if user exist
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(422).json({msg: 'Usuario não encontrado'})
    }

    try{
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch(err){
        return res.status(400).json({msg: 'Token Invalido'})
    }
    res.status(200).json({ user })
})

function checkToken(req, res, next) {
    const authHeader = req.headers['autorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token){
        return res.status(401).json({msg: 'Acesso Negado'})
    }
}


//Models
const User = require('./models/User')

//Register User
app.post('/auth/v1/register', async(req, res) => {

    if(req.method != 'POST'){
        return res.status(405).json({msg: 'Metodo invalido, Utilize o Metodo POST para utilizar!'})
    }

    const {name, email, password, confirmpassword} = req.body

    //validations
    if(!name){
        return res.status(422).json({msg: 'Nome é obrigatorio'})
    }

    if(!email){
        return res.status(422).json({msg: 'Email é obrigatorio'})
    }
    
    if(!password){
        return res.status(422).json({msg: 'Senha é obrigatorio'})
    }

    if(password != confirmpassword){
        return res.status(422).json({msg: 'As senhas não conferem'})
    }

    //Check if exist user
    const userExists = await User.findOne({email: email})

    if(userExists){
        return res.status(422).json({msg: 'Email já cadastrado! Utilize outro email'})
    }

    // Crate Password
    const salt = await bcrypt.genSalt(12)
    const passHash = await bcrypt.hash(password, salt)

    //Create User
    const user = new User(
        {
            name,
            email,
            password:passHash
        }
    )
    try{
        await user.save()
        res.status(201).json({msg: 'Usuario Criado com sucesso!'})
    } catch(err) {
        console.log(err)

        return res.status(500).json({msg: 'Erro Interno do servidor, tente novamente mais tarde'})
    }
})

app.post('/auth/v1/login', async(req, res) => {

    const {email, password} = req.body

    if(!email){
        return res.status(422).json({msg: 'Email é obrigatorio'})
    }
    
    if(!password){
        return res.status(422).json({msg: 'Senha é obrigatorio'})
    }

    //Check if exist user
    const user = await User.findOne({email: email})

    if(!user){
        return res.status(404).json({msg: 'Usuario não encontrado'})
    }

    //Check password
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        return res.status(422).json({msg: 'Senha invalida'})
    }

    try{
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id
            },
            secret
        )
        res.status(200).json({msg: 'Autenticação realizada com sucesso!', token: token})
    } catch(err){
        console.log(err)

        return res.status(500).json({msg: 'Erro Interno do servidor, tente novamente mais tarde'})
    }
})

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.qyszxp2.mongodb.net/?retryWrites=true&w=majority`).then(() => console.log('Conectado com sucesso')).catch((err) => console.log(err))

app.listen(3000)