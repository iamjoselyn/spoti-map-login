if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
}

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')

const initializePassport = require('./passport-config')
initializePassport(
    passport, 
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
)

const users = []

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false}))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

//Envia los datos de la pagina una vez se inicia session.
app.get('/', checkAutenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
})

//Envia los datos de la pagina de login.
app.get('/login', checkNotAutenticated, (req, res) => {
    res.render('login.ejs')
})

//Envia los datos de la pagina de registro.
app.get('/register', checkNotAutenticated, (req, res) => {
    res.render('register.ejs')
})

//Evita que una vez la session esta iniciada no puedas ir a la pagina de login, en el caso de que no este iniciada, el usuario podra ingresar los datos.
app.post('/login', checkNotAutenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}))

//Evita que una vez la session esta iniciada no puedas ir a la pagina de register, en el caso de que no este iniciada, almacena los datos del nuevo usuario.
app.post('/register', checkNotAutenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        })
        res.redirect('/login')
    } catch {
        res.redirect('/register')
    }
    console.log(users)
})

//Cierra session y regresa a la pagina login.
app.delete('/logout', (req, res, next) => {
    req.logOut()
    res.redirect('/login')
})

//Confirma que si la session esta iniciada continue desde el metodo que fue llamado.
function checkAutenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }

    res.redirect('/login')
}

//Confirma que si la session esta iniciada continue desde el metodo que fue llamado.
function checkNotAutenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/')
    }

    next()
}

app.listen(3000)