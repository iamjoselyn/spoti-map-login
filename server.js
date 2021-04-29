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

//Send the home page details once you have logged in.
app.get('/', checkAutenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name })
})

//Send the data of the login page, if the session is not started.
app.get('/login', checkNotAutenticated, (req, res) => {
    res.render('login.ejs')
})

//Send the data of the registration page, if the session is not started.
app.get('/register', checkNotAutenticated, (req, res) => {
    res.render('register.ejs')
})

//Avoid that once the session is started you cannot go to the login page, in case it is not started, the user can enter the data.
app.post('/login', checkNotAutenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}))

//Avoid that once the session is started you cannot go to the register page, in case it is not started, it stores the data of the new user.
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

//Log out and return to the login page.
app.delete('/logout', (req, res, next) => {
    req.logOut()
    res.redirect('/login')
})

//Confirm that if the session is started continue from the method that was called, otherwise it returns you to the login
function checkAutenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }

    res.redirect('/login')
}

//Confirm that if the session is started it will send you to the main page, otherwise continue from the method that was called.
function checkNotAutenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/')
    }

    next()
}

app.listen(3000)