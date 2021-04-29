const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

function initialize(passport, getUserByEmail, getUserById) {
    const authenticateUser = async (email, password, done) => {

        //Buscamos el usuario por el email ingresado
        const user = getUserByEmail(email)

        //Si no existe usuario con el email ingresado, envia el siguiente mensage
        if (user == null) {
            return done(null, false, { message: 'No user with that email' })
        }

        //Comparamos la contraseña ingresada con el del usuario del email, si coincide devolvemos el usuario, en caso contrario mostramos el mensage de error corespondiente
        try {
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user)
            } else {
                return done(null, false, { message: 'Password incorrect' })
            }
        } catch (e) {
            return done(e)
        }
    }

    passport.use(new LocalStrategy({ usernameField: 'email'},
    authenticateUser))
    passport.serializeUser((user, done) => done(null, user.id))
    passport.deserializeUser((id, done) => {
        done(null, getUserById(id))
    })
}

module.exports = initialize