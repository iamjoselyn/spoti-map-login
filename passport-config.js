const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

function initialize(passport, getUserByEmail, getUserById) {
    const authenticateUser = async (email, password, done) => {

        //Search for the user by the email entered.
        const user = getUserByEmail(email)

        //If there is no user with the email entered, send the following message.
        if (user == null) {
            return done(null, false, { message: 'No user with that email' })
        }

        //Compare the password entered with that of the email user, if it matches we return the user, otherwise we show the corresponding error message.
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