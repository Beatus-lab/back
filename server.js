import express from 'express'
import session from 'express-session'
import passport from 'passport'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import dotenv from 'dotenv'
import cors from 'cors'

dotenv.config()

const PORT = process.env.PORT || 4000
const FRONT_URL = process.env.FRONT_URL || 'http://localhost:5173'
const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || '').split(',').map(s => s.trim()).filter(Boolean)

const app = express()

app.use(cors({ origin: FRONT_URL, credentials: true }))
app.use(express.json())

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, sameSite: 'lax' }
}))

app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser((user, done) => done(null, user))
passport.deserializeUser((obj, done) => done(null, obj))

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails && profile.emails[0] && profile.emails[0].value
    if (!email) return done(null, false, { message: 'No email' })
    const domain = email.split('@')[1]
    if (ALLOWED_DOMAINS.length > 0 && !ALLOWED_DOMAINS.includes(domain)) {
      return done(null, false, { message: 'Unauthorized domain' })
    }
    const user = { id: profile.id, displayName: profile.displayName, email }
    return done(null, user)
  } catch (err) {
    return done(err)
  }
}))

app.get('/auth/google', (req, res, next) => {
  const opts = { scope: ['profile', 'email'] }
  // if single allowed domain, add hd hint
  if (ALLOWED_DOMAINS.length === 1) opts.hd = ALLOWED_DOMAINS[0]
  passport.authenticate('google', opts)(req, res, next)
})

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/auth/failure', session: true }), (req, res) => {
  res.redirect(FRONT_URL)
})

app.get('/auth/failure', (req, res) => {
  res.status(401).json({ ok: false, message: 'Authentication failed' })
})

app.get('/api/user', (req, res) => {
  if (!req.user) return res.status(401).json({ ok: false })
  res.json({ ok: true, user: req.user })
})

app.post('/auth/logout', (req, res, next) => {
  // If there's no session (e.g. already logged out or no cookie), avoid calling
  // passport/session methods that expect `req.session` to exist.
  if (!req.session) return res.json({ ok: true })

  req.logout(function(err) {
    if (err) return next(err)
    req.session.destroy(() => {
      res.clearCookie('connect.sid')
      res.json({ ok: true })
    })
  })
})

app.listen(PORT, () => {
  console.log(`Auth server listening on http://localhost:${PORT}`)
})
