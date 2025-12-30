import express from 'express'
import session from 'express-session'
import passport from 'passport'
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import dotenv from 'dotenv'
import cors from 'cors'
import fs from 'fs'
import { promisify } from 'util'
import ExcelJS from 'exceljs'

const writeFile = promisify(fs.writeFile)
const readFile = promisify(fs.readFile)

dotenv.config()

const PORT = process.env.PORT || 4000
const FRONT_URL = process.env.FRONT_URL || 'http://localhost:5173'
const ALLOWED_DOMAINS = (process.env.ALLOWED_DOMAINS || '').split(',').map(s => s.trim()).filter(Boolean)
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim()).filter(Boolean)
const isProduction = process.env.NODE_ENV === 'production'

console.log('=== Server Config ===')
console.log('PORT:', PORT)
console.log('FRONT_URL:', FRONT_URL)
console.log('ALLOWED_DOMAINS:', ALLOWED_DOMAINS)
console.log('ADMIN_EMAILS:', ADMIN_EMAILS)
console.log('====================')

const app = express()

const DATA_FILE = process.env.DATA_FILE || 'applications.json'
let applications = []
// load existing data if present
try {
  const raw = fs.existsSync(DATA_FILE) ? fs.readFileSync(DATA_FILE, 'utf8') : ''
  applications = raw ? JSON.parse(raw) : []
} catch (err) {
  console.error('Failed to load applications file:', err)
  applications = []
}

app.use(cors({
  origin: FRONT_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  maxAge: 86400
}))
console.log('[CORS] origin:', FRONT_URL)
app.use(express.json())

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: isProduction,
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
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
  if (!req.user) {
    console.log('[/api/user] No session found')
    return res.status(401).json({ ok: false })
  }
  const isAdmin = ADMIN_EMAILS.includes(req.user.email)
  console.log(`[/api/user] User: ${req.user.email}, isAdmin: ${isAdmin}`)
  res.json({ ok: true, user: { ...req.user, isAdmin } })
})

function ensureAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ ok: false, message: 'Unauthorized' })
  next()
}

function ensureAdmin(req, res, next) {
  // 로그인 확인
  if (!req.user) {
    console.log('[Admin Check] No user in session')
    return res.status(401).json({ ok: false, message: 'Not authenticated' })
  }
  // 관리자 권한 확인
  if (!ADMIN_EMAILS.includes(req.user.email)) {
    console.log(`[Admin Check] User ${req.user.email} not in ADMIN_EMAILS:`, ADMIN_EMAILS)
    return res.status(403).json({ ok: false, message: 'Admin only' })
  }
  console.log(`[Admin Check] OK for ${req.user.email}`)
  next()
}

// Create an application (requires login)
app.post('/api/applications', express.json(), ensureAuth, async (req, res) => {
  try {
    const { lab, date, time, students, teacher, purpose, researchPlan } = req.body || {}
    
    // Validation
    if (!lab || !date) {
      return res.status(400).json({ ok: false, message: 'Missing required fields' })
    }
    
    const selectedTimes = time && (time.ET || time.EP1)
    if (!selectedTimes) {
      return res.status(400).json({ ok: false, message: 'Please select at least one time' })
    }

    const entry = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      userEmail: req.user.email,
      userName: req.user.displayName || '',
      lab,
      date,
      time: time || {},
      students: students || [],
      teacher: teacher || '',
      purpose: purpose || {},
      researchPlan: researchPlan || '',
      createdAt: new Date().toISOString()
    }

    applications.push(entry)
    await writeFile(DATA_FILE, JSON.stringify(applications, null, 2), 'utf8')
    res.status(201).json({ ok: true, application: entry })
  } catch (err) {
    console.error('Failed to save application', err)
    res.status(500).json({ ok: false, message: 'Failed to save' })
  }
})

// List applications for current user
app.get('/api/applications', ensureAuth, (req, res) => {
  const userApps = applications.filter(a => a.userEmail === req.user.email)
  res.json({ ok: true, applications: userApps })
})

// Admin: Get all applications
app.get('/api/admin/applications', ensureAdmin, (req, res) => {
  res.json({ ok: true, applications })
})

// Admin: Update application status (approve/reject/delete)
app.patch('/api/admin/applications/:id', express.json(), ensureAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const { status } = req.body
    const validStatuses = ['pending', 'approved', 'rejected']
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ ok: false, message: 'Invalid status' })
    }
    const idx = applications.findIndex(a => a.id === id)
    if (idx < 0) return res.status(404).json({ ok: false, message: 'Not found' })
    applications[idx].status = status
    applications[idx].updatedAt = new Date().toISOString()
    await writeFile(DATA_FILE, JSON.stringify(applications, null, 2), 'utf8')
    res.json({ ok: true, application: applications[idx] })
  } catch (err) {
    console.error('Failed to update application', err)
    res.status(500).json({ ok: false, message: 'Failed to update' })
  }
})

// Admin: Delete application
app.delete('/api/admin/applications/:id', ensureAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const idx = applications.findIndex(a => a.id === id)
    if (idx < 0) return res.status(404).json({ ok: false, message: 'Not found' })
    const removed = applications.splice(idx, 1)[0]
    await writeFile(DATA_FILE, JSON.stringify(applications, null, 2), 'utf8')
    res.json({ ok: true, application: removed })
  } catch (err) {
    console.error('Failed to delete application', err)
    res.status(500).json({ ok: false, message: 'Failed to delete' })
  }
})

// Admin: Export all applications as Excel
app.get('/api/admin/applications/export', ensureAdmin, async (req, res) => {
  try {
    const workbook = new ExcelJS.Workbook()
    const sheet = workbook.addWorksheet('Applications')

    sheet.columns = [
      { header: 'ID', key: 'id', width: 20 },
      { header: 'User Email', key: 'userEmail', width: 30 },
      { header: 'User Name', key: 'userName', width: 25 },
      { header: 'Lab', key: 'lab', width: 20 },
      { header: 'Date', key: 'date', width: 15 },
      { header: 'Time', key: 'time', width: 15 },
      { header: 'Students', key: 'students', width: 40 },
      { header: 'Teacher', key: 'teacher', width: 20 },
      { header: 'Purpose', key: 'purpose', width: 40 },
      { header: 'Research Plan', key: 'researchPlan', width: 50 },
      { header: 'Status', key: 'status', width: 12 },
      { header: 'Created At', key: 'createdAt', width: 25 },
      { header: 'Updated At', key: 'updatedAt', width: 25 }
    ]

    applications.forEach(a => {
      // Format time
      const timeStr = a.time && (a.time.ET || a.time.EP1)
        ? [a.time.ET ? 'ET' : '', a.time.EP1 ? 'EP1' : ''].filter(Boolean).join(', ')
        : '-'
      
      // Format students
      const studentStr = a.students && a.students.length
        ? a.students
            .filter(s => s.name)
            .map(s => `${s.grade}학년 ${s.class}반 ${s.name}`)
            .join('; ')
        : '-'
      
      // Format purpose
      const purposeArr = []
      if (a.purpose) {
        if (a.purpose.research) purposeArr.push('과제 연구')
        if (a.purpose.classActivity) purposeArr.push('학급 활동')
        if (a.purpose.club) purposeArr.push(`동아리 활동(${a.purpose.clubName || ''})`)
        if (a.purpose.other) purposeArr.push(`기타(${a.purpose.otherText || ''})`)
      }
      const purposeStr = purposeArr.length ? purposeArr.join('; ') : '-'

      sheet.addRow({
        id: a.id,
        userEmail: a.userEmail,
        userName: a.userName,
        lab: a.lab,
        date: a.date,
        time: timeStr,
        students: studentStr,
        teacher: a.teacher || '-',
        purpose: purposeStr,
        researchPlan: a.researchPlan || '-',
        status: a.status || 'pending',
        createdAt: a.createdAt,
        updatedAt: a.updatedAt || ''
      })
    })

    const buffer = await workbook.xlsx.writeBuffer()
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    res.setHeader('Content-Disposition', 'attachment; filename="applications.xlsx"')
    res.send(Buffer.from(buffer))
  } catch (err) {
    console.error('Failed to export applications', err)
    res.status(500).json({ ok: false, message: 'Export failed' })
  }
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
