// server.js
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory user storage (replace with actual database)
const users = new Map();

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));

app.use(express.json());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const googleId = profile.id;
    const email = profile.emails[0].value;
    
    // Check if user already exists
    let user = users.get(googleId);
    
    if (user) {
      // Existing user - update their info
      user.lastLogin = new Date();
      user.accessToken = accessToken;
      console.log('Existing user logged in:', user.email);
      return done(null, { ...user, isNewUser: false });
    } else {
      // New user - create basic profile
      const newUser = {
        googleId: googleId,
        email: email,
        name: profile.displayName,
        picture: profile.photos[0].value,
        accessToken: accessToken,
        createdAt: new Date(),
        lastLogin: new Date(),
        isRegistrationComplete: false, // Key flag for new users
        // Additional fields that might need completion
        phone: null,
        dateOfBirth: null,
        address: null,
        preferences: {}
      };
      
      users.set(googleId, newUser);
      console.log('New user created:', newUser.email);
      return done(null, { ...newUser, isNewUser: true });
    }
  } catch (error) {
    console.error('OAuth error:', error);
    return done(error, null);
  }
}));

// Serialize user for session
passport.serializeUser((user, done) => {
  done(null, user.googleId);
});

// Deserialize user from session
passport.deserializeUser((googleId, done) => {
  const user = users.get(googleId);
  if (user) {
    done(null, user);
  } else {
    done(new Error('User not found'), null);
  }
});

// Auth middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Not authenticated' });
};

// Middleware to check if registration is complete
const requireCompleteRegistration = (req, res, next) => {
  if (req.isAuthenticated() && req.user.isRegistrationComplete) {
    return next();
  }
  res.status(403).json({ 
    error: 'Registration not complete',
    message: 'Please complete your registration first',
    redirectTo: '/complete-registration'
  });
};

// Routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'Google OAuth API Server',
    status: 'running',
    authenticated: req.isAuthenticated(),
    user: req.isAuthenticated() ? {
      email: req.user.email,
      name: req.user.name,
      registrationComplete: req.user.isRegistrationComplete
    } : null
  });
});

// Google OAuth routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/failure' }),
  (req, res) => {
    const clientURL = process.env.CLIENT_URL || 'http://localhost:3000';
    
    // Check if user is new or existing
    if (req.user.isNewUser || !req.user.isRegistrationComplete) {
      // New user or incomplete registration - redirect to registration page
      res.redirect(`${clientURL}/complete-registration?new=true`);
    } else {
      // Existing user with complete registration - redirect to dashboard
      res.redirect(`${clientURL}/dashboard?login=success`);
    }
  }
);

// Auth status route
app.get('/auth/status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      authenticated: true,
      user: {
        googleId: req.user.googleId,
        email: req.user.email,
        name: req.user.name,
        picture: req.user.picture,
        isRegistrationComplete: req.user.isRegistrationComplete,
        createdAt: req.user.createdAt,
        lastLogin: req.user.lastLogin
      }
    });
  } else {
    res.json({
      authenticated: false
    });
  }
});

// Complete registration route
app.post('/auth/complete-registration', isAuthenticated, (req, res) => {
  try {
    const { phone, dateOfBirth, address, preferences } = req.body;
    
    // Validate required fields
    if (!phone) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['phone']
      });
    }
    
    // Update user information
    const user = users.get(req.user.googleId);
    if (user) {
      user.phone = phone;
      user.dateOfBirth = dateOfBirth;
      user.address = address;
      user.preferences = preferences || {};
      user.isRegistrationComplete = true;
      user.registrationCompletedAt = new Date();
      
      users.set(req.user.googleId, user);
      
      // Update session user
      req.user = user;
      
      res.json({
        message: 'Registration completed successfully',
        user: {
          email: user.email,
          name: user.name,
          phone: user.phone,
          isRegistrationComplete: true
        }
      });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    console.error('Registration completion error:', error);
    res.status(500).json({ error: 'Registration completion failed' });
  }
});

// Get registration status
app.get('/auth/registration-status', isAuthenticated, (req, res) => {
  res.json({
    isRegistrationComplete: req.user.isRegistrationComplete,
    user: {
      email: req.user.email,
      name: req.user.name,
      picture: req.user.picture,
      hasPhone: !!req.user.phone,
      hasDateOfBirth: !!req.user.dateOfBirth,
      hasAddress: !!req.user.address
    }
  });
});

// Protected route that requires complete registration
app.get('/api/profile', isAuthenticated, requireCompleteRegistration, (req, res) => {
  res.json({
    message: 'Protected route accessed successfully',
    user: {
      googleId: req.user.googleId,
      email: req.user.email,
      name: req.user.name,
      picture: req.user.picture,
      phone: req.user.phone,
      dateOfBirth: req.user.dateOfBirth,
      address: req.user.address,
      preferences: req.user.preferences,
      createdAt: req.user.createdAt,
      lastLogin: req.user.lastLogin
    }
  });
});

// Basic profile route (works without complete registration)
app.get('/api/basic-profile', isAuthenticated, (req, res) => {
  res.json({
    message: 'Basic profile accessed',
    user: {
      email: req.user.email,
      name: req.user.name,
      picture: req.user.picture,
      isRegistrationComplete: req.user.isRegistrationComplete
    }
  });
});

// Get all users (for testing - remove in production)
app.get('/api/users', (req, res) => {
  const userList = Array.from(users.values()).map(user => ({
    email: user.email,
    name: user.name,
    isRegistrationComplete: user.isRegistrationComplete,
    createdAt: user.createdAt
  }));
  res.json({ users: userList, count: userList.length });
});

// Logout route
app.post('/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Session destruction failed' });
      }
      res.json({ message: 'Logged out successfully' });
    });
  });
});

// Failure route
app.get('/auth/failure', (req, res) => {
  res.status(401).json({ 
    error: 'Authentication failed',
    message: 'Google OAuth authentication was unsuccessful'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('OAuth flow:');
  console.log('- New users: /auth/google → /complete-registration');
  console.log('- Existing users: /auth/google → /dashboard');
});