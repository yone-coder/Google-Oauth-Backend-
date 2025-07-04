const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const axios = require('axios'); // ADD THIS
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

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
    const user = {
      googleId: profile.id,
      email: profile.emails[0].value,
      name: profile.displayName,
      picture: profile.photos[0].value,
      accessToken: accessToken
    };

    console.log('User authenticated:', user.email);
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// Serialize user for session
passport.serializeUser((user, done) => {
  done(null, user);
});

// Deserialize user from session
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Auth middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Not authenticated' });
};

// Routes
app.get('/', (req, res) => {
  res.json({ 
    message: 'Google OAuth API Server',
    status: 'running',
    authenticated: req.isAuthenticated()
  });
});

// Google OAuth routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// UPDATED CALLBACK ROUTE - This is the key change
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/failure' }),
  async (req, res) => {
    try {
      const user = req.user;
      
      console.log('Processing OAuth callback for:', user.email);
      
      // Call your main backend to handle user registration/login
      const mainBackendUrl = process.env.MAIN_BACKEND_URL || 'https://supabase-y8ak.onrender.com';
      
      const response = await axios.post(`${mainBackendUrl}/api/auth/google-callback`, {
        googleId: user.googleId,
        email: user.email,
        name: user.name,
        picture: user.picture,
        accessToken: user.accessToken
      }, {
        timeout: 10000, // 10 second timeout
        headers: {
          'Content-Type': 'application/json'
        }
      });

      if (response.data.success) {
        // Redirect to frontend with JWT token and user data
        const clientURL = process.env.CLIENT_URL || 'http://localhost:3000';
        const token = response.data.token;
        const userData = encodeURIComponent(JSON.stringify(response.data.user));
        const isNewUser = response.data.isNewUser ? 'true' : 'false';
        
        console.log('OAuth success, redirecting to:', `${clientURL}/auth/success`);
        res.redirect(`${clientURL}/auth/success?token=${token}&user=${userData}&new=${isNewUser}`);
      } else {
        console.error('Main backend returned error:', response.data.message);
        res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/auth/error?message=${encodeURIComponent(response.data.message)}`);
      }
    } catch (error) {
      console.error('OAuth callback error:', error.message);
      console.error('Error details:', error.response?.data || error);
      
      const errorMessage = error.response?.data?.message || 'Authentication failed';
      res.redirect(`${process.env.CLIENT_URL || 'http://localhost:3000'}/auth/error?message=${encodeURIComponent(errorMessage)}`);
    }
  }
);

// Auth status route
app.get('/auth/status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      authenticated: true,
      user: req.user
    });
  } else {
    res.json({
      authenticated: false
    });
  }
});

// Protected route example
app.get('/api/profile', isAuthenticated, (req, res) => {
  res.json({
    message: 'Protected route accessed successfully',
    user: req.user
  });
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
  console.log(`Main Backend URL: ${process.env.MAIN_BACKEND_URL || 'https://supabase-y8ak.onrender.com'}`);
});