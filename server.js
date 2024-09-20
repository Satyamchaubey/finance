require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const ObjectId = mongoose.Types.ObjectId;
const passport = require('passport');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const User = require('./models/User');
const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

// MongoDB URI from environment variable
const uri = process.env.MONGODB_URI;

if (!uri) {
  console.error('MongoDB connection URI is missing. Please check your .env file.');
  process.exit(1);
}

mongoose.connect(uri, {
  serverSelectionTimeoutMS: 5000,
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB Atlas successfully'))
  .catch((err) => {
    console.error('Error connecting to MongoDB Atlas', err.message);
    process.exit(1);
  });

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Express session setup
app.use(session({
  secret: 'yourSecretKey',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: uri
  }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

// Passport configuration for Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'https://saaft.vercel.app/auth/google/callback',
  scope: ['profile', 'email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = new User({
        username: profile.displayName,
        email: profile.emails[0].value,
        googleId: profile.id,
        transactions: []
      });
      await user.save();
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Authentication Middleware
const isAuthenticated = (req, res, next) => {
  if (req.session && req.session.userId) {
    return next();
  } else {
    return res.redirect('/login');
  }
};

// Routes

// Home redirect to login
app.get('/', (req, res) => {
  res.redirect('/login');
});

// Sign Up Page
app.get('/signup', (req, res) => {
  res.render('signup');
});

// Sign Up Route
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    username,
    email,
    password: hashedPassword,
    transactions: []
  });

  try {
    await newUser.save();
    res.redirect('/login');
  } catch (err) {
    console.error('Error creating user:', err);
    res.send('Error creating user');
  }
});

// Login Page
app.get('/login', (req, res) => {
  res.render('login');
});

// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.send('User not found');
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.send('Incorrect password');
  }

  req.session.userId = user._id;
  res.redirect('/dashboard');
});

// Google OAuth Login
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    req.session.userId = req.user._id;
    res.redirect('/dashboard');
  }
);

// Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Dashboard Route
app.get('/dashboard', isAuthenticated, async (req, res) => {
  const user = await User.findById(req.session.userId);

  let totalIncome = 0;
  let totalExpenses = 0;

  user.transactions.forEach(transaction => {
    if (transaction.type === 'Income') {
      totalIncome += transaction.amount;
    } else if (transaction.type === 'Expense') {
      totalExpenses += transaction.amount;
    }
  });

  const netBalance = totalIncome - totalExpenses;

  res.render('dashboard', {
    user: user,
    totalIncome: totalIncome,
    totalExpenses: totalExpenses,
    netBalance: netBalance
  });
});

// Add Transaction Route
app.post('/add-transaction', isAuthenticated, async (req, res) => {
  const { description, type, date, amount } = req.body;

  const transaction = {
    description,
    type,
    date,
    amount: parseFloat(amount)
  };

  try {
    await User.findByIdAndUpdate(req.session.userId, {
      $push: { transactions: transaction }
    });
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Error adding transaction:', err);
    res.send('Error adding transaction');
  }
});

// Route to render the edit page
app.get('/edit-transaction/:id', isAuthenticated, async (req, res) => {
    const transactionId = req.params.id;
    try {
        const user = await User.findOne({ 'transactions._id': transactionId });
        if (!user) {
            return res.status(404).send('Transaction not found');
        }
        const transaction = user.transactions.id(transactionId);
        res.render('edit-transaction', { transaction });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// Route to handle the edit form submission
app.post('/edit-transaction/:id', isAuthenticated, async (req, res) => {
    const transactionId = req.params.id;
    const { description, type, date, amount } = req.body;
    try {
        const user = await User.findOne({ 'transactions._id': transactionId });
        if (!user) {
            return res.status(404).send('Transaction not found');
        }
        const transaction = user.transactions.id(transactionId);
        transaction.description = description;
        transaction.type = type;
        transaction.date = date;
        transaction.amount = parseFloat(amount);
        await user.save();
        res.redirect('/dashboard'); // Redirect to dashboard after successful edit
    } catch (err) {
        res.status(500).send('Server error');
    }
});


app.post('/delete-transaction/:id', isAuthenticated, async (req, res) => {
    try {
        const transactionId = req.params.id;
        // Ensure req.user is defined
        if (!req.user || !req.user._id) {
            return res.status(401).send('User not authenticated');
        }

        await User.updateOne(
            { _id: req.user._id },
            { $pull: { transactions: { _id: transactionId } } } // Assuming transactionId is already an ObjectId
        );
        res.redirect('/dashboard'); // Redirect after deletion
    } catch (error) {
        console.error('Error deleting transaction:', error);
        res.status(500).send('Error deleting transaction');
    }
});


// Search Transactions Route
app.post('/search-transactions', isAuthenticated, async (req, res) => {
  const { month, year } = req.body;
  const user = await User.findById(req.session.userId);
  const transactions = user.transactions.filter(t => {
    const date = new Date(t.date);
    return date.getMonth() + 1 === parseInt(month) && date.getFullYear() === parseInt(year);
  });
  res.render('dashboard', { user: { ...user._doc, transactions } });
});

// Download PDF Report Route
app.get('/download-pdf', isAuthenticated, async (req, res) => {
  const user = await User.findById(req.session.userId);

  const doc = new PDFDocument();
  res.setHeader('Content-disposition', 'attachment; filename=report.pdf');
  res.setHeader('Content-type', 'application/pdf');

  doc.pipe(res);

  doc.fontSize(18).text('Finance Tracker Report', { align: 'center' });
  doc.moveDown();

  if (user.transactions.length > 0) {
    doc.fontSize(12).text('Transactions:', { underline: true });
    user.transactions.forEach(transaction => {
      doc.text(`${transaction.description} - ${transaction.type} - ${new Date(transaction.date).toLocaleDateString()} - $${transaction.amount.toFixed(2)}`);
    });
  } else {
    doc.text('No transactions found.');
  }

  doc.end();
});

// Download Excel Report Route
app.get('/download-excel', isAuthenticated, async (req, res) => {
  const user = await User.findById(req.session.userId);

  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('Transactions');

  worksheet.columns = [
    { header: 'Description', key: 'description', width: 30 },
    { header: 'Type', key: 'type', width: 10 },
    { header: 'Date', key: 'date', width: 15 },
    { header: 'Amount', key: 'amount', width: 10 }
  ];

  user.transactions.forEach(transaction => {
    worksheet.addRow({
      description: transaction.description,
      type: transaction.type,
      date: new Date(transaction.date).toLocaleDateString(),
      amount: transaction.amount
    });
  });

  res.setHeader('Content-Disposition', 'attachment; filename=report.xlsx');
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

  await workbook.xlsx.write(res);
  res.end();
});

// Update Profile Route
app.post('/update-profile', isAuthenticated, async (req, res) => {
  const { username, email } = req.body;
  const userId = req.session.userId;

  try {
    await User.findByIdAndUpdate(userId, { username, email }, { new: true });
    res.redirect('/profile');
  } catch (err) {
    console.error('Error updating profile:', err);
    res.status(500).send('Error updating profile');
  }
});

// Server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
