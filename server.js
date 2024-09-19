const express = require('express');
const mongoose = require('mongoose');
const ObjectId = mongoose.Types.ObjectId;
const passport = require('passport');
const multer = require('multer');
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

// MongoDB Local Connection
const uri = "mongodb://localhost/finance-tracker"; // Replace 'myDatabase' with your actual database name
mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Connected to MongoDB!");
}).catch(err => {
    console.error('Error connecting to MongoDB:', err);
});


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// Set up Multer for file uploads
const upload = multer({ 
    dest: 'uploads/', // Directory to store uploaded files
    limits: { fileSize: 1000000 } // Limit file size (1MB)
});

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

// Passport configuration
passport.use(new GoogleStrategy({
    clientID: '1042265845512-4hv8t6ot16rcvjvekmgialmrecetmnc0.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: '/auth/google/callback',
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

    // Calculate summary
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

// Transaction Route for adding a new transaction
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
        { header: 'Amount', key: 'amount', width: 15 }
    ];

    if (user.transactions.length > 0) {
        user.transactions.forEach(transaction => {
            worksheet.addRow({
                description: transaction.description,
                type: transaction.type,
                date: new Date(transaction.date).toLocaleDateString(),
                amount: transaction.amount.toFixed(2)
            });
        });
    } else {
        worksheet.addRow({ description: 'No transactions found.' });
    }

    res.setHeader('Content-disposition', 'attachment; filename=report.xlsx');
    res.setHeader('Content-type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

    await workbook.xlsx.write(res);
    res.end();
});

// View All Transactions Route
app.get('/main', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId);
    res.render('main', { transactions: user.transactions });
});

// Profile Page Route
app.get('/profile', isAuthenticated, async (req, res) => {
    const user = await User.findById(req.session.userId);
    res.render('profile', { user });
});

// Route to handle profile update
app.post('/update-profile', upload.single('profilePicture'), async (req, res) => {
    const { username, email } = req.body;
    const userId = req.session.userId; // Assumes userId is stored in session

    try {
        const user = await User.findById(userId);

        // Update user profile details
        if (username) user.username = username;
        if (email) user.email = email;

        // Handle profile picture upload
        if (req.file) {
            user.profilePicture = `/uploads/${req.file.filename}`; // Save the path to the uploaded file
        }

        await user.save();

        res.redirect('/profile'); // Redirect to profile page or another page
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// Route to handle password change
app.post('/change-password', async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.session.userId; // Assumes userId is stored in session

    try {
        const user = await User.findById(userId);

        // Check if the old password is correct
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).send('Old password is incorrect');
        }

        // Hash new password and update the user
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        res.redirect('/profile'); // Redirect to profile page or another page
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});
// Route to render the edit form with existing transaction details
app.get('/edit-transaction/:id', isAuthenticated, async (req, res) => {
    const transactionId = req.params.id;

    try {
        // Find the user by ID
        const user = await User.findById(req.session.userId);

        // Find the transaction in the user's transactions array
        const transaction = user.transactions.id(transactionId);

        if (!transaction) {
            return res.status(404).send('Transaction not found');
        }

        // Render the edit form populated with the transaction data
        res.render('edit-transaction', { transaction });
    } catch (err) {
        console.error('Error fetching transaction:', err);
        res.status(500).send('Error fetching transaction');
    }
});
// Route to update the transaction in the database
app.post('/edit-transaction/:id', isAuthenticated, async (req, res) => {
    const transactionId = req.params.id;
    const { description, type, date, amount } = req.body;

    try {
        // Find the user by ID
        const user = await User.findById(req.session.userId);

        // Find the transaction and update it
        const transaction = user.transactions.id(transactionId);
        if (!transaction) {
            return res.status(404).send('Transaction not found');
        }

        // Update the transaction fields
        transaction.description = description;
        transaction.type = type;
        transaction.date = new Date(date);
        transaction.amount = parseFloat(amount);

        await user.save();

        // Redirect back to the dashboard or transactions page
        res.redirect('/dashboard');
    } catch (err) {
        console.error('Error updating transaction:', err);
        res.status(500).send('Error updating transaction');
    }
});

app.post('/delete-transaction/:id', isAuthenticated, async (req, res) => {
    const transactionId = req.params.id; // Get the transaction ID from the URL parameter

    try {
        // Find the user by their session ID
        const user = await User.findById(req.session.userId);

        if (!user) {
            return res.status(404).send('User not found');
        }

        // Filter out the transaction with the given ID
        user.transactions = user.transactions.filter(transaction => transaction._id.toString() !== transactionId);

        // Save the updated user document
        await user.save();

        // Redirect to dashboard or a page showing the updated list
        res.redirect('/dashboard');
    } catch (err) {
        console.error('Error deleting transaction:', err);
        res.status(500).send('Error deleting transaction');
    }
});



// Run the server
const PORT = 8000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
