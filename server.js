// all module imports
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const mailer = require('./util');
const crypto = require('crypto');
const User = require('./userModel');
const app = express();
const jwt = require('jsonwebtoken');
const sendEmail = require('./util');

//json body parser in post requests
app.use(express.json());

// config file setting
dotenv.config({ path: './config.env' });

// db connection
mongoose.connect(process.env.DATABASE_STRING, () => {
    console.log('Database Connection Successful.');
});

// registration endpoint
app.post('/register', async (req, res) => {
    try {
        const newUser = await User.create({
            email: req.body.email,
            username: req.body.username,
            password: req.body.password
        });

        if (newUser) {
            const token = jwt.sign({ id: newUser.id }, process.env.JWT_SECRET_KEY, { expiresIn: '24h' });
            res.status(200).json({
                status: 'success',
                data: {
                    token: token,
                    user: newUser
                }
            });
        } else {
            res.status(400).json({
                status: 'error',
                message: 'Some error occured'
            });
        }
    } catch (err) {
        console.log(err);
    }
});

// login endpoint
app.post('/login', async (req, res) => {
    try {
        // get username and password from request body
        const { username, password } = req.body;
        if (!username || !password) {
            res.status(404).json({
                status: 'error',
                data: 'Username or Password can\'t be empty.'
            });
        }

        // check if user exists
        const user = await User.findOne({ username });
        if (!user) {
            res.status(404).json({
                status: 'error',
                data: 'Username or Password incorrect.'
            });
        }

        // check the password
        const passwordCheck = await user.checkPassword(password, user.password);
        if (!passwordCheck) {
            res.status(404).json({
                status: 'error',
                data: 'Email or Password incorrect.'
            });
        }
        // create jwt token and send to client
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET_KEY, { expiresIn: '24h' });
        res.status(200).json({
            status: 'success',
            data: {
                token
            }
        });
    } catch (err) {
        console.log(err);
    }
});

// forget password endpoint
app.post('/forgetPassword', async (req, res) => {
    try {
        // find the user using email
        let user = await User.findOne({ email: req.body.email });
        if (!user) {
            res.status(404).json({
                status: 'error',
                data: 'User not exists.'
            });
        }

        // calling instance method to create reset token and send it to the client
        const token = await user.createResetToken();
        await user.save();
        const url = `${req.protocol}://${req.get('host')}/resetPassword/${token}`;
        const message = `Click the link to reset password: ${url}`;
        try {
            const mailOptions = {
                email: req.body.email,
                subject: 'Password Reset Mail',
                message
            };
            await sendEmail(mailOptions);
            res.status(200).json({
                status: 'success',
                message: 'mail sent.'
            })
        } catch (err) {
            user.passwordResetToken = undefined;
            await user.save();
            res.status(500).json({
                status: 'success',
                message: 'error sending mail.'
            })
        }
    } catch (err) {
        console.log(err);
    }
});

// resetpassword endpoint
app.post('/resetPassword/:token', async (req, res) => {
    try {
        // getting the token and encrypting it
        const hashToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
        // finding the user using token
        let user = await User.findOne({ passwordResetToken: hashToken });
        if (!user) {
            res.status(500).json({
                status: 'success',
                message: 'error user not exist.'
            });
        }
        // setting new Password
        user.password = req.body.password;
        user.passwordResetToken = undefined;
        await user.save();
        // sending new jwt to user
        const newToken = jwt.sign(user.id, process.env.JWT_SECRET_KEY);
        res.status(200).json({
            status: 'success',
            newToken
        });
    } catch (err) {
        console.log(err);
    }
});

// server start
app.listen(8000, () => {
    console.log('Server Online at port 8000.');
});