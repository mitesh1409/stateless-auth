import bcrypt from 'bcrypt';

import User from "../models/user.model.js";
import * as AuthTokens from "../services/authTokens.js";
import mongoose from 'mongoose';

function signUp(req, res) {
    if (req.authUser) {
        return res.redirect('/users/dashboard');
    }

    res.render('users/sign-up', {
        metaTitle: 'Stateless Authentication Example | Sign Up'
    });
}

async function doSignUp(req, res) {
    if (req.authUser) {
        return res.redirect('/users/dashboard');
    }

    const {
        firstName,
        lastName,
        gender,
        dob,
        email,
        password
    } = req.body;

    if (!firstName || !lastName || !gender || !dob || !email || !password) {
        return res
            .status(400)
            .render('users/sign-up', {
                metaTitle: 'Stateless Authentication Example | Sign Up',
                status: 'failure',
                error: 'All fields are required.'
            });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await User.create({
            firstName,
            lastName,
            gender,
            dob,
            email,
            password: hashedPassword,
        });
    } catch (error) {
        console.error('Error during user sign-up:', error);

        return res
            .status(500)
            .render('users/sign-up', {
                metaTitle: 'Stateless Authentication Example | Sign Up',
                status: 'failure',
                error: 'Something went wrong. Please try again.'
            });
    }

    return res
        .status(201)
        .render('users/sign-up', {
            metaTitle: 'Stateless Authentication Example | Sign Up',
            status: 'success',
            message: 'User sign-up successful.'
        });
}

function signIn(req, res) {
    if (req.authUser) {
        return res.redirect('/users/dashboard');
    }

    res.render('users/sign-in', {
        metaTitle: 'Stateless Authentication Example | Sign In'
    });
}

async function doSignIn(req, res) {
    if (req.authUser) {
        return res.redirect('/users/dashboard');
    }

    const { email, password } = req.body;

    if (!email || !password) {
        return res
            .status(400)
            .render('users/sign-in', {
                metaTitle: 'Stateless Authentication Example | Sign In',
                error: 'Email and Password are required'
            });
    }

    const user = await User.findOne({ email: email }).exec();

    if (!user) {
        return res
            .status(401)
            .render('users/sign-in', {
                metaTitle: 'Stateless Authentication Example | Sign In',
                error: 'Failed to login. Email or Password incorrect.'
            });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
        return res
            .status(401)
            .render('users/sign-in', {
                metaTitle: 'Stateless Authentication Example | Sign In',
                error: 'Failed to login. Email or Password incorrect.'
            });
    }

    // Here we are saving user data/state into a JWT token.
    // And this token is then sent to client using a cookie.
    // Client is managing this state not the server.
    // That is why this is Stateless Authentication.
    const authToken = AuthTokens.set({
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        gender: user.gender,
        dob: user.dob,
        email: user.email,
    });

    // Set cookie with authToken generated above.
    // In the subsequent requests client will send this authToken back to the server via cookie.
    // This is process implicit from client's end.
    res.cookie('authToken', authToken, { httpOnly: true });

    return res.redirect('/users/dashboard');
}

function dashboard(req, res) {
    if (!req.authUser) {
        return res.redirect('/users/sign-in');
    }

    const authUser = req.authUser;
    res.render('users/dashboard', {
        metaTitle: 'Stateless Authentication Example | Dashboard',
        userFullName: `${authUser.firstName} ${authUser.lastName}`
    });
}

function signOut(req, res) {
    if (!req.authUser) {
        return res.redirect('/users/sign-in');
    }

    // Remove the cookie as well.
    res.clearCookie('authToken');

    // Redirect to sign in page.
    return res.redirect('/users/sign-in');
}

async function getAuthToken(req, res) {
    const userId = req.params.userId;
    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).send('Invalid User ID');
    }

    const user = await User.findById(userId).exec();
    if (!user) {
        return res.status(404).send('User not found');
    }

    const authToken = AuthTokens.set({
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        gender: user.gender,
        dob: user.dob,
        email: user.email,
    });

    return res.status(200).send(authToken);
}

export {
    signUp,
    doSignUp,
    signIn,
    doSignIn,
    dashboard,
    signOut,
    getAuthToken
};
