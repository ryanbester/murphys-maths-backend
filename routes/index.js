/*
Copyright (C) 2019 Ryan Bester
*/

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const argon2 = require('argon2');
require('datejs');

const { Auth, AccessToken, User } = require('../core/auth');

const showLoginPage = (req, res, next) => {
    res.render('login', {title: "Login", message: "Login to the Murphy's Maths Control Panel"});
}

const performLogin = (req, res, next) => {
    // Get the values from the login form
    const username = req.body.username;
    const password = req.body.password;
    const rememberMe = req.body.remember_me;

    // Read the password from the database for the specified username
    Auth.readPasswordFromDatabase(username).then(result => {
        // Verify the password
        Auth.verifyPassword(password, {
            all: result
        }).then(result => {
            if(result == false){
                // If the credentials are incorrect, return an error
                res.render('login', {error: "Your username or password is incorrect", title: "Login", message: "Login to the Murphy's Maths Control Panel"});
            } else {
                // If authentication is successful, generate an access token
                const accessToken = new AccessToken(result.user_id);

                // Save the generated access token to the database
                accessToken.saveTokenToDatabase().then(result => {
                    if(rememberMe == 'true'){
                        // If the remember me option was checked, make the cookie last longer...
                        var maxAge = accessToken.lifetime * 60 * 1000;
                        var expires = accessToken.expiry;
                        res.cookie('AUTHTOKEN', accessToken.id, {maxAge: maxAge, expires: expires, httpOnly: true, secure: true});
                    } else {
                        // ...otherwise the cookie will expire when the browsing session ends
                        res.cookie('AUTHTOKEN', accessToken.id, {httpOnly: true, secure: true});
                    }
                    // Redirect the user to the dashboard
                    res.redirect(301, '/dashboard');
                }, err => console.log(err));
            }
        }, err => {
            // If the credentials are incorrect, return an error
            res.render('login', {error: "Your username or password is incorrect", title: "Login", message: "Login to the Murphy's Maths Control Panel", username: username});
        });
    }, err => {
        // If the credentials are incorrect, return an error
        res.render('login', {error: "Your username or password is incorrect", title: "Login", message: "Login to the Murphy's Maths Control Panel", username: username});
    });
}

router.get('/', showLoginPage);

router.post('/', performLogin);

module.exports = router;