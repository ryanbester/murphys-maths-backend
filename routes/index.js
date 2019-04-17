/*
Copyright (C) 2019 Ryan Bester
*/

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const argon2 = require('argon2');

const Auth = require('../core/auth');

const showLoginPage = (req, res, next) => {
    res.render('login', {title: "Login", message: "Login to the Murphy's Maths Control Panel"});
}

const performLogin = (req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;

    Auth.readPasswordFromDatabase(username).then(result => {
        Auth.verifyPassword(password, {
            all: result
        }).then(result => {
            res.redirect(301, '/dashboard');
        }, err => {
            res.render('login', {error: "Your username or password is incorrect", title: "Login", message: "Login to the Murphy's Maths Control Panel"});
        });
    }, err => {
        res.render('login', {error: "Your username or password is incorrect", title: "Login", message: "Login to the Murphy's Maths Control Panel"});
    });
}

router.get('/', showLoginPage);

router.post('/', performLogin);

module.exports = router;