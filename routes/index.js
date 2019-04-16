/*
Copyright (C) 2019 Ryan Bester
*/

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const argon2 = require('argon2');

const Auth = require('../core/auth');

const showLoginPage = (req, res, next) => {
    Auth.encryptPassword("password").then(encrypted => {
        message = encrypted.join("\n");

        Auth.verifyPassword("password", {"all": encrypted}).then(result => {
            message += "Verify password: " + result;
            res.render('index', {title: 'Murphy\'s Maths', message: message});
        }, err => {
            message += "Verify password: false";
            res.render('index', {title: 'Murphy\'s Maths', message: message});        
        });
    }, err => {
        res.render('index', {title: 'Error | Murphy\'s Maths', message: "Encrypt password: " + err.stack});
    });
}

router.get('/', showLoginPage);

module.exports = router;