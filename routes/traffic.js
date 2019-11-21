/*
Copyright (C) 2019 Ryan Bester
*/

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const argon2 = require('argon2');
require('datejs');

const { Auth, AccessToken, User, Nonce } = require('../core/auth');
const AuthUtil = require('../core/auth-util');
const app = require('../app');

exports.showTraffic = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'traffic'

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout/');

    Promise.all([logoutNoncePromise]).then(results => {
        res.render(activeItem, {
            title: "Traffic | Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            logoutNonce: results[0]
        });
    });
}