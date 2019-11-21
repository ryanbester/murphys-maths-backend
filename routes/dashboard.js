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

exports.initDashboard = (req, res, next) => {
    // Disable cache
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    if(req.signedCookies['AUTHTOKEN'] === undefined){
        res.redirect(301, '/?continue=' + encodeURIComponent(req.url));
    } else {
        const accessToken = new AccessToken(null, null, req.signedCookies['AUTHTOKEN']);
        accessToken.checkToken().then(result => {
            if(result == true){
                const user = new User(accessToken.user_id);
                user.verifyUser().then(result => {
                    if (result == true) {
                        user.loadInfo().then(result => {
                            res.locals.user = user;
                            next();
                        }, err => {
                            next();
                        });
                    } else {
                        res.redirect(301, '/?continue=' + encodeURIComponent(req.url));
                    }
                }, err => {
                    res.redirect(301, '/?continue=' + encodeURIComponent(req.url));
                });
            } else {
                res.redirect(301, '/?continue=' + encodeURIComponent(req.url));
            }
        }, err => {
            res.redirect(301, '/?continue=' + encodeURIComponent(req.url));
        });
    }
}

exports.showDashboard = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'home';

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout/');

    Promise.all([logoutNoncePromise]).then(results => {
        res.render(activeItem, {
            title: "Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            logoutNonce: results[0]
        });
    });
}