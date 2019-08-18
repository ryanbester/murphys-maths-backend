/*
Copyright (C) 2019 Ryan Bester
*/

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const argon2 = require('argon2');
require('datejs');

const { Auth, AccessToken, User, Nonce } = require('../core/auth');
const app = require('../app');
const dashboard = require('../routes/dashboard');

const showLoginPage = (req, res, next) => {
    const renderLoginPage = () => {
        res.render('login', {title: "Login", message: "Login to the Murphy's Maths Control Panel"});
    }

    if(req.signedCookies['AUTHTOKEN'] !== undefined){
        const accessToken = new AccessToken(null, null, req.signedCookies['AUTHTOKEN']);
        accessToken.checkToken().then(result => {
            if(result == true){
                const user = new User(accessToken.user_id);
                user.verifyUser().then(result => {
                    if (result == true) {
                        res.redirect(301, '/dashboard');
                    } else {
                        renderLoginPage();
                    }
                }, err => {
                    renderLoginPage();
                });
            } else {
                renderLoginPage();
            }
        }, err => {
            renderLoginPage();
        });
    } else {
        renderLoginPage();
    }
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
                        res.cookie('AUTHTOKEN', accessToken.id, {maxAge: maxAge, expires: expires, httpOnly: true, secure: true, signed: true});
                    } else {
                        // ...otherwise the cookie will expire when the browsing session ends
                        res.cookie('AUTHTOKEN', accessToken.id, {httpOnly: true, secure: true, signed: true});
                    }

                    // Redirect the user to the dashboard
                    if(req.query.continue === undefined) {
                        res.redirect(301, '/dashboard');
                    } else {
                        res.redirect(301, decodeURIComponent(req.query.continue));
                    }
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

const performLogout = (req, res, next) => {
    Nonce.verifyNonce('user-logout', req.query.nonce, req.path).then(result => {
        if(result == true){
            if(req.signedCookies['AUTHTOKEN'] === undefined){
                res.redirect(301, '/');
            } else {
                const accessToken = new AccessToken(null, null, req.signedCookies['AUTHTOKEN']);
                accessToken.deleteToken().then(result => {
                    res.cookie('AUTHTOKEN',{httpOnly: true, secure: true, signed: true, expires: Date.now()});
                    res.redirect(301, '/');
                }, err => {
                    res.cookie('AUTHTOKEN',{httpOnly: true, secure: true, signed: true, expires: Date.now()});
                    res.redirect(301, '/');
                })
            }
        } else {
            res.render('error-custom', {title: "Error", error: {
                title: "Cannot log you out",
                message: "The nonce verification has failed"
            }});
        }
    }, err => {
        res.render('error-custom', {title: "Error", error: {
            title: "Cannot log you out",
            message: "The nonce verification has failed"
        }});
    });
}


router.get('/', showLoginPage);

router.post('/', performLogin);

router.get('/dashboard*', dashboard.initDashboard);
router.post('/dashboard*', dashboard.initDashboard);

router.get('/dashboard', dashboard.showDashboard);
router.get('/dashboard/traffic', dashboard.showTraffic);
router.get('/dashboard/videos', dashboard.showVideos);
router.get('/dashboard/video-requests', dashboard.showVideoRequests);

router.get('/dashboard/profile', dashboard.showProfile);
router.post('/dashboard/profile', dashboard.performSaveProfile);

router.get('/dashboard/profile/change-password', dashboard.showProfileChangePassword);
router.post('/dashboard/profile/change-password', dashboard.performProfileChangePassword);

router.get('/dashboard/help', dashboard.showHelp);
router.get('/dashboard/settings', dashboard.showSettings);

router.get('/logout', performLogout);

module.exports = router;