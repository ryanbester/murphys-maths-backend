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

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout');

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

exports.showTraffic = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'traffic'

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout');

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

exports.showVideos = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'videos'

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout');

    Promise.all([logoutNoncePromise]).then(results => {
        res.render(activeItem, {
            title: "Videos | Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            logoutNonce: results[0]
        });
    });
}

exports.showVideoRequests = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'video-requests'

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout');

    Promise.all([logoutNoncePromise]).then(results => {
        res.render(activeItem, {
            title: "Video Requests | Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            logoutNonce: results[0]
        });
    });
}

exports.showProfile = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'profile';

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout');
    const logoutEverywhereNoncePromise = Nonce.createNonce('user-logout-everywhere', '/dashboard/profile/logout-everywhere');

    Promise.all([logoutNoncePromise, logoutEverywhereNoncePromise]).then(results => {
        res.render(activeItem, {
            title: "Profile | Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            firstName: user.first_name,
            lastName: user.last_name,
            newUsername: user.username,
            email: user.email_address,
            logoutNonce: results[0],
            logoutEverywhereNonce: results[1]
        });
    });
}

exports.performSaveProfile = (req, res, next) => {
    let user = res.locals.user;

    let firstName = req.body.firstName;
    let lastName = req.body.lastName;
    let newUsername = req.body.newUsername;
    let email = req.body.email;
    
    const showError = (error, invalidFields) => {
        let firstNameInvalid = false;
        let lastNameInvalid = false;
        let usernameInvalid = false;
        let emailInvalid = false;

        if(invalidFields != undefined){
            if(invalidFields.includes('firstName')){
                firstNameInvalid = true;
            }
            if(invalidFields.includes('lastName')){
                lastNameInvalid = true;
            }
            if(invalidFields.includes('username')){
                usernameInvalid = true;
            }
            if(invalidFields.includes('email')){
                emailInvalid = true;
            }
        }

        let activeItem = 'profile';

        const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout');
        const logoutEverywhereNoncePromise = Nonce.createNonce('user-logout-everywhere', '/dashboard/profile/logout-everywhere');

        Promise.all([logoutNoncePromise, logoutEverywhereNoncePromise]).then(results => {
            res.render(activeItem, {
                title: "Profile | Dashboard",
                activeItem: activeItem,
                fullname: user.first_name + " " + user.last_name || "Unknown user",
                username: user.username,
                firstName: firstName,
                lastName: lastName,
                newUsername: newUsername,
                email: email,
                error: error,
                firstNameInvalid: firstNameInvalid,
                lastNameInvalid: lastNameInvalid,
                usernameInvalid: usernameInvalid,
                emailInvalid: emailInvalid,
                logoutNonce: results[0],
                logoutEverywhereNonce: results[1]
            });
        });
    }

    const showSuccess = (message) => {
        let activeItem = 'profile';

        const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout');
        const logoutEverywhereNoncePromise = Nonce.createNonce('user-logout-everywhere', '/dashboard/profile/logout-everywhere');

        Promise.all([logoutNoncePromise, logoutEverywhereNoncePromise]).then(results => {
            res.render(activeItem, {
                title: "Profile | Dashboard",
                activeItem: activeItem,
                fullname: user.first_name + " " + user.last_name || "Unknown user",
                username: user.username,
                firstName: firstName,
                lastName: lastName,
                newUsername: newUsername,
                email: email,
                success: message,
                logoutNonce: results[0],
                logoutEverywhereNonce: results[1]
            });
        });
    }

    // Validate fields
    invalidFields = [];

    if(firstName.length < 1){
        invalidFields.push('firstName');
    }

    if(lastName.length < 1){
        invalidFields.push('lastName');
    }

    if(newUsername.length  < 1){
        invalidFields.push('username');
    }

    if(!(function(email){
        var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return re.test(String(email).toLowerCase());
    })(email)){
        invalidFields.push('email');
    }

    if(invalidFields.length > 0){
        showError(invalidFields.length + " fields are invalid", invalidFields);
    } else {
        const performSave = () => {
            user.first_name = firstName;
            user.last_name = lastName;
            user.username = newUsername;
            user.email_address = email;

            user.saveUser().then(result => {
                if(result == true){
                    showSuccess("Successfully saved your information");
                } else {
                    showError("Error saving your information");
                }
            }, err => {
                showError("Error saving your information");
            });
        }

        if(newUsername != user.username){
            User.usernameTaken(newUsername).then(result => {
                if(result == true){
                    showError("1 fields are invalid", ['username']);
                } else {
                    performSave();
                }
            }, err => {
                showError("1 fields are invalid", ['username']);
            });
        } else {
            performSave();
        }
    }
}

exports.showProfileChangePassword = (req, res, next) => {
    let user = res.locals.user;

    res.render('profile-change-password', {
        title: "Change Password | Dashboard",
    });
}

exports.performProfileChangePassword = (req, res, next) => {
    const showError = (error) => {
        res.render('profile-change-password', {
            title: "Change Password | Dashboard",
            error: error
        });
    }

    let user = res.locals.user;

    let currentPassword = req.body.currentPassword;
    let newPassword = req.body.newPassword;
    let confirmPassword = req.body.confirmPassword;

    if(newPassword !== confirmPassword){
        showError("Passwords do not match");
    } else {
        user.loadInfo().then(result => {
            if(result == true){
                Auth.readPasswordFromDatabase(user.username).then(result => {
                    Auth.verifyPassword(currentPassword, {
                        all: result
                    }).then(result => {
                        if(result == false){
                            showError("Current password is incorrect");
                        } else {
                            Auth.encryptPassword(newPassword).then(result => {
                                result.push(user.user_id);

                                Auth.savePasswordToDatabase({
                                    all: result
                                }).then(result => {
                                    if(result == true){
                                        // TODO: Delete all access tokens excluding the one the user is currently on
                                        res.redirect(301, '/dashboard/profile');
                                    } else {
                                        showError("Cannot set your new password. Your password will remain unchanged");
                                    }
                                }, err => {
                                    showError("Cannot set your new password. Your password will remain unchanged");
                                });
                            }, err => {
                                showError("Cannot set your new password. Your password will remain unchanged");
                            });
                        }
                    }, err => {
                        showError("Current password is incorrect");
                    });
                }, err => {
                    showError("Cannot change password");
                });
            } else {
                showError("Cannot change password");
            }
        }, err => {
            showError("Cannot change password");
        });
    }
}

exports.showHelp = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'help'

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout');

    Promise.all([logoutNoncePromise]).then(results => {
        res.render(activeItem, {
            title: "Help | Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            logoutNonce: results[0]
        });
    });
}

exports.showSettings = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'settings'

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout');

    Promise.all([logoutNoncePromise]).then(results => {
        res.render(activeItem, {
            title: "Settings | Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            logoutNonce: results[0]
        });
    });
}

