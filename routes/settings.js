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

exports.showSettings = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'settings'

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout/');
    const usersPromise = AuthUtil.get_users();

    Promise.all([logoutNoncePromise, usersPromise]).then(results => {
        res.render(activeItem, {
            title: "Settings | Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            logoutNonce: results[0],
            users: results[1]
        });
    });
}

exports.showAddUserPage = (req, res, next) => {
    let user = res.locals.user;
    let activeItem = 'settings'

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout/');
    const formNoncePromise = Nonce.createNonce('user-add-user', '/dashboard/settings/add-user/');

    Promise.all([logoutNoncePromise, formNoncePromise]).then(results => {
        res.render('settings-add-user', {
            title: "Add User | Settings | Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            logoutNonce: results[0],
            formNonce: results[1]
        });
    });
}

exports.performAddUser = (req, res, next) => {
    let user = res.locals.user;

    let email = req.body.email;
    let firstName = req.body.firstName;
    let lastName = req.body.lastName;
    let username = req.body.newUsername;
    let password = req.body.password;
    let confirmPassword = req.body.confirmPassword;

    const showError = (error, invalidFields) => {
        let emailInvalid = false;
        let firstNameInvalid = false;
        let lastNameInvalid = false;
        let usernameInvalid = false;

        if(invalidFields != undefined){
            if(invalidFields.includes('email')){
                emailInvalid = true;
            }
            if(invalidFields.includes('firstName')){
                firstNameInvalid = true;
            }
            if(invalidFields.includes('lastName')){
                lastNameInvalid = true;
            }
            if(invalidFields.includes('username')){
                usernameInvalid = true;
            }
        }

        let activeItem = 'settings'

        const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout/');
        const formNoncePromise = Nonce.createNonce('user-add-user', '/dashboard/settings/add-user/');

        Promise.all([logoutNoncePromise, formNoncePromise]).then(results => {
            res.render('settings-add-user', {
                title: "Add User | Settings | Dashboard",
                activeItem: activeItem,
                fullname: user.first_name + " " + user.last_name || "Unknown user",
                username: user.username,
                logoutNonce: results[0],
                email: email,
                firstName: firstName,
                lastName: lastName,
                newUsername: username,
                formNonce: results[1],
                emailInvalid: emailInvalid,
                firstNameInvalid: firstNameInvalid,
                lastNameInvalid: lastNameInvalid,
                usernameInvalid: usernameInvalid,
                error: error
            });
        });
    }

    const showSuccess = (message) => {
        let activeItem = 'settings'

        const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout/');
        const formNoncePromise = Nonce.createNonce('user-add-user', '/dashboard/settings/add-user/');

        Promise.all([logoutNoncePromise, formNoncePromise]).then(results => {
            res.render('settings-add-user', {
                title: "Add User | Settings | Dashboard",
                activeItem: activeItem,
                fullname: user.first_name + " " + user.last_name || "Unknown user",
                username: user.username,
                logoutNonce: results[0],
                formNonce: results[1],
                success: message
            });
        });
    }

    Nonce.verifyNonce('user-add-user', req.body.nonce, req.path).then(result => {
        if(result == true){
            // Validate fields
            invalidFields = [];

            if(email.length < 1){
                invalidFields.push('email');
            }

            if(!(function(email){
                var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
                return re.test(String(email).toLowerCase());
            })(email)){
                invalidFields.push('email');
            }

            if(firstName.length < 1){
                invalidFields.push('firstName');
            }

            if(lastName.length < 1){
                invalidFields.push('lastName');
            }

            if(username.length < 1){
                invalidFields.push('username');
            }

            if(password !== confirmPassword){
                showError("Passwords do not match");
            } else if (password < 4){
                showError("Password must be at least 4 characters long");
            } else {
                if(invalidFields.length > 0){
                    showError(invalidFields.length + " fields are invalid", invalidFields);
                } else {
                    const performSave = () => {
                        User.generateUserId().then(user_id => {
                            var user = new User(user_id, username, firstName, lastName, email);
                            user.saveUser().then(result => {
                                if(result == true){
                                    Auth.encryptPassword(confirmPassword).then(result => {
                                        result.push(user_id);

                                        Auth.savePasswordToDatabase({all: result}).then(result => {
                                            if(result == true){
                                                res.redirect(301, '../user-' + user_id + '/');
                                            } else {
                                                showError("Cannot create new user. Please try again.");
                                            }
                                        }, err => {
                                            showError("Cannot create new user. Please try again.");
                                        });
                                    }, err => {
                                        showError("Cannot create new user. Please try again.");
                                    });
                                } else {
                                    showError("Cannot create new user. Please try again.");
                                }
                            }, err => {
                                showError("Cannot create new user. Please try again.");
                            });
                        }, err => {
                            showError("Cannot create new user. Please try again.");
                        });
                    }

                    User.usernameTaken(username).then(result => {
                        if(result == true){
                            showError("1 fields are invalid", ['username']);
                        } else {
                            performSave();
                        }
                    }, err => {
                        showError("1 fields are invalid", ['username']);
                    });
                }
            }
        } else {
            showError("Cannot create new user. Please try again.");
        }
    }, err => {
        showError("Cannot create new user. Please try again.");
    });
}

exports.loadUserInfo = (req, res, next) => {
    const showError = () => {
        res.render('error-custom', {title: "Error", error: {
            title: "Unknown user",
            message: "Unknown user"
        }});
    }

    const userId = req.params.userId.substring(5);
    const targetUser = new User(userId);

    targetUser.loadInfo().then(result => {
        res.locals.targetUser = targetUser;
        next();
    }, err => showError());
}

exports.userInfoPage = (req, res, next) => {
    let user = res.locals.user;
    let targetUser = res.locals.targetUser;
    let activeItem = 'settings'

    const logoutNoncePromise = Nonce.createNonce('user-logout', '/logout/');
    const deleteUserNoncePromise = Nonce.createNonce('user-delete', '/settings/user-' + targetUser.user_id + '/delete-user/');

    Promise.all([logoutNoncePromise, deleteUserNoncePromise]).then(results => {
        res.render('settings-user', {
            title: targetUser.first_name + " " + targetUser.last_name + " | Settings | Dashboard",
            activeItem: activeItem,
            fullname: user.first_name + " " + user.last_name || "Unknown user",
            username: user.username,
            logoutNonce: results[0],
            deleteUserNonce: results[1],
            firstName: targetUser.first_name,
            lastName: targetUser.last_name,
            newUsername: targetUser.username,
            email: targetUser.email_address
        });
    });
}