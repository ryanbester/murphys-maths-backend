/*
Copyright (C) 2019 Ryan Bester
*/

const crypto = require('crypto');
const argon2 = require('argon2');
const mysql = require('mysql');
require('datejs');

const db = require('../db/db');
const { Auth, AccessToken, User, Nonce } = require('../core/auth');

const get_users = () => {
    return new Promise((resolve, reject) => {
        const connection = db.getConnection();

        // Open the connection
        connection.connect();

        connection.query("SELECT user_id AS user_id, username, email_address, first_name, last_name FROM users",
        (error, results, fields) => {
            // Close the connection
            connection.end();

            if (error) reject(error);

            let users = [];

            Object.keys(results).forEach(key => {
                users.push(new User(
                    results[key].user_id,
                    results[key].username,
                    results[key].first_name,
                    results[key].last_name,
                    results[key].email_address
                ));
            });

            resolve(users);
        });
    });
}

module.exports = {
    get_users: get_users
};