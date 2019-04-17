/*
Copyright (C) 2019 Ryan Bester
*/

const crypto = require('crypto');
const argon2 = require('argon2');
const mysql = require('mysql');

const db = require('../db/db');

module.exports = class Auth {
    static encryptPassword(password){
        return new Promise((resolve, reject) => {
            // Generate the salt
            const salt = crypto.randomBytes(8).toString('hex');

            // Concatenate the password, salt, and pepper
            const passwordCombined = password + salt + process.env.PEPPER;

            // Generate the first hash (SHA-512 HMAC of salt and peppered password)
            const hash1 = crypto.createHmac('sha512', process.env.SECRET_1).update(passwordCombined).digest('hex');

            // Generate the second hash (SHA-256 HMAC of plain password)
            const hash2 = crypto.createHmac('sha256', process.env.SECRET_2).update(password).digest('base64').substr(0, 32);

            // Generate the initialization vector (nonce)
            var iv = crypto.randomBytes(16);

            // Check if the IV is in the database
            const checkIV = ivFound => {
                return new Promise((resolve, reject) => {
                    // Create a connection to the database
                    const connection = db.getConnection();

                    // Open the connection
                    connection.connect();

                    // Execute the query to check for the IV
                    connection.query("SELECT COUNT(*) AS IVCount FROM passwd WHERE salt_iv = UNHEX(" + connection.escape(iv.toString('hex')) + ")",
                    (error, results, fields) => {
                        if (error) reject(error);

                        // If the IV is in the database, generate a new IV and continue the loop
                        if(results[0].IVCount > 0){
                            iv = crypto.randomBytes(16);
                            resolve(true);
                        } else {
                            // End the loop
                            resolve(false);
                        }
                    });
                });
            }

            // Create a loop
            ((data, condition, action) => {
                var whilst = data => {
                    // If IV is not in database, end the loops
                    return condition(data) ? action(data).then(whilst): Promise.resolve(data);
                }
                return whilst(data);
            })(true, ivFound => ivFound, checkIV).then(ivFound => {
                // Encrypt the salt with the SHA-256'd password with AES-256-CBC
                const cipher = crypto.createCipheriv('aes-256-cbc', hash2, iv);
                const saltEncrypted = cipher.update(salt, 'utf8', 'hex') + cipher.final('hex');

                // Hash the first hash with Argon2
                argon2.hash(hash1, {type: argon2.argon2id, timeCost: 8, parallelism: 8})
                .then(hash => {
                    // Return the hashed password, encrypted salt, and salt IV
                    resolve([hash, saltEncrypted, iv]);
                }, err => {
                    reject(err);
                });
            });
        });
    }

    static verifyPassword(password, options){
        return new Promise((resolve, reject) => {
            const verifyPassword = (hash, saltEncrypted, iv) => {
                return new Promise((resolve, reject) => {
                    try{
                        // Generate the  second hash (SHA-256 HMAC of plain password)
                        const hash2 = crypto.createHmac('sha256', process.env.SECRET_2).update(password).digest('base64').substr(0, 32);

                        // Decrypt the salt with the SHA-256'd password with AES-256-CBC
                        const cipher = crypto.createDecipheriv('aes-256-cbc', hash2, iv);
                        const salt = cipher.update(saltEncrypted, 'hex', 'utf8') + cipher.final('utf8');

                        // Concatenate the password, salt, and pepper
                        const passwordCombined = password + salt + process.env.PEPPER;

                        // Generate the first hash (SHA-512 HMAC of salt and peppered password)
                        const hash1 = crypto.createHmac('sha512', process.env.SECRET_1).update(passwordCombined).digest('hex');

                        // Verify the first hash with Argon2
                        argon2.verify(hash, hash1).then(result => {
                            // Return the result
                            resolve(result);
                        }, err => {
                            reject(err);
                        });
                    } catch(ex) {
                        reject(ex);
                    }
                });
            }

            if(options['all']){
                // Declare the variables in the order returned from the encryptPassword function
                if(options['all'][0] === undefined){
                    reject("Hash is not set");
                }
                const hash = options['all'][0];

                if(options['all'][1] === undefined){
                    reject("Encrypted salt is not set");
                }
                const saltEncrypted = options['all'][1];

                if(options['all'][2] === undefined){
                    reject("Salt IV is not set");
                }
                const iv = options['all'][2];

                // Verify the password
                verifyPassword(hash, saltEncrypted, iv).then(result => {
                    resolve(result);
                }, err => {
                    reject(err);
                })
            } else {
                // Declare the variables
                if(options['hash'] === undefined){
                    reject("Hash is not set");
                }
                const hash = options['hash'];

                if(options['saltEncrypted'] === undefined){
                    reject("Salt is not set");
                }
                const saltEncrypted = options['saltEncrypted'];

                if(options['iv'] === undefined){
                    reject("Salt IV is not set");
                }

                // Verify the password
                verifyPassword(hash, saltEncrypted, iv).then(result => {
                    resolve(result);
                }, err => {
                    reject(err);
                })
            }
        });
    }

    static savePasswordToDatabase(user_id, options){
        return new Promise((resolve, reject) => {
            if(options['all']){

            } else {

            }
        });
    }

    static readPasswordFromDatabase(user_id){
        return new Promise((resolve, reject) => {
            
        });
    }
}