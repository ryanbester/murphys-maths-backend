/*
Copyright (C) 2019 Ryan Bester
*/

const crypto = require('crypto');
const argon2 = require('argon2');
const mysql = require('mysql');
require('datejs');

const db = require('../db/db');

module.exports.Auth = class Auth {
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
                        // Close the connection
                        connection.end();

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
                    // If IV is not in database, end the loop
                    return condition(data) ? action(data).then(whilst) : Promise.resolve(data);
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
            const verifyPassword = (hash, saltEncrypted, iv, user_id) => {
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

                if(options['all'][3] === undefined){
                    reject("User ID is not set");
                }
                const user_id = options['all'][3];

                // Verify the password
                verifyPassword(hash, saltEncrypted, iv, user_id).then(result => {
                    if(result){
                        resolve(new module.exports.User(user_id));
                    } else {
                        resolve(false);
                    }
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
                const iv = options['iv'];

                if(options['user_id'] === undefined){
                    reject("User ID is not set");
                }
                const user_id = options['user_id'];

                // Verify the password
                verifyPassword(hash, saltEncrypted, iv, user_id).then(result => {
                    if(result){
                        resolve(new module.exports.User(user_id));
                    } else {
                        resolve(false);
                    }
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

    static readPasswordFromDatabase(username){
        return new Promise((resolve, reject) => {
            // Create a connection to the database
            const connection = db.getConnection();

            // Open the connection
            connection.connect();

            // Execute the query to get the record with the username
            connection.query("SELECT user_id FROM users WHERE username = " + connection.escape(username),
            (error, results, fields) => {
                if (error){
                    // Close the connection
                    connection.end();

                    reject(error);   
                }             

                // If the username matches a record
                if(results.length > 0){
                    // Get the user ID
                    const user_id = results[0].user_id;

                    // Query the passwd table for the password, salt, and IV with the user ID
                    connection.query("SELECT password, HEX(salt) AS salt, HEX(salt_iv) AS salt_iv FROM passwd WHERE user_id = " + connection.escape(user_id),
                    (error, results, fields) => {
                        // Close the connection
                        connection.end();

                        if (error) reject(error);

                        // If the user ID matches a record
                        if(results.length > 0){
                            // Get the password, salt, and IV
                            const hash = results[0].password;
                            const salt = results[0].salt;
                            const salt_iv = results[0].salt_iv;

                            // Return the password, salt, and IV
                            resolve([hash, salt, Buffer.from(salt_iv, 'hex'), user_id]);
                        } else {
                            reject("Username or password is incorrect");
                        }
                    });
                } else {
                    // Close the connection
                    connection.end();

                    reject("Username or password is incorrect");
                }
            });
        });
    }
}

module.exports.User = class User {
    constructor(user_id){
        this.user_id = user_id;
    }

    load_info(){

    }
}

module.exports.AccessToken = class AccessToken {
    constructor(user_id, lifetime = 43200, id) {
        this.user_id = user_id;
        this.lifetime = lifetime;

        if(this.lifetime !== undefined){
            this.expiry = Date.today().setTimeToNow().addMinutes(this.lifetime);
        }

        if(id === undefined){
            this.id = crypto.randomBytes(32).toString('hex');
        } else {
            this.id = id;
        }
    }

    saveTokenToDatabase() {
        return new Promise((resolve, reject) => {
            // Check if the ID is already in the database
            const checkID = idFound => {
                return new Promise((resolve, reject) => {
                    // Create a connection to the database
                    const connection = db.getConnection();

                    // Open the connection
                    connection.connect();

                    // Execute the query to check for the ID
                    connection.query("SELECT COUNT(*) AS IDCount FROM access_tokens WHERE access_token = UNHEX(" + connection.escape(this.id) + ")",
                    (error, results, fields) => {
                        // Close the connection
                        connection.end();

                        if (error) reject(error);

                        // If the ID is in the database, generate a new ID and continue the loop
                        if(results[0].IDCount > 0){
                            this.id = crypto.randomBytes(32).toString('hex');
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
                    // If ID is not in the database, end the loop
                    return condition(data) ? action(data).then(whilst) : Promise.resolve(data);
                }
                return whilst(data);
            })(true, idFound => idFound, checkID).then(idFound => {
                // Convert expiry time to string
                var expiryDateTime = this.expiry.toString('u');

                // Remove the Z from the end of the timestamp
                expiryDateTime = expiryDateTime.slice(0, -1);

                // SHA-256 the access token
                const hash = crypto.createHash('sha256').update(this.id).digest('hex');

                // Create a connection to the database
                const connection = db.getConnection('modify');

                // Open the connection
                connection.connect();

                // Execute the query to insert the access token into the database
                connection.query("INSERT INTO access_tokens VALUES("
                + "UNHEX(" + connection.escape(hash) + "), "
                + connection.escape(this.user_id) + ", "
                + connection.escape(expiryDateTime) + ")",
                (error, results, fields) => {
                    // Close the connection
                    connection.end();

                    if (error) reject(error);

                    resolve(true);
                });
            });
        });
    }

    checkToken(){
        return new Promise((resolve, reject) => {
            // SHA-256 the access token
            const hash = crypto.createHash('sha256').update(this.id).digest('hex');

            // Create a connection to the database
            const connection = db.getConnection();

            // Open the connection
            connection.connect();

            // Check if the access token is in the database
            connection.query("SELECT * FROM access_tokens WHERE access_token = UNHEX(" + connection.escape(this.id) + ")",
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                // If access token is not found, return an error
                if(results === undefined || results.length == 0){
                    reject("Access token not found");
                } else {
                    // If access token has expired, return an error
                    if(Date.parse(results[0].expires) < Date.today()){
                        reject("Token has expired");
                    } else {
                        this.user_id = results[0].user_id;
                        resolve(true);
                    }
                }
            });
        });
    }
}