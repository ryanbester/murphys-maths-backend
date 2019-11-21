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
                });
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

    static savePasswordToDatabase(options){
        return new Promise((resolve, reject) => {
            const savePassword = (hash, saltEncrypted, iv, user_id) => {
                return new Promise((resolve, reject) => {
                    // Create a connection to the database
                    const connection = db.getConnection('modify');

                    // Open the connection
                    connection.connect();

                    connection.query("SELECT COUNT(*) AS UserCount FROM passwd WHERE user_id = " + connection.escape(user_id),
                    (error, results, fields) => {
                        if (error) {
                            connection.end();
                            reject(error);
                        } else {
                            if(results[0].UserCount > 0){
                                // Execute the query to update the existing password in the database
                                connection.query("UPDATE passwd "
                                + "SET password = " + connection.escape(hash) + ", "
                                + "salt = UNHEX(" + connection.escape(saltEncrypted) + "), "
                                + "salt_iv = UNHEX(" + connection.escape(iv.toString('hex')) + ") "
                                + "WHERE user_id = " + connection.escape(user_id),
                                (error, results, fields) => {
                                    // Close the connection
                                    connection.end();

                                    if (error) reject(error);

                                    resolve(true);
                                });
                            } else {
                                // Execute the query to insert the new password into the database
                                connection.query("INSERT INTO passwd VALUES("
                                + connection.escape(user_id) + ", "
                                + connection.escape(hash) + ", "
                                + "UNHEX(" + connection.escape(saltEncrypted) + "), "
                                + "UNHEX(" + connection.escape(iv.toString('hex')) + "))",
                                (error, results, fields) => {
                                    // Close the connection
                                    connection.end();

                                    if (error) reject(error);

                                    resolve(true);
                                });
                            }
                        }
                    });
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
                savePassword(hash, saltEncrypted, iv, user_id).then(result => {
                    if(result){
                        resolve(result);
                    } else {
                        resolve(false);
                    }
                }, err => {
                    reject(err);
                });
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
                savePassword(hash, saltEncrypted, iv, user_id).then(result => {
                    if(result){
                        resolve(result);
                    } else {
                        resolve(false);
                    }
                }, err => {
                    reject(err);
                })
            }

        });
    }

    static deletePasswordFromDatabase(user_id){
        return new Promise((resolve, reject) => {
            // Create a connection to the database
            const connection = db.getConnection('delete');

            // Open the connection
            connection.connect();

            connection.query("DELETE FROM passwd WHERE user_id = " + connection.escape(user_id),
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                resolve(true);
            });
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
    constructor(user_id, username, first_name, last_name, email_address){
        this.user_id = user_id;
        this.username = username;
        this.first_name = first_name;
        this.last_name = last_name;
        this.email_address = email_address;
    }

    loadInfo(){
        return new Promise((resolve, reject) => {
            // Check if user ID is set
            if (this.user_id === undefined) {
                reject("User ID not set");
            }

            // Create a connection to the database
            const connection = db.getConnection();

            // Open the connection
            connection.connect();

            // Execute the query to obtain the user details
            connection.query("SELECT * FROM users WHERE user_id = " + connection.escape(this.user_id),
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                // IF the user ID matches a record
                if (results.length > 0) {
                    // Get the user details
                    this.username = results[0].username;
                    this.first_name = results[0].first_name;
                    this.last_name = results[0].last_name;
                    this.email_address = results[0].email_address;

                    resolve(true);
                } else {
                    reject(false);
                }
            });
        });
    }

    verifyUser() {
        return new Promise((resolve, reject) => {
            // Create a connection to the database
            const connection = db.getConnection();

            // Open the connection
            connection.connect();

            // Execute the query to check for the user ID
            connection.query("SELECT COUNT(*) AS UserCount FROM users WHERE user_id = " + connection.escape(this.user_id),
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                // If the user is in the database, return true
                if(results[0].UserCount > 0 && results[0].UserCount < 2){
                    resolve(true);
                } else {
                    reject(false);
                }
            });
        });
    }

    saveUser() {
        return new Promise((resolve, reject) => {
            if(this.user_id === undefined){
                reject("User ID not set");
            }

            // Create a connection to the database
            const connection = db.getConnection('modify');

            // Open the connection
            connection.connect();

            // Execute the query to update the user information
            connection.query("SELECT COUNT(*) AS UserCount FROM users WHERE user_id = " + connection.escape(this.user_id),
            (error, results, fields) => {
                if(error){
                    connection.end();
                    reject(error);
                } else {
                    if(results[0].UserCount > 0){
                        // Update the existing user

                        // Execute the query to update the user information
                        connection.query("UPDATE users "
                        + "SET username = " + connection.escape(this.username) + ", "
                        + "first_name = " + connection.escape(this.first_name) + ", "
                        + "last_name = " + connection.escape(this.last_name) + ", "
                        + "email_address = " + connection.escape(this.email_address)
                        + " WHERE user_id = " + connection.escape(this.user_id),
                        (error, results, fields) => {
                            // Close the connection
                            connection.end();

                            if (error) reject(error);

                            resolve(true);
                        });
                    } else {
                        // Insert the new user

                        // Execute the query to update the user information
                        connection.query("INSERT INTO users VALUES("
                        + connection.escape(this.user_id) + ","
                        + connection.escape(this.username) + ", "
                        + connection.escape(this.first_name) + ", "
                        + connection.escape(this.last_name) + ", "
                        + connection.escape(this.email_address) + ")",
                        (error, results, fields) => {
                            // Close the connection
                            connection.end();

                            if (error) reject(error);

                            resolve(true);
                        });
                    }
                }
            });
        });
    }

    deleteUser(){
        return new Promise((resolve, reject) => {
            if(this.user_id === undefined){
                reject("User ID not set");
            }

            // Create a connection to the database
            const connection = db.getConnection('delete');

            // Open the connection
            connection.connect();

            connection.query("DELETE FROM users WHERE user_id = " + connection.escape(this.user_id),
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                resolve(true);
            });
        });
    }

    static usernameTaken(username) {
        return new Promise((resolve, reject) => {
            // Create a connection to the database
            const connection = db.getConnection();

            // Open the connection
            connection.connect();

            // Execute the query to check for the username
            connection.query("SELECT COUNT(*) AS UserCount FROM users WHERE username = " + connection.escape(username),
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                // If the username is in the database, return true
                if(results[0].UserCount > 0){
                    resolve(true);
                } else {
                    resolve(false);
                }
            })
        });
    }

    static generateUserId() {
        return new Promise((resolve, reject) => {
            const connection = db.getConnection();

            connection.connect();

            connection.query("SELECT MAX(user_id) AS HighestUserID FROM users",
            (error, results, fields) => {
                connection.end();

                if (error) reject(error);

                resolve(results[0].HighestUserID + 1);
            });
        });
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
            connection.query("SELECT * FROM access_tokens WHERE access_token = UNHEX(" + connection.escape(hash) + ")",
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

    deleteToken(){
        return new Promise((resolve, reject) => {
            // SHA-256 the access token
            const hash = crypto.createHash('sha256').update(this.id).digest('hex');

            // Create a connection to the database
            const connection = db.getConnection();

            // Open the connection
            connection.connect();

            // Check if the access token exists
            connection.query("SELECT * FROM access_tokens WHERE access_token = UNHEX(" + connection.escape(hash) + ")",
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                if(results.length > 0){
                    // Delete the access token

                    // Create a connection to the database
                    const connection = db.getConnection('delete');

                    // Open the connection
                    connection.connect();

                    // Execute the delete query
                    connection.query("DELETE FROM access_tokens WHERE access_token = UNHEX(" + connection.escape(hash) + ")",
                    (error, results, fields) => {
                        // Close the connection
                        connection.end();

                        if (error) reject(error);

                        resolve(true);
                    });
                }
            });
        });
    }

    deleteUserTokens(exceptions){
        return new Promise((resolve, reject) => {
            if(this.user_id === undefined){
                reject("User ID not set");
            }

            var exceptionSubQuery = '';

            // Create a connection to the database
            const connection = db.getConnection('delete');

            if (exceptions !== undefined){
                var hashedExceptions = [];

                // SHA-256 every exception
                exceptions.forEach((exception) => {
                    const hash = crypto.createHash('sha256').update(exception).digest('hex');

                    hashedExceptions.push(hash);
                });

                var i = 0;
                hashedExceptions.forEach((exception) => {
                    exceptionSubQuery += " AND access_token != UNHEX(" + connection.escape(exception) + ")";
                });
            }

            // Open the connection
            connection.connect();

            connection.query("DELETE FROM access_tokens WHERE user_id = " + connection.escape(this.user_id) + exceptionSubQuery,
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                resolve(true);
            });
        });
    }

    static deleteExpiredTokens(){
        return new Promise((resolve, reject) => {
            // Create a connection to the database
            const connection = db.getConnection('delete');

            // Open the connection
            connection.connect();

            connection.query("DELETE FROM access_tokens WHERE expires < NOW()",
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                resolve(true);
            });
        });
    }

    static deleteAllTokens(){
        return new Promise((resolve, reject) => {
            // Create a connection to the database
            const connection = db.getConnection('delete');

            // Open the connection
            connection.connect();

            connection.query("DELETE FROM access_tokens",
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                resolve(true);
            });
        });
    }
}

module.exports.Nonce = class Nonce {
    static createNonce(name, url){
        return new Promise((resolve, reject) => {
            // Generate an ID
            let rawID = crypto.randomBytes(8).toString('hex');

            // Encrypt the ID
            let id = crypto.createHash('sha256').update(rawID).digest('hex');

            // Generate the expiry date
            const expiry = Date.today().setTimeToNow().addHours(24).toString('u').slice(0, -1);

            // Check if the ID is already in the database
            const checkID = idFound => {
                return new Promise((resolve, reject) => {
                    // Create a connection to the database
                    const connection = db.getConnection();

                    // Open the connection
                    connection.connect();

                    // Execute the query to check for the ID
                    connection.query("SELECT COUNT(*) AS IDCount FROM nonces WHERE ID = UNHEX(" + connection.escape(id) + ")",
                    (error, results, fields) => {
                        // Close the connection
                        connection.end();

                        if (error) reject(error);

                        // If the ID is in the database, generate a new ID and continue the loop
                        if(results[0].IDCount > 0){
                            id = crypto.randomBytes(8).toString('hex');
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
                // Create a connection to the database
                const connection = db.getConnection('modify');

                // Open the connection
                connection.connect();

                // Execute the query to insert the nonce into the database
                connection.query("INSERT INTO nonces VALUES("
                + "UNHEX(" + connection.escape(id) + "), "
                + connection.escape(name) + ", "
                + connection.escape(url) + ", "
                + connection.escape(expiry) + ")",
                (error, results, fields) => {
                    // Close the connection
                    connection.end();

                    if (error) reject(error);

                    resolve(rawID);
                });
            });
        });
    }

    static verifyNonce(name, id, url){
        return new Promise((resolve, reject) => {
            // SHA-256 the ID
            const hash = crypto.createHash('sha256').update(id).digest('hex');

            // Create a connection to the database
            const connection = db.getConnection();

            // Open the connection
            connection.connect();

            // Check if the nonce is in the database
            connection.query("SELECT * FROM nonces WHERE id = UNHEX(" + connection.escape(hash) + ")",
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                // If the nonce is not found, return an error
                if(results === undefined || results.length == 0){
                    reject("Nonce not found");
                } else {
                    // If nonce matches the name
                    if(results[0].name != name){
                        reject("Nonce invalid");
                    } else {
                        // If nonce has a different URL, return an error
                        if(results[0].url != url){
                            reject("Nonce invalid");
                        } else {
                            // If nonce has expired, return an error
                            if(Date.parse(results[0].expires) < Date.today()){
                                reject("Nonce has expired");
                            } else {             
                                // Delete the nonce

                                // Create a connection to the database
                                const connection = db.getConnection('delete');

                                // Open the connection
                                connection.connect();

                                // Execute the delete query
                                connection.query("DELETE FROM nonces WHERE id = UNHEX(" + connection.escape(hash) + ")",
                                (error, results, fields) => {
                                    // Close the connection
                                    connection.end();

                                    if (error) reject(error);

                                    resolve(true);
                                });
                            }
                        }
                    }
                }
            });
        });
    }

    static deleteAllNonces(){
        return new Promise((resolve, reject) => {
            // Create a connection to the database
            const connection = db.getConnection('delete');

            // Open the connection
            connection.connect();

            // Execute the delete query
            connection.query("DELETE FROM nonces",
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                resolve(true);
            });
        });
    }

    static deleteExpiredNonces(){
        return new Promise((resolve, reject) => {
            // Create a connection to the database
            const connection = db.getConnection('delete');

            // Open the connection
            connection.connect();

            // Execute the delete query
            connection.query("DELETE FROM nonces WHERE expires < NOW()",
            (error, results, fields) => {
                // Close the connection
                connection.end();

                if (error) reject(error);

                resolve(true);
            });
        });
    }
}