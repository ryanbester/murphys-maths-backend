/*
Copyright (C) 2019 Ryan Bester
*/

const mysql = require('mysql');

module.exports.getConnection = (type) => {
    var username = process.env.DB_USER;
    var password = process.env.DB_PASS;

    if(type == 'modify'){
        username = process.env.DB_USER_MODIFY;
        password = process.env.DB_PASS_MODIFY;
    } else if (type == 'delete'){
        username = process.env.DB_USER_DELETE;
        password = process.env.DB_PASS_DELETE;
    }

    const connection = mysql.createConnection({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: username,
        password: password,
        database: process.env.DB_DATABASE
    });

    return connection;
}