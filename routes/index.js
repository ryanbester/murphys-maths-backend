/*
Copyright (C) 2019 Ryan Bester
*/

const express = require('express');
const router = express.Router();

const { catchErrors } = require('../handlers/errorHandlers');
const { showIndexPage } = require('../core/index.js')
const { showLoginPage } = require('../core/auth.js')

router.get('/', catchErrors(showIndexPage))

router.get('/login', catchErrors(showLoginPage));

module.exports = router;