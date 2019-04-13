/*
Copyright (C) 2019 Ryan Bester
*/

const express = require('express');
const router = express.Router();

const { catchErrors } = require('../handlers/errorHandlers');

showLoginPage = (req, res, next) => {
	res.render('index', {title: "Login", message: "Login to the Murphy's Maths Control Panel"});
}

router.get('/', catchErrors(showLoginPage));

module.exports = router;