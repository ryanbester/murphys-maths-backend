/*
Copyright (C) 2019 Ryan Bester
*/

module.exports.showLoginPage = (req, res, next) => {
	res.render('index', {message: "Login to the Murphy's Maths Control Panel"});
}