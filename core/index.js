/*
Copyright (C) 2019 Ryan Bester
*/

module.exports.showIndexPage = (req, res, next) => {
    res.render('index', {message: "Welcome to the Murphy's Maths Control Panel"});
}