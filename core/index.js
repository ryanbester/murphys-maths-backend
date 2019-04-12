/*
Copyright (C) 2019 Ryan Bester
*/

module.exports.showIndexPage = (req, res, next) => {
    res.render('index', {title: 'Murphy\'s Maths', message: "Welcome to the Murphy's Maths Control Panel"});
}