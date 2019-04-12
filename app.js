const path = require('path')
const https = require('https');
const fs = require('fs');
const express = require('express')
const helmet = require('helmet')

const app = express();

app.set('title', "Murphys Maths");

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(helmet());

const options = {
	key: fs.readFileSync("/etc/nginx/certs/www.ryanbester.com.key", 'utf8'),
	cert: fs.readFileSync("/etc/nginx/certs/www.ryanbester.com.crt", 'utf8')
};

app.get('/', function(req, res) {
	res.render('index', {title: 'Murphys Maths', message: 'Welcome to Murphys Maths'});
});

// Handle 404 page
app.use(function(req, res, next){
	const err = new Error("404: Page not found");
	err.status = 404;
	next(err);
});

// Error handler
app.use(function(err, req, res, next){
	res.locals.app = app;
	res.locals.error = err;
	res.locals.error.status = err.status || 500;
	
	if(req.app.get('env') !== 'development'){
		delete err.stack;
	}

	res.locals.title = err.message;
	res.status(err.status || 500);
	res.render('error');
});

var httpsServer = https.createServer(options, app);
httpsServer.listen(process.env.PORT);