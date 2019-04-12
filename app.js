const path = require('path')
const https = require('https');
const fs = require('fs');
const express = require('express')
const helmet = require('helmet')

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

const options = {
	key: fs.readFileSync("/etc/nginx/certs/www.ryanbester.com.key", 'utf8'),
	cert: fs.readFileSync("/etc/nginx/certs/www.ryanbester.com.crt", 'utf8')
};

app.get('/', function(req, res) {
	res.render('index', {title: 'Title', message: 'Welcome to Murphys Maths'});
});

// Handle 404 page
app.use(function(req, res, next){
	res.status(404);
	res.end("404: Not found\n");
});

var httpsServer = https.createServer(options, app);
httpsServer.listen(process.env.PORT);