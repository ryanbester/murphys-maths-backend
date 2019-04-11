const https = require('https');
const fs = require('fs');

var app = require('express')();

const options = {
	key: fs.readFileSync("/etc/nginx/certs/www.ryanbester.com.key", 'utf8'),
	cert: fs.readFileSync("/etc/nginx/certs/www.ryanbester.com.crt", 'utf8')
};

app.get('/', function(req, res) {
	res.writeHead(200);
	res.end("Hello, World!\n");
});

app.use(function(req, res, next){
	res.status(404);
	res.end("404: Not found\n");
});

var httpsServer = https.createServer(options, app);

httpsServer.listen(process.env.PORT);
