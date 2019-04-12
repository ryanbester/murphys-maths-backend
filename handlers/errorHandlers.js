/*
Copyright (C) 2019 Ryan Bester
*/

module.exports.catchErrors = (fn) => {
    return function(req, res, next){
        return fn(req, res, next).catch((e) => {
            if(e.response){
                e.status = e.response.status;
            }
            next(e);
        });
    }
}