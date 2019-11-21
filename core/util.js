/*
Copyright (C) 2019 Ryan Bester
*/

const get_tld = () => {
    if(process.env.NODE_ENV == 'development'){
        return "dev";
    } else {
        return "com";
    }
}

module.exports = {
    get_tld: get_tld,
};