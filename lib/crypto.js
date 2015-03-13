var crypto = require('crypto');

crypto.createToken = function (length, encoding, callback) {
    return crypto.pseudoRandomBytes(length, function (err, token) {
        if (err) {
            return callback(err);
        }

        callback(null, token.toString(encoding));
    });
};

module.exports = crypto;
