/*
 * Copyright (c) 2015, Yahoo Inc. All rights reserved.
 * Copyrights licensed under the New BSD License.
 * See the accompanying LICENSE file for terms.
 */

'use strict';

module.exports = CSP;

var crypto = require('./crypto');
var LRU    = require('lru-cache');

var TOKEN_RE = /(self|unsafe-inline)(?!.)|(sha(256|384|512)-|nonce-)/;

var VALID_DIRECTIVES = [
    'default-src',
    'style-src',
    'connect-src',
    'script-src',
    'object-src',
    'img-src',
    'frame-ancestors',
    'form-action',
    'child-src',
    'base-uri',
    'media-src',
    'font-src',
    'plugin-types',
    'report-uri'
];

function CSP (config) {
    this.cache         = new LRU(50);
    this.cspPolicies   = this.getCSPPolicies(config || {});

    this.signedScripts = {};
    this.signedStyles  = {};
}

CSP.prototype.sign = function (key) {
    var result = this.cache.get(key);
    var hash;

    if (!result) {
        // The hashing algorithm may be one of: SHA-256, SHA-384 or SHA-512
        // See https://w3c.github.io/webappsec/specs/content-security-policy/#source-list-valid-hashes
        // Node only supports SHA-256 and SHA-512. Using the 256 version
        // because it's faster.
        hash = crypto.createHash('sha256');
        hash.update(key, 'utf8');
        // As per the spec in 4.2.5.2.3, this must return the base64 encoded
        // version of the digest
        result = 'sha256-' + hash.digest('base64');
        this.cache.set(key, result);
    }

    return result;
};

CSP.prototype.unsafeGetProps = function (obj) {
    var hashes = [];
    var hash;

    // Ignore hasOwnProperty because this function is meant to be called
    // on objects created with Object.create(null)
    /*jshint forin: false*/
    for (hash in obj) {
        hashes.push("'" + hash + "'");
    }

    return hashes;
    /*jshint forin: true*/
};

CSP.prototype.getHeaders = function (res, policy, signedScripts, signedStyles) {
    var useSignedScripts = signedScripts.length > 0;
    var useSignedStyles  = signedStyles.length > 0;
    var useScriptNonce   = !!policy.useScriptNonce;
    var useStyleNonce    = !!policy.useStyleNonce;
    var directives       = policy.directives || {};
    var nonce            = (useScriptNonce || useStyleNonce) ? '\'nonce-' + res.locals.cspToken + '\' ' : null;
    var policyKeys       = Object.keys(directives);

    if ((useScriptNonce || useSignedScripts) && policyKeys.indexOf('script-src') < 0) {
        policyKeys.push('script-src');
    }

    if ((useStyleNonce || useSignedStyles) && policyKeys.indexOf('style-src') < 0) {
        policyKeys.push('style-src');
    }

    return policyKeys.map(function (type) {
        var policy = [type].concat(directives[type] || []);

        if ((useScriptNonce && type === 'script-src') || (useStyleNonce && type === 'style-src')) {
            policy = policy.concat(nonce);
        }

        if (type === 'script-src' && useSignedScripts) {
            policy = policy.concat(signedScripts);
        }

        if (type === 'style-src' && useSignedStyles) {
            policy = policy.concat(signedStyles);
        }

        return policy.join(' ');
    }).join(';');
};

CSP.prototype.setContentSecurityHeaders = function (res) {
    var signedScripts    = this.unsafeGetProps(this.getSignedScripts(res));
    var signedStyles     = this.unsafeGetProps(this.getSignedStyles(res));
    var responsePolicies = res.locals.cspPolicies;
    var policies         = responsePolicies ? responsePolicies.policy : this.cspPolicies.policy;
    var reportPolicies   = responsePolicies ? responsePolicies.reportPolicy : this.cspPolicies.reportPolicy;
    var policy, reportPolicy;

    if (policies) {
        policy = this.getHeaders(res, policies, signedScripts, signedStyles);
        res.setHeader('Content-Security-Policy', policy);
    }

    if (reportPolicies) {
        reportPolicy = this.getHeaders(res, reportPolicies, signedScripts, signedStyles);
        res.setHeader('Content-Security-Policy-Report-Only', reportPolicy);
    }
};

CSP.prototype.getSignedScripts = function (res) {
    if (!res._cspSignedScripts) {
        Object.defineProperty(res, '_cspSignedScripts', {
            value: Object.create(this.signedScripts)
        });
    }
    return res._cspSignedScripts;
};

CSP.prototype.getSignedStyles = function (res) {
    if (!res._cspSignedStyles) {
        Object.defineProperty(res, '_cspSignedStyles', {
            value: Object.create(this.signedStyles)
        });
    }
    return res._cspSignedStyles;
};

CSP.prototype.getCSPPolicies = function (config) {
    var policy, reportPolicy;

    if (config.policy) {
        policy = Object.freeze({
            useScriptNonce: !!config.policy.useScriptNonce,
            useStyleNonce:  !!config.policy.useStyleNonce,
            directives:     config.policy.directives ? this.getDirectives(config.policy.directives) : null
        });
    }

    if (config.reportPolicy) {
        reportPolicy = Object.freeze({
            useScriptNonce: !!config.reportPolicy.useScriptNonce,
            useStyleNonce:  !!config.reportPolicy.useStyleNonce,
            directives:     config.reportPolicy.directives ? this.getDirectives(config.reportPolicy.directives) : null
        });
    }

    return Object.freeze({
        policy:       policy,
        reportPolicy: reportPolicy
    });
};

CSP.prototype.getDirectives = function (config) {
    var directives = {};

    VALID_DIRECTIVES.forEach(function (directiveName) {
        if (Array.isArray(config[directiveName])) {
            directives[directiveName] = config[directiveName].filter(function (rule) {
                //If cspPolicies have been defined, no app level directives can be set
                //i.e. this is a request and it is safe to allow the developer to specify
                //a nonce
                if (this.cspPolicies || rule.replace(/\'/, '').indexOf('nonce-') !== 0) {
                    return true;
                }
                throw new Error('You cannot explicitly set a nonce at the app level. If you want to use a nonce, set `useScriptNonce` or `useStyleNonce` to true in the config object.');
            }, this)
            .map(function (rule) {
                if (TOKEN_RE.test(rule)) {
                    rule = '\'' + rule + '\'';
                }
                return rule;
            });
            Object.freeze(directives[directiveName]);
        }
    }, this);

    return Object.freeze(directives);
};

CSP.prototype.setNonce = function (res, policies, reportPolicies, callback) {
    if ((policies && (policies.useScriptNonce || policies.useStyleNonce)) ||
        (reportPolicies && (reportPolicies.useScriptNonce || reportPolicies.useStyleNonce))) {
        // Using base64 encoding, assuming the character set is the one defined
        // in http://en.wikipedia.org/wiki/Base64#Examples. This should base a
        // safe value for HTML attributes and HTTP headers.
        crypto.createToken(36, 'base64', function (err, token) {
            if (err) {
                return callback(err);
            }

            try {
                Object.defineProperty(res.locals, 'cspToken', {
                    value: token,
                    enumerable: true
                });
                callback(null, res);
            } catch (ex) {
                callback(new Error('Unable to set the nonce token to res.locals.'));
            }
        });
    } else {
        callback(null, res);
    }
};
