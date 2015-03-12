/*
 * Copyright (c) 2015, Yahoo Inc. All rights reserved.
 * Copyrights licensed under the New BSD License.
 * See the accompanying LICENSE file for terms.
 */

'use strict';
var crypto = require('crypto');
var LRU    = require('lru-cache');

exports.extend = function (app, config) {
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

    var TOKEN_RE = /(self|unsafe-inline)(?!.)|(sha(256|384|512)-|nonce-)/;

    var cache  = new LRU(50);
    var appSignedScripts = {};
    var appSignedStyles = {};
    var cspPolicies;
    
    if (app['@express-csp']) {
        return;
    }

    Object.defineProperty(app, '@express-csp', {
        value: exports
    });

    config = config || {};
    cspPolicies = getCSPPolicies(config);

    function sign(str) {
        var result = cache.get(str),
            hash;

        if (!result) {
            // The hashing algorithm may be one of: SHA-256, SHA-384 or SHA-512
            // See https://w3c.github.io/webappsec/specs/content-security-policy/#source-list-valid-hashes
            // Node only supports SHA-256 and SHA-512. Using the 256 version
            // because it's faster.
            hash = crypto.createHash('sha256');
            hash.update(str, 'utf8');
            // As per the spec in 4.2.5.2.3, this must return the base64 encoded
            // version of the digest
            result = 'sha256-' + hash.digest('base64');
            cache.set(str, result);
        }

        return result;
    }

    //creates an array of hashes from an object containing hashes as key values
    function unsafeGetProps(obj) {
        var hashes = [], hash;

        // Ignore hasOwnProperty because this function is meant to be called
        // on objects created with Object.create(null)
        /*jshint forin: false*/
        for (hash in obj) {
            hashes.push('\'' + hash + '\'');
        }

        return hashes;
        /*jshint forin: true*/
    }

    function getHeaders(res, policy, signedScripts, signedStyles) {
        var useSignedScripts = signedScripts.length > 0,
            useSignedStyles = signedStyles.length > 0,
            directives = policy.directives || {},
            policies,
            useScriptNonce = policy.useScriptNonce,
            useStyleNonce = policy.useStyleNonce,
            nonce = (useScriptNonce || useStyleNonce) ? '\'nonce-' + res.locals.cspToken + '\' ' : null,
            policyKeys = Object.keys(directives);
        
        if ((useScriptNonce || useSignedScripts) && policyKeys.indexOf('script-src') < 0) {
            policyKeys.push('script-src');
        }
        
        if ((useStyleNonce || useSignedStyles) && policyKeys.indexOf('style-src') < 0) {
            policyKeys.push('style-src');
        }

        policies = policyKeys.map(function (type) {
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
            
            policy = policy.join(' ');
            return policy;
        });

        return policies.join(';');
    }

    function setHeaders(res) {
        var signedScripts = unsafeGetProps(getSignedScripts(res)),
            signedStyles = unsafeGetProps(getSignedStyles(res)),
            responsePolicies = res.locals.cspPolicies,
            policies = responsePolicies ? responsePolicies.policy : cspPolicies.policy,
            reportPolicies = responsePolicies ? responsePolicies.reportPolicy : cspPolicies.reportPolicy,
            policy,
            reportPolicy;

        if (policies) {
            policy = getHeaders(res, policies, signedScripts, signedStyles);
            res.setHeader('Content-Security-Policy', policy);
        }

        if (reportPolicies) {
            reportPolicy = getHeaders(res, reportPolicies, signedScripts, signedStyles);
            res.setHeader('Content-Security-Policy-Report-Only', reportPolicy);
        }
    }

    // Signed scripts are stored as keys in an object to take advantage of
    // prototypical inheritance instead of relying on array concatenation
    // This way getting all the signed scripts just means getting all the
    // properties of the response._cspSignedScripts object
    function getSignedScripts(res) {
        if (!res._cspSignedScripts) {
            Object.defineProperty(res, '_cspSignedScripts', {
                value: Object.create(appSignedScripts)
            });
        }
        return res._cspSignedScripts;
    }

    // Signed styles are stored as keys in an object to take advantage of
    // prototypical inheritance instead of relying on array concatenation
    // This way getting all the signed styles just means getting all the
    // properties of the response._cspSignedStyles object
    function getSignedStyles(res) {
        if (!res._cspSignedStyles) {
            Object.defineProperty(res, '_cspSignedStyles', {
                value: Object.create(appSignedStyles)
            });
        }
        return res._cspSignedStyles;
    }

    //Deep copy of data structure to prevent future mutations which could
    //cause an unintentional change to the headers.
    //Checking for nonce sources at the app level. Nonces should not be
    //explicitly set at app creation. Nonces should be randomly generated
    //per request. If you need to use a nonce for inline scripts, set the
    //`useScriptNonce`  or `useStyleNonce` value to true.
    function getCSPPolicies(config) {
        var policy,
            reportPolicy;
        if (config.policy) {
            policy = Object.freeze({
                useScriptNonce: config.policy.useScriptNonce || false,
                useStyleNonce: config.policy.useStyleNonce || false,
                directives: config.policy.directives ? getDirectives(config.policy.directives) : null
            });
        }
        if (config.reportPolicy) {
            reportPolicy = Object.freeze({
                useScriptNonce: config.reportPolicy.useScriptNonce || false,
                useStyleNonce: config.reportPolicy.useStyleNonce || false,
                directives: config.reportPolicy.directives ? getDirectives(config.reportPolicy.directives) : null
            });
        }
        return Object.freeze({
            policy: policy,
            reportPolicy: reportPolicy
        });
    }

    function getDirectives(config) {
        var directives = {};
        VALID_DIRECTIVES.forEach(function (directiveName) {
            if (Array.isArray(config[directiveName])) {
                directives[directiveName] = config[directiveName].filter(function (rule) {
                    //If cspPolicies have been defined, no app level directives can be set
                    //i.e. this is a request and it is safe to allow the developer to specify
                    //a nonce
                    if (cspPolicies || rule.replace(/\'/, '').indexOf('nonce-') !== 0) {
                        return true;
                    }
                    throw new Error('You cannot explicitly set a nonce at the app level. If you want to use a nonce, set `useScriptNonce` or `useStyleNonce` to true in the config object.');
                })
                .map(function (rule) {
                    if(TOKEN_RE.test(rule)) {
                        rule = '\'' + rule + '\'';
                    }
                    return rule;
                });
                Object.freeze(directives[directiveName]);
            }
        });
        return Object.freeze(directives);
    }

    function setNonce(res, appPolicies, appReportPolicies, callback) {
        if ((appPolicies && (appPolicies.useScriptNonce || appPolicies.useStyleNonce)) ||
            (appReportPolicies && (appReportPolicies.useScriptNonce || appReportPolicies.useStyleNonce))) {
            // Using base64 encoding, assuming the character set is the one defined
            // in http://en.wikipedia.org/wiki/Base64#Examples. This should base a
            // safe value for HTML attributes and HTTP headers.
            createToken(36, 'base64', function (err, token) {
                if (err) {
                    return callback(err);
                }
                try {
                    Object.defineProperty(res.locals, 'cspToken', {
                        value: token,
                        enumerable: true
                    });
                    callback(null, res);
                } catch(e) {
                    callback(new Error('Unable to set the nonce token to res.locals.'));
                }
            });
        } else {
            callback(null, res);
        }
    }

    // middleware
    app.use(function (req, res, next) {
        setNonce(res, cspPolicies.policy, cspPolicies.reportPolicy, function(err, res) {
            if (err) {
                next(err);    
            }
            setHeaders(res);
            next();
        });
    });


    app.signScript = function (script) {
        appSignedScripts[sign(script)] = true;
    };

    app.response.signScript = function (script) {
        var scripts = getSignedScripts(this);
        scripts[sign(script)] = true;
        setHeaders(this);
    };

    app.signStyle = function (style) {
        appSignedStyles[sign(style)] = true;
    };

    app.response.signStyle = function (style) {
        var styles = getSignedStyles(this);
        styles[sign(style)] = true;
        setHeaders(this);
    };

    app.response.setPolicy = function (config) {
        Object.freeze(config);
        var policy = config.policy,
            reportPolicy = config.reportPolicy;
        try {
            Object.defineProperty(this.locals, "cspPolicies", {
                value: getCSPPolicies(config),
                enumerable: true
            });
        } catch(e) {
            throw new Error('The res.locals.cspPolicies value must only be set once per request and must always be set through the `setPolicy` method.');
        }
        if (this.locals.cspToken) {
            setHeaders(this);
        } else {
            setNonce(this, policy, reportPolicy, function(err, res) {
                if (err) {
                    throw err;    
                }
                setHeaders(res);
            });
        }
    };

    function createToken(length, encoding, callback) {
        return crypto.pseudoRandomBytes(length, function(err, token) {
            if (err) {
                callback(err);
            } else {
                callback(null, token.toString(encoding));
            }
        });
    }
};
