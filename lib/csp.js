/*
 * Copyright (c) 2015, Yahoo Inc. All rights reserved.
 * Copyrights licensed under the New BSD License.
 * See the accompanying LICENSE file for terms.
 */

'use strict';

module.exports = CSP;

var LRU     = require('lru-cache');
var crypto  = require('crypto');
var TOKEN_RE = new RegExp([
    '(self|none|strict-dynamic|',
    'unsafe-inline|unsafe-eval|unsafe-hashed-attributes)',
    '(?!.)|(sha(256|384|512)-|nonce-)'
].join(''));

if (!Object.assign) {
    Object.assign = require('object-assign');
}

var SUPPORTED_DIRECTIVES = [
    'base-uri',
    'block-all-mixed-content',
    'child-src',
    'connect-src',
    'default-src',
    'font-src',
    'form-action',
    'frame-ancestors',
    'frame-src',
    'img-src',
    'media-src',
    'object-src',
    'plugin-types',
    'report-uri',
    'reflected-xss',
    'require-sri-for',
    'script-src',
    'style-src',
    'upgrade-insecure-requests',
    'worker-src',
    'manifest-src'
];

var freeze = Object.freeze;

function CSP (config) {
    config = Object.assign({}, config, {
        cacheSize: 50
    });

    this.scripts  = {};
    this.styles   = {};
    this.cache    = new LRU(config.cacheSize);
    this.policies = this.parseConfiguration(config);
}

CSP.prototype = {
    constructor: CSP,
    
    signScript: function (script) {
        this.scripts[this.sign(script)] = true;
    },

    signStyle: function (style) {
        this.styles[this.sign(style)] = true;
    },

    sign: function (key) {
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
    },

    /**
    * Parses an input object for CSP configurations object
    * for both `policy`, `reportPolicy` options.
    *
    * @method parseConfiguration
    * @param {Object} CSP Policy Configuration
    * @return {Object} Parsed CSP Result (immutable)
    */
    parseConfiguration: function (config) {
        var policy, reportPolicy;

        if (config.policy) {
            policy = freeze({
                useScriptNonce: !!config.policy.useScriptNonce,
                useStyleNonce:  !!config.policy.useStyleNonce,
                directives:     config.policy.directives ? this.getDirectives(config.policy.directives) : null
            });
        }

        if (config.reportPolicy) {
            reportPolicy = freeze({
                useScriptNonce: !!config.reportPolicy.useScriptNonce,
                useStyleNonce:  !!config.reportPolicy.useStyleNonce,
                directives:     config.reportPolicy.directives ? this.getDirectives(config.reportPolicy.directives) : null
            });
        }

        return freeze({
            policy:       policy,
            reportPolicy: reportPolicy
        });
    },

    getDirectives: function (config) {
        var directives = {};

        SUPPORTED_DIRECTIVES.forEach(function (directiveName) {
            if (Array.isArray(config[directiveName])) {
                directives[directiveName] = config[directiveName].filter(function (rule) {
                    //If policies have been defined, no app level directives can be set
                    //i.e. this is a request and it is safe to allow the developer to specify
                    //a nonce
                    if (this.policies || rule.replace(/\'/, '').indexOf('nonce-') !== 0) {
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
                freeze(directives[directiveName]);
            }
        }, this);

        return freeze(directives);
    },

    createNonceToken: function () {
        return crypto.pseudoRandomBytes(36).toString('base64');
    },

    getKeys: function (obj) {
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
    }
};
