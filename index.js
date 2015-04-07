/*
 * Copyright (c) 2015, Yahoo Inc. All rights reserved.
 * Copyrights licensed under the New BSD License.
 * See the accompanying LICENSE file for terms.
 */

'use strict';

var onHeaders = require('on-headers');
var CSP       = require('./lib/csp');

function policyBuilder (policy, signedScripts, signedStyles) {
    var hasSignedScripts = signedScripts.length > 0;
    var hasSignedStyles  = signedStyles.length > 0;
    var useScriptNonce   = !!policy.useScriptNonce;
    var useStyleNonce    = !!policy.useStyleNonce;
    var directives       = policy.directives || {};
    var nonce            = (useScriptNonce || useStyleNonce) ? '\'nonce-' + this.locals.cspToken + '\' ' : null;
    var directiveKeys    = Object.keys(directives);
    var typePolicy;

    if ((useScriptNonce || hasSignedScripts) && directiveKeys.indexOf('script-src') < 0) {
        directiveKeys.push('script-src');
    }

    if ((useStyleNonce || hasSignedStyles) && directiveKeys.indexOf('style-src') < 0) {
        directiveKeys.push('style-src');
    }

    return directiveKeys.map(function (type) {
        typePolicy = [type].concat(directives[type] || []);

        if ((useScriptNonce && type === 'script-src') || (useStyleNonce && type === 'style-src')) {
            typePolicy = typePolicy.concat(nonce);
        }

        if (type === 'script-src' && hasSignedScripts) {
            typePolicy = typePolicy.concat(signedScripts);
        }
        else if (type === 'style-src' && hasSignedStyles) {
            typePolicy = typePolicy.concat(signedStyles);
        }

        return typePolicy.join(' ');
    }).join(';');
}

exports.extend = function (app, config) {
    if (app['@csp']) { return app; }

    Object.defineProperty(app, '@csp', {
        value: exports
    });

    var csp = new CSP(config);

    function getSignedStyles (res) {
        if (!res._cspSignedStyles) {
            Object.defineProperty(res, '_cspSignedStyles', {
                value: Object.create(csp.styles)
            });
        }

        return res._cspSignedStyles;
    }

    function getSignedScripts (res) {
        if (!res._cspSignedScripts) {
            Object.defineProperty(res, '_cspSignedScripts', {
                value: Object.create(csp.scripts)
            });
        }

        return res._cspSignedScripts;
    }

    app.signScript = function (str) {
        csp.signScript(str);
    };

    app.signStyle = function (str) {
        csp.signStyle(str);
    };

    app.response.signScript = function (script) {
        var scripts = getSignedScripts(this);
        scripts[csp.sign(script)] = true;
    };

    app.response.signStyle = function (style) {
        var styles = getSignedStyles(this);
        styles[csp.sign(style)] = true;
    };

    app.response.setPolicy = function (config) {
        try {
            Object.defineProperty(this.locals, 'cspPolicies', {
                value:      csp.parseConfiguration(config),
                enumerable: true
            });
        } catch (ex) {
            throw new Error('The `response.locals.cspPolicies` value must only be set once per request and must always be set through the `setPolicy` method.');
        }
    };

    app.use(function (req, res, next) {
        var policy       = csp.policies.policy;
        var reportPolicy = csp.policies.reportPolicy;

        onHeaders(res, function () {
            var scriptKeys     = csp.getKeys(getSignedScripts(res));
            var styleKeys      = csp.getKeys(getSignedStyles(res));
            var localPolicies  = res.locals.cspPolicies;
            var policies       = localPolicies ? localPolicies.policy : policy;
            var reportPolicies = localPolicies ? localPolicies.reportPolicy : reportPolicy;
            var policyHeader, reportPolicyHeader;

            if (policies) {
                policyHeader = policyBuilder.call(res, policies, scriptKeys, styleKeys);
                res.setHeader('Content-Security-Policy', policyHeader);
            }

            if (reportPolicies) {
                reportPolicyHeader = policyBuilder.call(res, reportPolicies, scriptKeys, styleKeys);
                res.setHeader('Content-Security-Policy-Report-Only', reportPolicyHeader);
            }
        });

        /**
        * Generates a base64 encoded token and stores a nonce token on `res.locals.cspToken`.
        */
        if ((policy && (policy.useScriptNonce || policy.useStyleNonce)) ||
            (reportPolicy && (reportPolicy.useScriptNonce || reportPolicy.useStyleNonce))) {
            Object.defineProperty(res.locals, 'cspToken', {
                value:      csp.createNonceToken(),
                enumerable: true
            });
        }

        next();
    });

    return app;
};
