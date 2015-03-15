/*
 * Copyright (c) 2015, Yahoo Inc. All rights reserved.
 * Copyrights licensed under the New BSD License.
 * See the accompanying LICENSE file for terms.
 */

'use strict';

var CSP    = require('./lib/csp');

exports.extend = function (app, config) {
    if (app['@express-csp']) {
        return;
    }

    var csp = new CSP(config);

    Object.defineProperty(app, '@express-csp', {
        value: exports
    });

    app.signScript = function (script) {
        csp.signedScripts[csp.sign(script)] = true;
    };

    app.response.signScript = function (script) {
        var scripts = csp.getSignedScripts(this);
        scripts[csp.sign(script)] = true;
        csp.setContentSecurityHeaders(this);
    };

    app.signStyle = function (style) {
        csp.signedStyles[csp.sign(style)] = true;
    };

    app.response.signStyle = function (style) {
        var styles = csp.getSignedStyles(this);
        styles[csp.sign(style)] = true;
        csp.setContentSecurityHeaders(this);
    };

    app.response.setPolicy = function (config) {
        Object.freeze(config);

        var policy       = config.policy;
        var reportPolicy = config.reportPolicy;

        try {
            Object.defineProperty(this.locals, 'cspPolicies', {
                value: csp.getCSPPolicies(config),
                enumerable: true
            });
        } catch (ex) {
            throw new Error('The `res.locals.cspPolicies` value must only be set once per request and must always be set through the `setPolicy` method.');
        }

        if (this.locals.cspToken) {
            csp.setContentSecurityHeaders(this);
        } else {
            csp.setNonce(this, policy, reportPolicy, function (err, res) {
                if (err) {
                    throw err;
                }
                csp.setContentSecurityHeaders(res);
            });
        }
    };

    app.use(function (req, res, next) {
        csp.setNonce(res, csp.cspPolicies.policy, csp.cspPolicies.reportPolicy, function (err, res) {
            if (err) {
                return next(err);
            }
            csp.setContentSecurityHeaders(res);
            next();
        });
    });

    return app;
};
