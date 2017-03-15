/*global describe, it, specify*/
var express = require('express');
var expect  = require('chai').expect;
var request = require('supertest');
var csp     = require('../index');
var crypto  = require('crypto');
var path    = require('path');
var exphbs  = require('express-handlebars');

if (!Object.assign) {
    Object.assign = require('object-assign');
}

var appDefaults = {
    policy: {
        directives: {
            'script-src': [
                'https://*.yahoo.com',
                'https://*.syimg.com'
            ]
        }
    }
};

var allDirectives = {
    'base-uri'        : ['self'],
    'child-src'       : ['self', '*.ads.foo.com'],
    'connect-src'     : ['self', 'feeds.*.foo.com'],
    'default-src'     : ['self' ],
    'font-src'        : ['fonts.foo.com'],
    'form-action'     : ['self', '*.apis.baz.com'],
    'frame-ancestors' : ['self'],
    'img-src'         : ['self', '*.assets.foo.com', '*.images.foo.com'],
    'media-src'       : ['self', '*.content.foo.com', '*.videos.bar.com'],
    'object-src'      : ['none'],
    'plugin-types'    : ['application/pdf'],
    'report-uri'      : ['http://www.foo.com/report'],
    'script-src'      : ['self', '*.scripts.foo.com', '*.build.baz.com'],
    'style-src'       : ['self', 'styles.*.foo.com', '*.styles.bar.com']
};

function createApp(options) {
    var app = express();
    csp.extend(app, Object.assign({}, appDefaults, options || {}));

    app.route('/').get(function (req, res) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!DOCTYPE html><html><head><title>CSP test</title></head><body></body></html>');
    });

    return app;
}

function getCleanPolicies() {
    return {
        policy: {
            directives: {
                'script-src' : ['self', 'unsafe-inline'],
                'style-src'  : ['*.foo.com']
            }
        },
        reportPolicy: {
            directives: {
                'script-src' : ['self', 'unsafe-inline'],
                'style-src'  : ['*.foo.com']
            }
        }
    };
}

function testToEnsurePoliciesAreUnchanged(res) {
    //get clean copy of the setPolicy object
    var testPolicies = getCleanPolicies();
    Object.keys(testPolicies).forEach(function(policyType) {
        var cspHeader = policyType === 'reportPolicy' ? 'content-security-policy-report-only' : 'content-security-policy';
        var testPolicy = testPolicies[policyType];
        var testDirectiveKeys = Object.keys(testPolicy.directives);
        var policies = res.headers[cspHeader].split(';');
        //there should only be the a 'style-src' and 'script-src' directives
        expect(policies.length).to.equal(testDirectiveKeys.length);
        policies = policies.map(function(policy) {
            return policy.split(' ');
        });
        var directiveKeys = policies.map(function(policy) {
            return policy[0];
        });
        var directives = {};

        policies.forEach(function(policy) {
            directives[policy.shift()] = policy;
        });

        Object.keys(allDirectives).forEach(function(key) {
            if (testDirectiveKeys.indexOf(key) > -1) {
                var testDirective = testPolicy.directives[key];
                expect(directiveKeys.indexOf(key)).to.be.above(-1);
                testDirective.forEach(function(rule, dirIndex) {
                    expect(directives[key][dirIndex].replace(/\'/g, '')).to.equal(rule);
                });
            } else {
                expect(directiveKeys.indexOf(key)).to.equal(-1);
            }
        });
    });
}

function hash(str) {
    var h = crypto.createHash('sha256');
    h.update(str, 'utf8');
    return h.digest('base64');
}

describe('express-csp', function () {
    describe('as an Express extension', function () {
        var app = express();

        it('has an extend() function', function () {
            expect(csp).to.have.property('extend')
                .that.is.a('function');
        });

        it('sets a brand on the application', function () {
            csp.extend(app);

            expect(app).to.have.property('@csp')
                .that.equals(csp);
        });

        it('adds methods to sign scripts', function () {
            expect(app).to.have.property('signScript')
                .that.is.a('function');
        });

        it('is only applied once', function () {
            var method = app.signScript;
            csp.extend(app);
            expect(app.signScript).to.equal(method);
        });
    });

    describe('an extended application', function () {
        var app = createApp();

        it('sends basic CSP headers', function (done) {
            request(app).get('/')
                .expect(function (res) {
                    expect(res.headers).to.have.property('content-security-policy');
                })
                .end(done);
        });

        it('does not do anything without configuration', function (done) {
            var emptyApp = express();
            csp.extend(emptyApp, {});

            emptyApp.route('/').get(function (req, res) {
                res.writeHead(200, {
                    'Content-Type': 'text/html'
                });
                res.end('<!DOCTYPE html><html><head><title>CSP test</title></head><body></body></html>');
            });

            request(emptyApp).get('/')
                .expect(function (res) {
                    if (res.headers['content-security-policy']) {
                        return 'Unexpected CSP header: ' + res.headers['content-security-policy'];
                    }
                })
                .end(done);
        });
    });

    describe('signs scripts and styles correctly', function () {
        var app = createApp();
        var script1 = 'foo()';
        var script2 = 'bar();';
        var style1 = 'body{background:#fff}';
        var style2 = 'body{border:1px solid #000}';
        var style3 = 'p{background:#911d21}';

        var script2hash = hash(script2);
        var style2hash = hash(style2);

        app.signScript(script1);
        app.signStyle(style1);
        app.signStyle(style3);

        app.route('/foo').get(function (req, res) {
            expect(res).to.have.property('signScript')
                .that.is.a('function');

            res.signScript(script2);

            res.writeHead(200, {
                'Content-Type': 'text/html'
            });
            res.end('<!DOCTYPE html><html><head><title>CSP test bar</title></head><body></body></html>');
        });

        app.route('/baz').get(function (req, res) {
            res.signStyle(style2);

            res.writeHead(200, {
                'Content-Type': 'text/html'
            });
            res.end('<!DOCTYPE html><html><head><title>CSP test bar</title></head><body></body></html>');
        });

        specify('for application shared scripts', function (done) {
            request(app).get('/')
                .expect(function (res) {
                    var policies = res.headers['content-security-policy'].split(';');
                    var hashedScripts = policies.filter(function (policy) {
                        return policy.split(' ')[0] === 'script-src';
                    });

                    hashedScripts = hashedScripts[0].split(' ').slice(3);
                    expect(hashedScripts.length).to.equal(1);
                    expect(hashedScripts).to.contain('\'' + 'sha256-' + hash(script1) + '\'');
                })
                .end(done);
        });
        
        specify('for application shared styles', function (done) {
            request(app).get('/')
                .expect(function (res) {
                    var policies = res.headers['content-security-policy'].split(';');
                    var hashedStyles = policies.filter(function (policy) {
                        return policy.split(' ')[0] === 'style-src';
                    });

                    hashedStyles = hashedStyles[0].split(' ').slice(1);
                    expect(hashedStyles.length).to.equal(2);
                    expect(hashedStyles).to.contain('\'' + 'sha256-' + hash(style1) + '\'');
                })
                .end(done);
        });

        specify('for route specific scripts', function (done) {
            request(app).get('/foo')
                .expect(function (res) {
                    var policies = res.headers['content-security-policy'].split(';');
                    var hashedScripts = policies.filter(function (policy) {
                        return policy.split(' ')[0] === 'script-src';
                    });

                    expect(hashedScripts.length).to.equal(1);

                    hashedScripts = hashedScripts[0].split(' ').slice(3);

                    expect(hashedScripts).to.contain('\'' + 'sha256-' + script2hash + '\'');
                    expect(hashedScripts.length).to.equal(2);
                })
                .end(done);
        });

        specify('for route specific styles', function (done) {
            request(app).get('/baz')
                .expect(function (res) {
                    var policies = res.headers['content-security-policy'].split(';');
                    var hashedStyles = policies.filter(function (policy) {
                        return policy.split(' ')[0] === 'style-src';
                    });

                    expect(hashedStyles.length).to.equal(1);

                    hashedStyles = hashedStyles[0].split(' ').slice(1);

                    expect(hashedStyles).to.contain('\'' + 'sha256-' + style2hash + '\'');
                    expect(hashedStyles.length).to.equal(3);
                })
                .end(done);
        });

        specify('always uses the same signature for the same script', function (done) {
            app.route('/bar').get(function (req, res) {
                res.signScript(script2);
                res.signScript(script2);

                res.writeHead(200, {
                    'Content-Type': 'text/html'
                });
                res.end('<!DOCTYPE html><html><head><title>CSP test bar</title></head><body></body></html>');
            });

            request(app).get('/bar')
                .expect(function (res) {
                    var policies = res.headers['content-security-policy'].split(';');
                    var hashedScripts = policies.filter(function (policy) {
                        return policy.split(' ')[0] === 'script-src';
                    });

                    expect(hashedScripts.length).to.equal(1);

                    hashedScripts = hashedScripts[0].split(' ').slice(3);

                    expect(hashedScripts).to.contain('\'' + 'sha256-' + script2hash + '\'');
                    expect(hashedScripts.length).to.equal(2);
                })
                .end(done);
        });
    });
    
    describe('directives get set', function () {
        var app = createApp({
                policy: {
                    directives: allDirectives
                },
                reportPolicy: {
                    directives: allDirectives
                }
            });
       
        Object.keys(allDirectives).forEach(function(directive, index) {
            it(directive + ' directive is in the  `content-security-policy` header', function(done) {
                request(app).get('/')
                    .expect(function (res) {
                        var policies = res.headers['content-security-policy'].split(';'),
                            policy = policies[index].split(' ');
                        expect(policy.shift()).to.equal(directive);
                        policy.forEach(function(rule, ruleIndex) {
                            expect(rule.replace(/\'/g, '')).to.equal(allDirectives[directive][ruleIndex]);
                        });
                    }).end(done);
            });
            
            it(directive + ' report directive is in the `content-security-policy-report-only` header', function(done) {
                request(app).get('/')
                    .expect(function (res) {
                        var policies = res.headers['content-security-policy-report-only'].split(';'),
                            policy = policies[index].split(' ');
                        expect(policy.shift()).to.equal(directive);
                        policy.forEach(function(rule, ruleIndex) {
                            expect(rule.replace(/\'/g, '')).to.equal(allDirectives[directive][ruleIndex]);
                        });
                    }).end(done);
            });
        });
    });
    
    describe('csp polices cannot be altered after they are set', function() {
        var cspPolicies = getCleanPolicies();
        var app = createApp(cspPolicies);

        Object.keys(cspPolicies).forEach(function(policyType) {
            cspPolicies[policyType].useScriptNonce = true;
            cspPolicies[policyType].useStyleNonce = true;
            cspPolicies[policyType].directives['default-src'] = ['*'];
            cspPolicies[policyType].directives['script-src'] = ['*'];
            cspPolicies[policyType].directives['style-src'].push('*');
            cspPolicies[policyType].directives['report-uri'] = ['http://reports.nefarious.com/reports'];
        });

        app.route('/foo').get(function (req, res) {
            res.writeHead(200, {
                'Content-Type': 'text/html'
            });
            res.end('<!DOCTYPE html><html><head><title>CSP test bar</title></head><body></body></html>');
        });
        
        it('the csp policies are unaffected by changing the original value', function(done) {
            request(app).get('/foo')
                .expect(testToEnsurePoliciesAreUnchanged)
                .end(done);
        });
        
    });
    

    describe('directives are quoted properly', function () {
        var app = createApp({
                policy: {
                    directives: allDirectives
                },
                reportPolicy: {
                    directives: allDirectives
                }
            });

        specify('for none', function (done) {
            request(app).get('/')
                .expect(function (res) {
                    var policies = res.headers['content-security-policy'].split(';');
                    var hashedScripts = policies.filter(function (policy) {
                        return policy.split(' ')[0] === 'object-src';
                    });

                    hashedScripts = hashedScripts[0].split(' ').slice(1);
                    expect(hashedScripts.length).to.equal(1);
                    expect(hashedScripts).to.contain('\'none\'');
                })
                .end(done);
        });
    });

    describe('nonce token middleware', function () {
        var app;
        function setupApp(app) {
            app.set('views', path.join(__dirname, 'fixtures/views/'));
            app.engine('handlebars', exphbs({
                defaultLayout: 'main',
                layoutsDir: path.join(app.get('views'), 'layouts/')
            }));
            app.set('view engine', 'handlebars');

            app.get('/bar', function (req, res) {
                res.render('test');
            });

            return app;
        }

        it('includes the token in res.locals when it already has script-src rules', function (done) {
            app = setupApp(createApp({
                policy: {
                    useScriptNonce: true
                }
            }));
            request(app).get('/bar')
                .expect(function (res) {
                    var token = res.text.trim();
                    expect(token.length).to.be.above(0);

                    var policy = res.headers['content-security-policy'].split(';')
                        .filter(function (policy) {
                            return policy.substr(0, 'script-src '.length) ===
                                'script-src ';
                        })[0];
                    
                    policy = policy.split(' ').slice(1);

                    var nonce = policy.filter(function (rule) {
                        return rule.replace(/\'/g, '').substr(0, 'nonce-'.length) === 'nonce-';
                    })[0].replace(/\'/g, '').substr('nonce-'.length);
    
                    expect(token.length).to.equal(nonce.length);
                    expect(token).to.equal(nonce);
                })
                .end(done);
        });

        it('includes the token in res.locals when it does not already has script-src rules', function (done) {
            app = setupApp(createApp({
                policy: {
                    useScriptNonce: true,
                    directives: {
                        'style-src': ['*']
                    }
                }
            }));
            request(app).get('/bar')
                .expect(function (res) {
                    var token = res.text.trim();
                    expect(token.length).to.be.above(0);
                    
                    var policy = res.headers['content-security-policy'].split(';')
                        .filter(function (policy) {
                            return policy.substr(0, 'script-src '.length) ===
                                'script-src ';
                        })[0];
                    policy = policy.split(' ').slice(1);

                    var nonce = policy.filter(function (rule) {
                        return rule.replace(/\'/g, '').substr(0, 'nonce-'.length) === 'nonce-';
                    })[0].replace(/\'/g, '').substr('nonce-'.length);
                    
                    expect(token.length).to.equal(nonce.length);
                    expect(token).to.equal(nonce);
                })
                .end(done);
        });

        it('includes a token when set in the config', function(done) {
            app = setupApp(createApp({
                policy: {
                    useScriptNonce: true          
                }
            }));
            request(app).get('/bar')
                .expect(function (res) {
                    var token = res.text.trim();
                    expect(token.length).to.be.above(0);

                    var policy = res.headers['content-security-policy'].split(';')
                        .filter(function (policy) {
                            return policy.substr(0, 'script-src '.length) ===
                                'script-src ';
                        })[0];

                    policy = policy.split(' ').slice(1);

                    var nonce = policy.filter(function (rule) {
                        return rule.replace(/\'/g, '').substr(0, 'nonce-'.length) === 'nonce-';
                    })[0].replace(/\'/g, '').substr('nonce-'.length);

                    expect(token.length).to.equal(nonce.length);
                    expect(token).to.equal(nonce);

                })
                .end(done);
        });

        it('includes only one token in the header for each request', function(done) {
            request(app).get('/bar')
                .expect(function (res) {
                        var policy = res.headers['content-security-policy'].split(';')
                            .filter(function (policy) {
                                return policy.substr(0, 'script-src '.length) ===
                                    'script-src ';
                            })[0];

                        policy = policy.split(' ').slice(1);

                        var nonce = policy.filter(function(rule) {
                            return rule.replace(/\'/g, '').indexOf('nonce-') === 0;
                        });
                        
                        expect(nonce.length).to.equal(1);
                })
                .end(done);
        });
    });
    
    describe('response.setPolicy', function () {
        var app = createApp({
            policy: {
                directives: allDirectives
            },
            reportPolicy: {
                directives: allDirectives
            }
        });

        var responsePolicies = getCleanPolicies();

        app.route('/baz').get(function (req, res) {
            res.setPolicy(responsePolicies);
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<!DOCTYPE html><html><head><title>CSP test bar</title></head><body></body></html>');
        });

        Object.keys(responsePolicies).forEach(function(policyType) {
            it('response ' + policyType + ' takes precedence over app level policy', function(done) {
                var cspHeader = policyType === 'reportPolicy' ? 'content-security-policy-report-only' : 'content-security-policy';
                request(app).get('/baz')
                    .expect(function (res) {
                        var policies = res.headers[cspHeader].split(';');
                        expect(policies.length).to.equal(2);
                        //allDirectives keys are in the same order as the VALID_DIRECTIVES array that is used in the
                        //app to construct policies.
                        Object.keys(allDirectives).filter(function(directive) {
                            return Object.keys(responsePolicies[policyType].directives).indexOf(directive) > -1;
                        }).forEach(function(item, index, arr) {
                            var policy = policies[index].split(' ');
                            var key = arr[index];
                            expect(policy.shift()).to.equal(key); 
                            policy.forEach(function(item, index) {
                                expect(item.replace(/\'/g, '')).to.equal(responsePolicies[policyType].directives[key][index]);
                            });
                        });
                    })
                    .end(done);
            });
        });

        app.route('/foo').get(function (req, res) {
            //set the response policy 
            res.setPolicy(responsePolicies);

            Object.keys(responsePolicies).forEach(function (policyType) {
                responsePolicies[policyType].useScriptNonce = true;
                responsePolicies[policyType].useStyleNonce = true;
                responsePolicies[policyType].directives['default-src'] = ['*'];
                responsePolicies[policyType].directives['script-src'] = ['*'];
                responsePolicies[policyType].directives['style-src'].push('*');
                responsePolicies[policyType].directives['report-uri'] = ['http://reports.nefarious.com/reports'];
            });

            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<!DOCTYPE html><html><head><title>CSP test bar</title></head><body></body></html>');
        });
        
        it('the cspPolicies set by response.setPolicy cannot be altered', function(done) {
            request(app).get('/foo')
                .expect(testToEnsurePoliciesAreUnchanged)
                .end(done);
        });

        app.route('/bar').get(function (req, res) {
            res.setPolicy(getCleanPolicies());

            Object.keys(responsePolicies).forEach(function(policyType) {
                    res.locals.cspPolicies[policyType].useScriptNonce = true;
                    res.locals.cspPolicies[policyType].useStyleNonce = true;
                    res.locals.cspPolicies[policyType].directives['default-src'] = ['*'];
                    res.locals.cspPolicies[policyType].directives['script-src'] = ['*'];

                    //attempting to update an immutable array should throw an error 
                    try {
                        res.locals.cspPolicies[policyType].directives['style-src'].push('*');
                    } catch(e) {
                    }
                    res.locals.cspPolicies[policyType].directives['report-uri'] = ['http://reports.nefarious.com/reports'];
            });

            // signing a script will force the headers to be reset
            res.signScript('console.log("bar");');

            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<!DOCTYPE html><html><head><title>CSP test bar</title></head><body></body></html>');
        });

        it('the cspPolicies set by response.setPolicy cannot be changed by altering res.locals.cspPolicies', function(done) {
            request(app).get('/bar')
                .expect(testToEnsurePoliciesAreUnchanged)
                .end(done);
        });
    });

    describe('manually set nonces and shas', function() {
        var policies = getCleanPolicies(),
            sha = 'sha256-' + hash('console.log("I am safe");'),
            app;
        policies.policy.directives['script-src'].push(sha);    
        app  = createApp(policies);
        
        app.route('/').get(function (req, res) {
            res.writeHead(200, {
                'Content-Type': 'text/html'
            });
            res.end('<!DOCTYPE html><html><head><title>Manual nonce and sha test</title></head><body></body></html>');
        });
        
        it('shas can be manually set at the app level', function(done) {
            request(app).get('/')
                .expect(function(res) {
                    var policies = res.headers['content-security-policy'].split(';');
                    var scriptRules = policies.filter(function (policy) {
                        return policy.split(' ')[0] === 'script-src';
                    })[0].split(' ');
                    expect(scriptRules).to.contain('\'' + sha + '\'');
                })
                .end(done);
        });

        it('shas and nonces can be manually set at the response level', function(done) {
            var policies = getCleanPolicies(),
                nonce = 'nonce-foo1bar2baz3';
            app.route('/foo').get(function (req, res) {
                policies.policy.directives['script-src'].push(sha);
                policies.policy.directives['script-src'].push(nonce);
                res.setPolicy(policies);
                res.writeHead(200, {
                    'Content-Type': 'text/html'
                });
                res.end('<!DOCTYPE html><html><head><title>Manual nonce and sha test</title></head><body></body></html>');
            });
            request(app).get('/foo')
                .expect(function(res) {
                    var policies = res.headers['content-security-policy'].split(';');
                    var scriptRules = policies.filter(function (policy) {
                        return policy.split(' ')[0] === 'script-src';
                    })[0].split(' ');
                    expect(scriptRules).to.contain('\'' + sha + '\'');
                    expect(scriptRules).to.contain('\'' + nonce + '\'');
                })
                .end(done);

        });

        it('an error is thrown when a nonce is manually set at the app level', function() {
            var policies = getCleanPolicies(),
                nonce = 'nonce-foo1bar2baz3',
                app,
                error;
            policies.policy.directives['script-src'].push(nonce);
            try {
                app = createApp(policies);    
            } catch(e) {
                error = e;
            } 
            expect(error).to.not.be.an('undefined');
            expect(error.message).to.not.be.an('undefined');
            expect(error.message).to.equal("You cannot explicitly set a nonce at the app level. If you want to use a nonce, set `useScriptNonce` or `useStyleNonce` to true in the config object.");
        });

    });
});
