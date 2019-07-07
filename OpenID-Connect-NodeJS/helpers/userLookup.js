'use strict';

var configManager = new (require('./configManager.js'))(),
    jwt = require('jwt-simple'),
    _ = require('lodash');

var UserLookup = function () {
};

//this function handles the "login" part where the user actually performs a login procedure, this function should tell if the info the user has provided is accurate
UserLookup.prototype.validate = function (req, callback) {

    // code to query user data should go there

    req.model.user.findOne({identifier: req.body.identifier}, function (err, user) {
        if (!err && user && user.samePassword(req.body.password)) {
            return callback(null, user);
        } else {
            var error = new Error('Identifiant ou mot de passe incorrect.');
            return callback(error);
        }
    });
};

//this function allows to format the user info to what the app needs and / or wants to send to the client
UserLookup.prototype.buildAndSendUserInfo = function (req, res, decryptedIdTokenObject, access) {
    //code needed to build the user information to send back when the userInfo endpoint is called
    req.model.user.findOne({id: decryptedIdTokenObject.sub}, function (err, user) {
        var pivotIdentityMembers = {
            'given_name': true,
            'family_name': true,
            'birthdate': true,
            'gender': true,
            'birthplace': true,
            'birthdepartment': true,
            'birthcountry': true,
            'preferred_username': true
        };

        if (configManager.isModeAgents()) {
            pivotIdentityMembers.siren = true;
            pivotIdentityMembers.email = true;
            pivotIdentityMembers.usual_name = true,
            pivotIdentityMembers.organizational_unit = true,
            pivotIdentityMembers.identity_provider = true
        }

        if (req.check.scopes.indexOf('email') !== -1) {

            pivotIdentityMembers.email = true;
        }
        if (req.check.scopes.indexOf('address') !== -1) {
            pivotIdentityMembers.address = true;
        }
        if (req.check.scopes.indexOf('phone') !== -1) {
            pivotIdentityMembers.phone_number = true;
        }
        if (configManager.isAcrValuesActivated() && access.acr_values) {
            pivotIdentityMembers._claim_names = true;
            pivotIdentityMembers._claim_sources = true;
            req.model.client.findOne({id: access.client}, function (err, client) {
                var claim_sources_result = {};
                var claim_names_result = {};
                _.forEach(access.acr_values , function(acr_value) {
                    if(user[acr_value] !== undefined) {
                        claim_sources_result[acr_value] = user[acr_value];
                        claim_names_result[acr_value] = 'src1';
                    }
                });
                if (Object.keys(claim_sources_result).length > 0) {
                    user._claim_names = claim_names_result;
                    user._claim_sources = {src1: {JWT: jwt.encode(claim_sources_result, client.secret)}};
                }
                buildAndSetPivotIdentity(res, user, pivotIdentityMembers);
            });
        } else {
            buildAndSetPivotIdentity(res, user, pivotIdentityMembers);
        }
    });
};

function buildAndSetPivotIdentity(res, user, pivotIdentityMembers) {
    var pivotIdentity = {};
    pivotIdentity.sub = user.id;
    for (var member in pivotIdentityMembers) {
        if (pivotIdentityMembers.hasOwnProperty(member) && user.hasOwnProperty(member)) {
            pivotIdentity[member] = user[member];
        }
    }

    if (configManager.isModeAgents() || pivotIdentity.given_name) {
        res.json(pivotIdentity);
    } else {
        res.status(400).send();
    }
}

module.exports = UserLookup;
