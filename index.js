'use strict';

const Token = require('./token');

const realmPublicKey = `-----BEGIN PUBLIC KEY-----
poc_realm_public_key
-----END PUBLIC KEY-----`;

const clientId = 'poc_frontend';

module.exports.auth = (event) => {
    try {
        const token = Token.fromEvent(event, realmPublicKey, clientId);

        token.validate();

        const grant = {
            'X-Hasura-User-Id': token.userId,
            // default role
            'X-Hasura-Role': token.role,
            // all roles
            'X-Hasura-Realm-Role': token.roles.join(', '),
        };

        console.log('Token validated: %o', grant);

        return grant;
    } catch (e) {
        console.log(e);

        return {
            'X-Hasura-Role': 'anonymous',
        }
    }
};
