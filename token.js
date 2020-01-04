const crypto = require('crypto');

class Token {
    static fromEvent(event, realmPublicKey, clientId) {
        const header = event.extensions.request.headers.authorization;

        if (header) {
            if (header.indexOf('bearer ') === 0 || header.indexOf('Bearer ') === 0) {
                return new Token(header.substring(7), realmPublicKey, clientId);
            }
        }

        return new Token();
    }

    constructor(token, realmPublicKey, clientId) {
        this.rolePrefix = 'role_';
        this.publicKey = realmPublicKey;
        this.notBefore = 0;
        this.clientId = clientId;
        this.content = {
            exp: 0,
            realm_access: {
                roles: [],
            },
            resource_access: {
                [this.clientId]: {
                    roles: [],
                },
            },
        };
        this.token = token;

        if (token) {
            try {
                const parts = token.split('.');
                this.header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
                this.signature = Buffer.from(parts[2], 'base64');
                this.signed = parts[0] + '.' + parts[1];
                this.content = JSON.parse(Buffer.from(parts[1], 'base64').toString());
            } catch (err) {

            }
        }
    }

    get userId() {
        return this.content.sub;
    }

    get roles() {
        const combined = [
            ...new Set([
                ...this.content.resource_access[this.clientId].roles,
                ...this.content.realm_access.roles,
            ]),
        ];
        return combined
            .filter(elem => elem.startsWith(this.rolePrefix));
    }

    get role() {
        return this.content.realm_access.roles
            .filter(elem => elem.startsWith(this.rolePrefix))[0];
    }

    get isExpired() {
        return ((this.content.exp * 1000) < Date.now());
    }

    validate() {
        if (!this.token) {
            throw new Error('invalid token (missing)');
        }

        if (this.isExpired) {
            throw new Error('invalid token (expired)');
        }

        if (!this.signed) {
            throw new Error('invalid token (not signed)');
        }

        if (this.content.typ !== 'Bearer') {
            throw new Error('invalid token (wrong type)');
        }

        if (this.content.iat < this.notBefore) {
            throw new Error('invalid token (stale token)');
        }

        // TODO verify issuer (keycloak iss mismatch: internal dn vs. ip vs. external fqdn)
        // if (token.content.iss !== this.realmUrl) {
        //     throw new Error('invalid token (wrong ISS)');
        // }

        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(this.signed);
        if (!verify.verify(this.publicKey, this.signature)) {
            throw new Error('invalid token (signature)');
        }
    }
}

module.exports = {
    Token: Token
};
