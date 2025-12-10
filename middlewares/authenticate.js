import * as AuthTokens from '../services/authTokens.js';

export default function authenticate(req, res, next) {
    const authToken = req.cookies?.authToken;
    req.authUser = authToken ? AuthTokens.get(authToken) : null;
    next();
}
