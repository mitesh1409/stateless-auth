import jwt from 'jsonwebtoken';

function set(payload) {
    return jwt.sign(payload, process.env.JWT_SECRET || 'SECRET-2025');
}

function get(token) {
    try {
        return jwt.verify(token, process.env.JWT_SECRET || 'SECRET-2025');
    } catch (err) {
        console.error('Failed to verify JWT token:', token);
        console.error(err);
        return null;
    }
}

export {
    set,
    get
};
