const jwt = require('jsonwebtoken');
const { AuthorizationError } = require('./../errors');

function assertJWToken(token) {
  if (!token) {
    throw new AuthorizationError({
      message: 'You must supply a JWT for authorization!'
    });
  }
  try {
    return jwt.verify(
      token.replace('Bearer ', ''),
      process.env.JWT_SECRET
    );
  } catch (err) {
    throw new AuthorizationError({
      message: 'You are not authorized.'
    });
  }
}

function assertScopes(JWTObj, expectedScopes) {
  const scopes = JWTObj.scope;
  if (!scopes) {
    throw new AuthorizationError({ message: 'No scopes supplied!' });
  }
  if (expectedScopes && expectedScopes.some(scope => scopes.indexOf(scope) === -1)) {
    throw new AuthorizationError({
      message: `You are not authorized. Expected scopes: ${expectedScopes.join(', ')}`,
    });
  }
  return true;
}

function signJWToken(tokenObject) {
  return jwt.sign(tokenObject, process.env.JWT_SECRET);
}

module.exports = { assertJWToken, assertScopes, signJWToken };
