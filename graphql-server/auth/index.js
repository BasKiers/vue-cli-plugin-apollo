const jwt = require('jsonwebtoken');
const { AuthorizationError } = require('./../errors');
const { directiveTypeDefs } = require('./../directives');

console.log(directiveTypeDefs);

const ROLES = directiveTypeDefs.definitions
  .find(definition => definition.kind === 'EnumTypeDefinition' && definition.name.value === 'Role')
  .values
  .map(value => value.name.value);

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

function assertRole(JWTObj, expectedRole) {
  if (typeof JWTObj === 'string') {
    JWTObj = assertJWToken(token);
  }
  const role = JWTObj.role;
  if (!role) {
    throw new AuthorizationError({ message: 'No role supplied!' });
  }
  if (ROLES.indexOf(role) < 0 || ROLES.indexOf(expectedRole)) {
    throw new AuthorizationError({ message: 'Invalid role supplied!' });
  }
  if (expectedRole && ROLES.indexOf(expectedRole) > ROLES.indexOf(role)) {
    throw new AuthorizationError({
      message: `You are not authorized. Expected role: ${expectedRole}`,
    });
  }
  return true;
}

function assertScope(JWTObj, expectedScopes) {
  if (typeof JWTObj === 'string') {
    JWTObj = assertJWToken(token);
  }
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

module.exports = { assertJWToken, assertRole, assertScope, signJWToken };
