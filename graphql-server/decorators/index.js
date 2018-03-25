const jwt = require('jsonwebtoken');
const { assertJWToken, assertScopes } = require('./../auth');

const CheckAuth = (context, controller) => {
  const token = context.headers.authorization;
  const jwtObj = assertJWToken(token);
  return controller(jwtObj);
};

const CheckScopes = (context,
  expectedScopes,
  controller,
  ...params) => {
  const token = context.headers.authorization;
  assertScopes(token, expectedScopes);

  return controller(params);
};

module.exports = { CheckAuth, CheckScopes };