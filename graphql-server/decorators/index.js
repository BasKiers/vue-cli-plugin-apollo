const { assertJWToken, assertScopes } = require('./../auth');

const AssertAuth = () => {
  return (target, prop, descriptor, ...rest) => {
    const { value: originalFunc } = descriptor;
    descriptor.value = (root, args, context) => {
      if (!context.jwt) {
        const token = context.headers.authorization;
        context.jwt = assertJWToken(token);
      }
      return originalFunc(root, args, context, ...rest);
    };
    return descriptor;
  }
};

const AssertScopes = (scopes = []) => {
  return (target, prop, descriptor) => {
    const { value: originalFunc } = descriptor;
    descriptor.value = (root, args, context, ...rest) => {
      if (!context.jwt) {
        const token = context.headers.authorization;
        context.jwt = assertJWToken(token);
      }
      assertScopes(context.jwt, scopes);
      return originalFunc(root, args, context, ...rest);
    };
    return descriptor;
  }
};

module.exports = { AssertAuth, AssertScopes };