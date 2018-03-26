import { assertJWToken, assertScope, assertRole } from './../auth';

export const Auth = ({ role, scope }) => {
  return (target, prop, descriptor, ...rest) => {
    const { value: originalFunc } = descriptor;
    descriptor.value = (root, args, context) => {
      if (!context.jwt) {
        const token = context.headers.authorization;
        context.jwt = assertJWToken(token);
      }
      if (role) {
        assertRole(context.jwt, role);
      }
      if (scope) {
        assertScope(context.jwt, scope);
      }
      return originalFunc(root, args, context, ...rest);
    };
    return descriptor;
  }
};
