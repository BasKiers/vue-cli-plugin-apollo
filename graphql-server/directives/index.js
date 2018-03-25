const { forEachField } = require('graphql-tools');
const { getArgumentValues } = require('graphql/execution/values');
const { assertJWToken, assertScopes } = require('./../auth');

const directiveTypeDefs = `
  directive @isAuthenticated on QUERY | FIELD
  directive @hasScope(scope: [String]) on QUERY | FIELD
`;

const directiveResolvers = {
  isAuthenticated(result, source, args, context) {
    const token = context.headers.authorization;
    assertJWToken(token);
    return result;
  },
  hasScope(result, source, args, context) {
    const token = context.headers.authorization;
    const expectedScopes = args.scope;
    assertScopes(token, expectedScopes);

    return result;
  },
};

// Credit: agonbina https://github.com/apollographql/graphql-tools/issues/212
const attachDirectives = schema => {
  forEachField(schema, field => {
    const directives = field.astNode.directives;
    directives.forEach(directive => {
      const directiveName = directive.name.value;
      const resolver = directiveResolvers[directiveName];

      if (resolver) {
        const oldResolve = field.resolve;
        const Directive = schema.getDirective(directiveName);
        const args = getArgumentValues(Directive, directive);

        field.resolve = function () {
          const [source, _, context, info] = arguments;
          let promise = oldResolve.call(field, ...arguments);

          const isPrimitive = !(promise instanceof Promise);
          if (isPrimitive) {
            promise = Promise.resolve(promise);
          }

          return promise.then(result =>
            resolver(result, source, args, context, info)
          );
        };
      }
    });
  });
};

module.exports = { directiveResolvers, attachDirectives, directiveTypeDefs };