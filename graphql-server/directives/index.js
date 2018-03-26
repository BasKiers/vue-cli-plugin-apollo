import { assertJWToken, assertScope, assertRole, ROLES } from './../auth';
import gql from 'graphql-tag';
import { SchemaDirectiveVisitor, defaultFieldResolver } from 'graphql-tools';

export const directiveTypeDefs = `
  directive @auth(role: Role, scope: [String]) on OBJECT | FIELD_DEFINITION

  enum Role {
    ${ROLES.join('\n    ')}
  }
`;

class AuthDirective extends SchemaDirectiveVisitor {
	visitObject(type) {
		this.ensureFieldsWrapped(type);
		type._requiredAuth = true;
		type._requiredAuthRole = this.args.role;
		type._requiredAuthScope = this.args.scope;
	}

	// Visitor methods for nested types like fields and arguments
	// also receive a details object that provides information about
	// the parent and grandparent types.
	visitFieldDefinition(field, details) {
		this.ensureFieldsWrapped(details.objectType);
		field._requiredAuth = true;
		field._requiredAuthRole = this.args.role;
		field._requiredAuthScope = this.args.scope;
	}

	ensureFieldsWrapped(objectType) {
		// Mark the GraphQLObjectType object to avoid re-wrapping:
		if (objectType._authFieldsWrapped) return;
		objectType._authFieldsWrapped = true;

		const fields = objectType.getFields();

		Object.values(fields).forEach(field => {
			const { resolve = defaultFieldResolver } = field;
			field.resolve = async function (...args) {
				// Get the required Role from the field first, falling back
				// to the objectType if no Role is required by the field:
				const requiredAuth = field._requiredAuth || objectType._requiredAuth;
				const requiredRole = field._requiredAuthRole || objectType._requiredAuthRole;
				const requiredScope = field._requiredAuthScope || objectType._requiredAuthScope;

				if (!(requiredAuth || requiredRole || requiredScope)) {
					return resolve.apply(this, args);
				}

				const context = args[2];
				if (!context.jwt) {
					const token = context.headers.authorization;
					context.jwt = assertJWToken(token);
				}
				if (requiredRole) {
					assertRole(roles, context.jwt, requiredRole);
				}
				if (requiredScope) {
					assertScope(context.jwt, requiredScope);
				}

				return resolve.apply(this, args);
			};
		});
	}
}

export const schemaDirectives = {
	auth: AuthDirective,
};
