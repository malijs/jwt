# @malijs/jwt

Mali JWT authentication middleware.

[![npm version](https://img.shields.io/npm/v/@malijs/jwt.svg?style=flat-square)](https://www.npmjs.com/package/@malijs/jwt)
[![build status](https://github.com/malijs/jwt/workflows/Node%20CI/badge.svg)](https://github.com/malijs/jwt/actions)

[Mali](https://github.com/malijs/mali) middleware that validates JSON Web Tokens and sets `ctx.user`
(by default) if a valid token is provided.

## Install

```
$ npm install @malijs/jwt
```

## Usage

The JWT authentication middleware authenticates callers using a JWT
token. If the token is valid, `ctx.user` (by default) will be set
with the JSON object decoded to be used by later middleware for
authorization and access control.

### Retrieving the token

The token is normally provided in call metadata `Authorization` property
using `bearer` scheme; but custom token retrieval can also be done through the
`getToken` option. The provided function should match the following interface:

```js
/**
 * Your custom token resolver
 * @this The ctx object passed to the middleware
 *
 * @param  {object}      opts The middleware's options
 * @return {String|null}      The resolved token or null if not found
 */
```

The resolution order for the token is the following. The first non-empty token resolved will be the one that is verified.
 - `opts.getToken` function
 - check the Authorization metadata property for a bearer token

### Passing the secret

Normally you provide a single shared secret in `opts.secret`, but another
alternative is to have an earlier middleware set `ctx.secret`,
typically per request. If this property exists, it will be used instead
of the one in `opts.secret`.

### Checking if the token is revoked

using `isRevoked` option you can provide a async function to jwt for it check
the token is revoked. The provided function should match the following interface:

```js
/**
 * Your custom isRevoked resolver
 *
 * @param  {object}      ctx The ctx object passed to the middleware
 * @param  {object}      token token The token
 * @param  {object}      user Content of the token
 * @return {Promise}     If the token is not revoked, the promise must resolve with false, otherwise (the promise resolve with false or error) the token is revoked
 */
```

## Options

* `key` - the path to set decoded JSON object into `ctx`. Default: `user`.
* `secretPath` - the path within `ctx` to look for the secret. If not present at path uses `opts.secret`. Default: `secret`. If the resulting value in the property is a function, it will be evaluated. Supports async functions.
* `isRevoked` - Async function for checking if token is revoked.
* `getToken` - Optional function for getting token. Can be async.
* `tokenPath` - Optional path for to place token within `ctx`.

## Example

```js
// Middleware below this line is only reached if JWT token is valid
app.use(jwt({ secret: 'shared-secret' }))

// Protected middleware
app.use(function (ctx, next) {
  console.log(ctx.user) // the decoded JSON data
  return next()
})
```

```js
// Middleware below this line is only reached if JWT token is valid
app.use(jwt({
  secret: 'shared-secret',
  tokenPath: 'token'
}))

// Protected middleware
app.use(function (ctx, next) {
  console.log(ctx.user) // the decoded JSON data
  console.log(ctx.token) // the token
  return next()
})
```

```js
// Get the token using a custom getToken function
app.use(jwt({
  getToken: ctx => ctx.req.token,
  tokenPath: 'state.token',
  key: 'state.user'
}))

// Protected middleware
app.use(function(ctx, next) {
  console.log(ctx.state.user) // the decoded JSON data
  console.log(ctx.state.token) // the token
  return next()
})
```

## Credits

Based on [koa-jwt](https://github.com/koajs/jwt)

## License

Apache 2.0
