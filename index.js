const bearer = require('mali-bearer')
const pify = require('pify')
const JWT = pify(require('jsonwebtoken'))
const get = require('lodash.get')
const set = require('lodash.set')

function jwt (options) {
  const opts = options || {}
  opts.key = opts.key || 'user'
  opts.tokenKey = opts.tokenKey || 'token'
  opts.secretPath = opts.secretPath || 'secret'

  const identity = user => user
  const isRevoked = opts.isRevoked
    ? (ctx, token) => user => opts.isRevoked(ctx, user, token).then(revocationHandler(user))
    : () => identity

  function jwtMiddleware (ctx, next) {
    bearer(opts, (token, ctx, next) => {
      const secret = get(ctx, opts.secretPath, opts.secret)
      if (!secret) {
        throw new Error('Invalid secret')
      }

      return JWT.verify(token, secret, opts)
        .then(isRevoked(ctx, token))
        .then(user => {
          set(ctx, opts.key, user)
          set(ctx, opts.tokenKey, token)
        })
        .catch(e => {
          const msg = 'Invalid token' + (opts.debug
            ? ' - ' + e.message
            : '')
          throw new Error(msg)
        })
        .then(next)
    })
  }

  return jwtMiddleware
}

function revocationHandler (user) {
  return revoked => revoked
    ? Promise.reject(new Error('Revoked token'))
    : Promise.resolve(user)
}

module.exports = jwt
