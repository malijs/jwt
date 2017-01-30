const bearer = require('mali-bearer')
const pify = require('pify')
const JWT = pify(require('jsonwebtoken'))
const get = require('lodash.get')
const set = require('lodash.set')

function jwt (options) {
  const opts = options || {}
  opts.key = opts.key || 'user'
  opts.secretPath = opts.secretPath || 'secret'

  const identity = user => user
  const isRevoked = opts.isRevoked
    ? (ctx, token) => user => opts.isRevoked(ctx, user, token).then(revocationHandler(user))
    : () => identity

  return function jwtMiddleware (ctx, next) {
    if (typeof opts.getToken === 'function') {
      const token = opts.getToken(ctx)
      if (token) {
        return jwtAction(token, ctx, next)
      }
    }

    const bearerAction = bearer(opts, jwtAction)
    return bearerAction(ctx, next)
  }

  function jwtAction (token, ctx, next) {
    const secret = get(ctx, opts.secretPath, opts.secret)
    if (!secret) {
      throw new Error('Invalid secret')
    }

    return JWT.verify(token, secret, opts)
      .then(isRevoked(ctx, token))
      .then(user => {
        set(ctx, opts.key, user)
        if (opts.tokenKey) {
          set(ctx, opts.tokenKey, token)
        }
      })
      .catch(e => {
        const msg = 'Invalid token' + (opts.debug
          ? ' - ' + e.message
          : '')
        throw new Error(msg)
      })
      .then(next)
  }
}

function revocationHandler (user) {
  return revoked => revoked
    ? Promise.reject(new Error('Revoked token'))
    : Promise.resolve(user)
}

module.exports = jwt
