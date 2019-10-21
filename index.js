const bearer = require('@malijs/bearer')
const pify = require('pify')
const { decode } = require('jsonwebtoken')
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

  return async function jwtMiddleware (ctx, next) {
    if (typeof opts.getToken === 'function') {
      const token = await opts.getToken(ctx)
      if (token) {
        return jwtAction(token, ctx, next)
      }
    }

    const bearerAction = bearer(opts, jwtAction)
    return bearerAction(ctx, next)
  }

  async function jwtAction (token, ctx, next) {
    let secret = ''
    if (opts.secretPath) {
      secret = get(ctx, opts.secretPath, opts.secret)
    } else {
      secret = opts.secret
    }
    if (!secret) {
      throw new Error('Invalid secret')
    }

    if (typeof secret === 'function') {
      secret = await getSecret(secret, token)
    }

    return JWT.verify(token, secret, opts)
      .then(isRevoked(ctx, token))
      .then(user => {
        set(ctx, opts.key, user)
        if (opts.tokenPath) {
          set(ctx, opts.tokenPath, token)
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

async function getSecret (provider, token) {
  const decoded = decode(token, { complete: true })

  if (!decoded || !decoded.header) {
    throw new Error('Invalid token')
  }

  return provider(decoded.header, decoded.payload)
}

module.exports = jwt
