import test from 'ava'
import path from 'path'
import caller from 'grpc-caller'
import jwt from 'jsonwebtoken'

import Mali from 'mali'
import malijwt from '../'

function getRandomInt (min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

function getHostport (port) {
  return '0.0.0.0:'.concat(port || getRandomInt(1000, 60000))
}

const PROTO_PATH = path.resolve(__dirname, './jwt.proto')

function testCall (ctx) {
  ctx.res = {
    message: ctx.req.message,
    user: ctx.user
  }
}

test('should fail if no authorization metadata', async t => {
  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: 'shhhh' }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }))
  t.true(error.message.indexOf('Not Authorized') >= 0)
  await app.close()
})

test('should fail if authorization metadata is malformed', async t => {
  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: 'shhhh' }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'wrong' }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Not Authorized') >= 0)
  await app.close()
})

test('should allow provided getToken function to throw', async t => {
  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({
    secret: 'shhhh',
    getToken: ctx => { throw new Error('Bad Authorization') }
  }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'wrong' }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Bad Authorization') >= 0)
  await app.close()
})

test('should throw if getToken function returns invalid jwt', async t => {
  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({
    secret: 'shhhh',
    getToken: () => jwt.sign({ foo: 'bar' }, 'bad')
  }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'wrong' }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token') >= 0)
  await app.close()
})

test('should fail if authorization metadata not well-formatted jwt', async t => {
  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: 'shhhh' }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer wrongjwt' }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token') >= 0)
  await app.close()
})

test('should throw if authorization metadata is not valid jwt', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: 'different-shhhh', debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token - invalid signature') >= 0)
  await app.close()
})

test('should throw if audience is not expected', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar', aud: 'expected-audience' }, secret)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({
    secret: 'shhhhhh',
    audience: 'not-expected-audience',
    debug: true
  }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token - jwt audience invalid. expected: not-expected-audience') >= 0)
  await app.close()
})

test('should throw if token is expired', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar', exp: 1382412921 }, secret)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: 'shhhhhh', debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token - jwt expired') >= 0)
  await app.close()
})

test('should throw if token issuer is wrong', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar', iss: 'http://foo' }, secret)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: 'shhhhhh', issuer: 'http://wrong', debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token - jwt issuer invalid. expected: http://wrong') >= 0)
  await app.close()
})

test('should throw if secret neither provided by options or middleware', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar', iss: 'http://foo' }, secret)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid secret') >= 0)
  await app.close()
})

test('should throw if secret both provided by options (right secret) and middleware (wrong secret)', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar', iss: 'http://foo' }, secret)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: 'wrong secret', debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token - invalid signature') >= 0)
  await app.close()
})

test('should throw if isRevoked throwsAsync error', async t => {
  const isRevoked = (ctx, token, user) => Promise.reject(new Error('Revoked token'))
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret, isRevoked, debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token - Revoked token') >= 0)
  await app.close()
})

test('should throw if revoken token', async t => {
  const isRevoked = (ctx, token, user) => Promise.resolve(true)
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret, isRevoked, debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token - Revoked token') >= 0)
  await app.close()
})

test('should work if authorization metadata is valid jwt', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const response = await client.testCall({ message: 'hello' }, meta)
  t.is(response.message, 'hello')
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should work if the provided getToken function returns a valid jwt', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret, getToken: ctx => ctx.req.message }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const response = await client.testCall({ message: token })
  t.is(response.message, token)
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should use the first resolved token', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  const invalidToken = jwt.sign({ foo: 'bar' }, 'badSecret')

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret, getToken: ctx => ctx.req.message }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + invalidToken }
  const response = await client.testCall({ message: token }, meta)
  t.is(response.message, token)
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should use provided key for decoded data', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret, key: 'jwtdata' }))
  app.use('testCall', ctx => {
    ctx.res = {
      message: ctx.req.message,
      user: ctx.jwtdata
    }
  })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const response = await client.testCall({ message: 'hello' }, meta)
  t.is(response.message, 'hello')
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should use provided nested key for decoded data', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret, key: 'state.jwtdata' }))
  app.use('testCall', ctx => {
    ctx.res = {
      message: ctx.req.message,
      user: ctx.state.jwtdata
    }
  })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const response = await client.testCall({ message: 'hello' }, meta)
  t.is(response.message, 'hello')
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should work if secret is provided by middleware', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use((ctx, next) => {
    ctx.secret = secret
    return next()
  })
  app.use(malijwt())
  app.use('testCall', ctx => {
    ctx.res = {
      message: ctx.req.message,
      user: ctx.user
    }
  })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const response = await client.testCall({ message: 'hello' }, meta)
  t.is(response.message, 'hello')
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should not overwrite ctx.token on successful token verification if opts.tokenPath is undefined', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use((ctx, next) => {
    ctx.token = 'DONT_CLOBBER_ME'
    return next()
  })
  app.use(malijwt({ secret: secret, key: 'jwtdata' }))
  app.use('testCall', ctx => {
    ctx.res = {
      message: ctx.token,
      user: ctx.jwtdata
    }
  })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const response = await client.testCall({ message: 'hello' }, meta)
  t.is(response.message, 'DONT_CLOBBER_ME')
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should populate the raw token to ctx.token, and decoded data into ctx.user', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret }))
  app.use('testCall', ctx => {
    ctx.res = {
      message: ctx.token || '',
      user: ctx.user
    }
  })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const response = await client.testCall({ message: 'hello' }, meta)
  t.is(response.message, '')
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should populate the raw token to ctx.token, in key from opts.tokenPath', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret, key: 'jwtdata', tokenPath: 'testtokenPath' }))
  app.use('testCall', ctx => {
    ctx.res = {
      message: ctx.testtokenPath,
      user: ctx.jwtdata
    }
  })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const response = await client.testCall({ message: 'hello' }, meta)
  t.is(response.message, token)
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should populate the raw token to ctx, in nested key from opts.tokenPath', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: secret, key: 'state.jwtdata', tokenPath: 'state.testtokenPath' }))
  app.use('testCall', ctx => {
    ctx.res = {
      message: ctx.state.testtokenPath,
      user: ctx.state.jwtdata
    }
  })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const response = await client.testCall({ message: 'hello' }, meta)
  t.is(response.message, token)
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should use middleware secret if both middleware and options provided', async t => {
  const secret = 'shhhhhh'
  const token = jwt.sign({ foo: 'bar' }, secret)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use((ctx, next) => {
    ctx.secret = secret
    return next()
  })
  app.use(malijwt({ secret: 'wrong secret' }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const response = await client.testCall({ message: 'hello' }, meta)
  t.is(response.message, 'hello')
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should work with async getToken and secret functions', async t => {
  const secretValue = 'shhhhhh'
  const secret = async (header, payload) => Promise.resolve(secretValue)
  const getToken = async ctx => Promise.resolve(ctx.req.message)
  const token = jwt.sign({ foo: 'bar' }, secretValue)

  t.plan(4)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret, getToken }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const response = await client.testCall({ message: token })
  t.is(response.message, token)
  t.truthy(response.user)
  t.is(response.user.foo, 'bar')
  t.truthy(response.user.iat)
  await app.close()
})

test('should throw if secret provider throws', async t => {
  const secretValue = 'shhhhhh'
  const secret = async (header, payload) => Promise.reject(new Error('Not supported'))
  const token = jwt.sign({ foo: 'bar' }, secretValue)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret, debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Not supported') >= 0)
  await app.close()
})

test('should throw if secret provider used but token invalid', async t => {
  const secret = async (header, payload) => Promise.resolve('a nice secret')

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret, debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer asdf' }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token') >= 0)
  await app.close()
})

test('should throw if secret provider returns a secret that does not match jwt', async t => {
  const secretValue = 'shhhhhh'
  const secret = async (header, payload) => Promise.resolve('not a secret')
  const token = jwt.sign({ foo: 'bar' }, secretValue)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret, debug: true }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  t.true(error.message.indexOf('Invalid token - invalid signature') >= 0)
  await app.close()
})

test('should throw if getToken provider throws', async t => {
  const secretValue = 'shhhhhh'
  const secret = async (header, payload) => Promise.resolve(secretValue)
  const getToken = async ctx => Promise.reject(new Error('Bad Token'))
  const token = jwt.sign({ foo: 'bar' }, secretValue)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret, getToken }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  console.dir(error, { depth: 3, colors: true })
  t.true(error.message.indexOf('Bad Token') >= 0)
  await app.close()
})

test('should throw with async getToken and incorrect token value in request', async t => {
  const secretValue = 'shhhhhh'
  const secret = async (header, payload) => Promise.resolve(secretValue)
  const getToken = async ctx => Promise.resolve(ctx.req.message)
  const token = jwt.sign({ foo: 'bar' }, secretValue)

  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret, getToken }))
  app.use({ testCall })
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'Bearer ' + token }
  const error = await t.throwsAsync(client.testCall({ message: 'hello' }, meta))
  console.dir(error, { depth: 3, colors: true })
  t.true(error.message.indexOf('Invalid token') >= 0)
  await app.close()
})
