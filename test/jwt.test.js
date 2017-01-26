import test from 'ava'
import path from 'path'
import caller from 'grpc-caller'

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
  ctx.res = { message: ctx.req.message }
}

test('should fail if no authorization header', async t => {
  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: 'shhhh' }))
  app.use({testCall})
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const error = await t.throws(client.testCall({ message: 'hello' }))
  t.is(error.message, 'Not Authorized')
  await app.close()
})

test('should fail if authorization header is malformed', async t => {
  t.plan(2)
  const host = getHostport()
  const app = new Mali(PROTO_PATH, 'Tester')
  app.use(malijwt({ secret: 'shhhh' }))
  app.use({testCall})
  app.start(host)

  const client = caller(host, PROTO_PATH, 'Tester')
  const meta = { Authorization: 'wrong' }
  const error = await t.throws(client.testCall({ message: 'hello' }, meta))
  t.is(error.message, 'Not Authorized')
  await app.close()
})
