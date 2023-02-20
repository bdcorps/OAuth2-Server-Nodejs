const path = require('path') // has path and __dirname
const express = require('express')
const oauthServer = require('../oauth/server.js')

const DebugControl = require('../utilities/debug.js')
const prisma = require('../../lib/prisma')

const router = express.Router() // Instantiate a new router

const filePath = path.join(__dirname, '../public/oauthAuthenticate.html')

router.get('/', (req, res) => {  // send back a simple form for the oauth
  res.sendFile(filePath)
})


router.get("/addclient", async (req, res) => {

  await prisma.client.create({
    data: {
      clientId: "myClientId",
      clientSecret: "clientSecret",
      redirectUris: ['http://localhost:3030/client/app'],
      grants: ['authorization_code', 'refresh_token'],
    }
  })
})

router.post('/authorize', async (req, res, next) => {
  DebugControl.log.flow('Initial User Authentication')
  const { email, password } = req.body;

  const params = [ // Send params back down
    'client_id',
    'redirect_uri',
    'response_type',
    'grant_type',
    'state',
  ]
    .map(a => `${a}=${req.body[a]}`)
    .join('&')

  if (!email || !password) {
    return res.redirect(`/oauth?success=false&${params}`)
  }

  const user = await prisma.user.findMany({
    where: {
      email,
      password
    }
  })

  console.log("founduser", user)

  if (user && user.length > 0) {
    req.body.user = { user: user[0].id }
    return next()
  }

  return res.redirect(`/oauth?success=false&${params}`)
}, (req, res, next) => { // sends us to our redirect with an authorization code in our url
  DebugControl.log.flow('Authorization')
  return next()
}, oauthServer.authorize({
  authenticateHandler: {
    handle: req => {
      DebugControl.log.functionName('Authenticate Handler')
      DebugControl.log.parameters(Object.keys(req.body).map(k => ({ name: k, value: req.body[k] })))

      return req.body.user
    }
  }
}))

router.post('/token', (req, res, next) => {
  DebugControl.log.flow('Token')
  next()
}, oauthServer.token({
  requireClientAuthentication: { // whether client needs to provide client_secret
    // 'authorization_code': false,
  },
}))  // Sends back token


module.exports = router
