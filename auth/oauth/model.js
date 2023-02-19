// See https://oauth2-server.readthedocs.io/en/latest/model/spec.html for what you can do with this
const crypto = require('crypto')
const prisma = require('../../lib/prisma')
const db = { // Here is a fast overview of what your db model should look like
  authorizationCode: {
    authorizationCode: '', // A string that contains the code
    expiresAt: new Date(), // A date when the code expires
    redirectUri: '', // A string of where to redirect to with this code
    client: null, // See the client section
    user: null, // Whatever you want... This is where you can be flexible with the protocol
  },
  client: { // Application wanting to authenticate with this server
    clientId: '', // Unique string representing the client
    clientSecret: '', // Secret of the client; Can be null
    grants: [], // Array of grants that the client can use (ie, `authorization_code`)
    redirectUris: [], // Array of urls the client is allowed to redirect to
  },
  token: {
    accessToken: '', // Access token that the server created
    accessTokenExpiresAt: new Date(), // Date the token expires
    client: null, // Client associated with this token
    user: null, // User associated with this token
  },
}


const DebugControl = require('../utilities/debug.js')

module.exports = {
  getClient: async function (clientId, clientSecret) {
    // query db for details with client
    log({
      title: 'Get Client',
      parameters: [
        { name: 'clientId', value: clientId },
        { name: 'clientSecret', value: clientSecret },
      ]
    })

    return prisma.client.findFirst(
      {
        where: {
          clientId: clientId,
          clientSecret: "clientSecret",
        }
      }
    )
  },
  saveToken: async (token, client, user) => {
    /* This is where you insert the token into the database */
    log({
      title: 'Save Token',
      parameters: [
        { name: 'token', value: token },
        { name: 'client', value: client },
        { name: 'user', value: user },
      ],
    })

    const savedToken = await prisma.token.create({
      data: {
        accessToken: token.accessToken,
        accessTokenExpiresAt: token.accessTokenExpiresAt,
        refreshToken: token.accessToken, // NOTE this is only needed if you need refresh tokens down the line
        refreshTokenExpiresAt: token.accessTokenExpiresAt,
        clientId: client.clientId, 
        userId: user.user,
      }
    })


    return new Promise(resolve => resolve({ ...savedToken, client, user }))
  },
  getAccessToken: async accessToken => {
    /* This is where you select the token from the database where the code matches */
    log({
      title: 'Get Access Token',
      parameters: [
        { name: 'accessToken', value: accessToken },
      ]
    })
    if (!accessToken || accessToken === 'undefined') return false
    const foundAccessToken = await prisma.token.findFirst({
      where: {
        accessToken: accessToken
      },
      select: {
        accessToken: true,
        accessTokenExpiresAt: true,
        refreshToken: true,
        refreshTokenExpiresAt: true,
        client: true,
        user: true
      }
    })

    const res = foundAccessToken
    res["client"]["id"] = foundAccessToken.clientId
    res["user"] = { user: foundAccessToken.user.id }

    return new Promise(resolve => resolve(foundAccessToken))

  },
  getRefreshToken: async token => {
    /* Retrieves the token from the database */
    log({
      title: 'Get Refresh Token',
      parameters: [
        { name: 'token', value: token },
      ],
    })
    // DebugControl.log.variable({ name: 'db.token', value: db.token })
    const foundRefreshToken = await prisma.token.findFirst({
      where: {
        refreshToken: token
      },
      select: {
        accessToken: true,
        accessTokenExpiresAt: true,
        refreshToken: true,
        refreshTokenExpiresAt: true,
        client: true,
        user: true
      }
    })

    const res = foundRefreshToken
    res["client"]["id"] = foundRefreshToken.clientId

    return new Promise(resolve => resolve(foundRefreshToken))
  },
  revokeToken: token => {
    // TODO: Implement this
    /* Delete the token from the database */
    log({
      title: 'Revoke Token',
      parameters: [
        { name: 'token', value: token },
      ]
    })
    if (!token || token === 'undefined') return new Promise(resolve => resolve(false))

    return prisma.token.delete({ where: { refreshToken: token.refreshToken } })
      .then(function (token) {
        return !!token;
      });
  },
  generateAuthorizationCode: (client, user, scope, callback) => {
    /* generate authroization code */

    log({
      title: 'Generate Authorization Code',
      parameters: [
        { name: 'client', value: client },
        { name: 'user', value: user },
      ],
    })

    const err = null;
    const seed = crypto.randomBytes(256)
    const code = crypto
      .createHash('sha1')
      .update(seed)
      .digest('hex')
    return callback(err, code);
  },
  saveAuthorizationCode: async (code, client, user) => {
    /* This is where you store the access code data into the database */
    log({
      title: 'Save Authorization Code',
      parameters: [
        { name: 'code', value: code },
        { name: 'client', value: client },
        { name: 'user', value: user },
      ],
    })

    return prisma.authCode.create({
      data: {
        authorizationCode: code.authorizationCode,
        expiresAt: code.expiresAt,
        clientId: client.clientId,
        userId: user.user,
        redirectUri: code.redirectUri
      }
    })
  },
  getAuthorizationCode: async (authorizationCode) => {
    /* this is where we fetch the stored data from the code */
    log({
      title: 'Get Authorization code',
      parameters: [
        { name: 'authorizationCode', value: authorizationCode },
      ],
    })

    // correct code
    // {
    //   authorizationCode: 'df5f329adfd0a3b94099606e27e9c00c3b3b4a74',
    //   expiresAt: 2023-02-18T20:42:50.737Z,
    //   client: {
    //     clientId: 'myClientId',
    //     clientSecret: null,
    //     grants: [ 'authorization_code', 'refresh_token' ],
    //     redirectUris: [ 'http://localhost:3030/client/app' ]
    //   },
    //   user: { user: 1 }
    // }


    const authCode = await prisma.authCode.findFirst({
      where: {
        authorizationCode: authorizationCode
      },
      select: {
        authorizationCode: true,
        expiresAt: true,
        // redirectUri: true,
        clientId: true,
        client: true,
        user: true
      }
    })

    console.log("has authCode", !!authCode)

    const res = authCode
    res["client"]["redirectUri"] = [authCode.client.redirectUris]
    res["user"] = { user: authCode.user.id }


    return new Promise(resolve => resolve(res))
  },
  revokeAuthorizationCode: async code => {
    /* This is where we delete codes */
    log({
      title: 'Revoke Authorization Code',
      parameters: [
        { name: 'authorizationCode', value: code },
      ],
    })


    return prisma.authCode.delete({ where: { authorizationCode: code.authorizationCode } })
      .then(function (authorizationCode) {
        return !!authorizationCode;
      });


    // await prisma.authCode.delete({
    //   where: {
    //     authorizationCode: code.authorizationCode
    //   }
    // })


    // const codeWasFoundAndDeleted = true  // Return true if code found and deleted, false otherwise
    // return new Promise(resolve => resolve(codeWasFoundAndDeleted))
  },
  verifyScope: (token, scope) => {
    /* This is where we check to make sure the client has access to this scope */
    log({
      title: 'Verify Scope',
      parameters: [
        { name: 'token', value: token },
        { name: 'scope', value: scope },
      ],
    })
    const userHasAccess = true  // return true if this user / client combo has access to this resource
    return new Promise(resolve => resolve(userHasAccess))
  }
}

function log({ title, parameters }) {
  DebugControl.log.functionName(title)
  DebugControl.log.parameters(parameters)
}
