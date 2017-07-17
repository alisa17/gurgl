const jwt = require('jsonwebtoken')

const crypto = require('./crypto')
const users = require('../db/members')

let connection = null
function createToken (user, secret) {
  return jwt.sign(user, secret, {
    expiresIn: "24h"
  })
}

function handleError (err, req, res, next) {
  if (err) {
    return res.status(403).json({
      message: 'Access to this resource was denied.',
      error: err.message
    })
  }
  next()
}

function issueJwt (req, res, next) {
  connection = req.app.get('db')
  verify(req.body.username, req.body.password,
    (err, user) => {
      if (err) {
        console.log(err)
        return res.status(500).json({
          message: 'Authentication failed due to a server error.'
        })
      }

      if (!user) {
        return res.status(403).json({
          message: 'Authentication failed.',
        })
      }

      const token = createToken(user, process.env.JWT_SECRET)
      res.json({
        message: 'Authentication successful.',
        token
      })
    })

}

function verify (username, password, callback) {
  users.getByName(username, connection)
      .then(users => {
        if (users.length === 0 || !crypto.verifyUser(users[0], password)) {
          return callback(null, false)
      }
      const user = users[0]
      delete user.hash
      callback(null, user)
    })
  .catch(err => {
    callback(err, false)
  })
}

module.exports = {
  handleError,
  issueJwt,
  verify,
  createToken
}
