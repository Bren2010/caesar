fs = require 'fs'
crypto = require 'crypto'
ursa = require 'ursa'

salt = 'lK4qA0RY8TRMq8duxRup'

# Create a random symmetrical key.
#
# @param {Number} bytes
exports.createRandom = (bytes = 32, cb) -> crypto.randomBytes bytes, cb

# Create a random RSA private key.  (Public key included).
#
# @param {Number} bytes
# @param {Number} exp
exports.createPrivate = (bytes = 256, exp = 65537) ->
    ursa.generatePrivateKey bytes * 8, exp

# Generate a random symmetrical key from a password asynchronously.
#
# @param {String} password
# @param {Number} bytes
# @param {Function} cb
exports.fromPassword = (password, bytes = 32, cb) ->
    crypto.pbkdf2 password, salt, 4096, bytes, cb

# Generate a random symmetrical key from a password synchronously.
#
# @param {String} password
# @param {Number} bytes
# @param {Function} cb
exports.fromPasswordSync = (password, bytes = 32) ->
    crypto.pbkdf2Sync password, salt, 4096, bytes

# Load a PEM encoded RSA public key asynchronously.
#
# @param {String} loc
# @param {Function} cb
exports.loadPublicKey = (loc, cb) ->
    fs.readFile loc, (err, data) ->
        if err? then cb err, null
        else cb null, ursa.createPublicKey data

# Load a PEM encoded RSA public key synchronously.
#
# @param {String} loc
exports.loadPublicKeySync = (loc) ->
    data = fs.readFileSync loc
    ursa.createPublicKey data

# Load a PEM encoded RSA private key asynchronously.
#
# @param {String} loc
# @param {Function} cb
exports.loadPrivateKey = (loc, cb) ->
    fs.readFile loc, (err, data) ->
        if err? then cb err, null
        else cb null, ursa.createPrivateKey data

# Load a PEM encoded RSA private key synchronously.
#
# @param {String} loc
exports.loadPrivateKeySync = (loc) ->
    data = fs.readFileSync loc
    ursa.createPrivateKey data
