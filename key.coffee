fs = require 'fs'
crypto = require 'crypto'
ursa = require 'ursa'

salt = 'lK4qA0RY8TRMq8duxRup'


# Create a random symmetrical key.
#
# 1. `bytes` is the size of the key to create.  *(Number)*
# 2. `cb(err, key)` is optional and will make the operation asynchronous.
#    *(Function)*
exports.createRandom = (bytes = 32, cb) -> crypto.randomBytes bytes, cb

# Create a random RSA private key, from which the public key can be derived.
#
# 1. `bytes` is the size of the key to create.  *(Number)*
# 2. `exp` is the exponent to use.  *(Number)*
exports.createPrivate = (bytes = 256, exp = 65537) ->
    ursa.generatePrivateKey bytes * 8, exp

# Generate a pseudo-random symmetrical key from a password asynchronously.
#
# 1. `password` is the password to use.  *(String)*
# 2. `bytes` is the size of the key to create.  *(Number)*
# 3. `cb(err, key)` will be called when finished.  *(Function)*
exports.fromPassword = (password, bytes = 32, cb) ->
    crypto.pbkdf2 password, salt, 4096, bytes, cb

# Generate a pseudo-random symmetrical key from a password synchronously.
# *(See above.)*
exports.fromPasswordSync = (password, bytes = 32) ->
    crypto.pbkdf2Sync password, salt, 4096, bytes

# Load a PEM encoded RSA public key asynchronously.
#
# 1. `loc` is the location of the public key file.  *(String)*
# 2. `cb(err, pubKey)` will be called when finished.  *(Function)*
exports.loadPublicKey = (loc, cb) ->
    fs.readFile loc, (err, data) ->
        if err? then cb err, null
        else cb null, ursa.createPublicKey data

# Load a PEM encoded RSA public key synchronously.  *(See above.)*
exports.loadPublicKeySync = (loc) ->
    data = fs.readFileSync loc
    ursa.createPublicKey data

# Load a PEM encoded RSA private key asynchronously.
#
# 1. `loc` is the location of the private key file.  *(String)*
# 2. `cb(err, privKey)` will be called when finished.  *(Function)*
exports.loadPrivateKey = (loc, cb) ->
    fs.readFile loc, (err, data) ->
        if err? then cb err, null
        else cb null, ursa.createPrivateKey data

# Load a PEM encoded RSA private key synchronously.  *(See above)*
exports.loadPrivateKeySync = (loc) ->
    data = fs.readFileSync loc
    ursa.createPrivateKey data
