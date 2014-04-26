# One-Time Signature schemes are digital signature mechanisms where each  
# keypair can be used at most once.  They have a much lower signing and 
# verification cost than traditional signatures, making them ideal for 
# authenticating broadcast streams.  Use at your own discretion.
#
# Implemented here is HORS.  Data of any length may be signed.
#
# https://eprint.iacr.org/2002/014.pdf
crypto = require 'crypto'
stream = require 'stream'
hash = require './hash'

# Create a random key for a one-time signature.  Outputs a random keypair in 
# the form of [public key, private key].  It's best not to change any of the 
# arguments if you don't know what they do.
#
# 1. `l` is the length (in bytes) of the random strings generated.
# 2. `k` is the number of random objects to pull from the private key.  (2 | k)
# 3. `t` is the number of random strings to generate.  (t | 2^32)
exports.generateKey = (l = 10, k = 20, t = 256) ->
    [s, v] = [[], []]
    
    s.push crypto.randomBytes(l) until s.length is t
    v[i] = hash.chain(si, 1, 'sha1').slice(0, l) for si, i in s
    
    [[k, v], [k, s]]


# Class for generating one-time signatures.  Sign objects are writable streams.
# The data written is used to generate the signature.  Once all of the data has 
# been written, the `sign` method will return the signature.  It's best not to 
# change any of the arguments if you don't know what they do.
class exports.Sign extends stream.Writable
    constructor: ->
        if not this instanceof exports.Sign then return new exports.Sign()
        stream.Writable.call this
        
        @hash = crypto.createHash 'sha1'
    
    _write: (chunk, encoding, cb) -> @hash.write chunk, encoding, cb
    
    # Calculates the signature on all the updated data passed through the sign.
    #
    # 1. `privKey` is the private key to sign with.
    sign: (privKey) ->
        @hash.end()
        out = @hash.read()
        
        [j, sig] = [0, []]
        
        until j is privKey[0]
            n = out.readUInt8(j) % privKey[1].length
            sig.push privKey[1][n]
            
            ++j
        
        sig


# Class for verifying one-time signatures.  Verify objects are writable streams.
# The data written is used to verify the signature.  Once all of the data has 
# been written, the `verify` method will return true if the supplied signature 
# is valid.  It's best not to change any of the arguments if you don't know what 
# they do.
class exports.Verify extends stream.Writable
    constructor: ->
        if not this instanceof exports.Verify then return new exports.Verify()
        stream.Writable.call this
        
        @hash = crypto.createHash 'sha1'
    
    _write: (chunk, encoding, cb) -> @hash.write chunk, encoding, cb
    
    # Verifies the signed data.  Returns true or false depending on validity.
    #
    # 1. `pubKey` is the public key to verify with.
    # 2. `signature` is the candidate signature.
    verify: (pubKey, sig) ->
        @hash.end()
        out = @hash.read()
        
        [j, i] = [0, []]
        
        until j is pubKey[0]
            n = out.readUInt8(j) % pubKey[1].length
            
            cand = hash.chain(sig[j], 1, 'sha1').slice(0, pubKey[1][0].length)
            if cand.toString('hex') isnt pubKey[1][n].toString('hex')
                return false
            
            ++j
        
        return true
