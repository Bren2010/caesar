# Commitments are a cryptographic method of allowing somebody to "commit" to a
# value without revealing what that value is (confidential).  Later in time,
# they admit the value that they committed to and a "decommitment" so third
# parties can verify that they have not tried to change the value they committed
# to initially.
#
# http://en.wikipedia.org/wiki/Commitment_scheme#Coin_flipping
ursa = require 'ursa'
key = require './key'

# Makes a commitment.  Returns the pair (commitment, decommitment).  As above
# indicates, the commitment should be published immediately.  The decommitment
# should be published along with the commited item later in time.
#
# 1. `info` is the value to be commited to.  (I choose heads.)  *(Buffer)*
exports.make = (info) ->
    privKey = key.createPrivate()
    sig = privKey.hashAndSign 'sha512', info
    
    [sig, privKey.toPublicPem()]

# Verifies a commitment.  Returns true or false.
#
# 1. `cand` is the candidate value admitted by the committer.  (He says he chose
#    heads.)  *(Buffer)*
# 2. `commitment` is the commitment they published.  *(Buffer)*
# 3. `decommitment` is the value published with the candidate as proof of
#    commitment.
exports.verify = (candidate, commitment, decommitment) ->
    pubKey = ursa.createPublicKey decommitment
    pubKey.hashAndVerify 'sha512', candidate, commitment
