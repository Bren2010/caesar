# k-Time Signature schemes are digital signature mechanisms where each keypair 
# is used at most k-times.  See OTS.  Assumes loose time synchronization.
#
# Implemented here is a Merkle-Winternitz Chain, which can sign a fixed number 
# of bits with an extremely low storage overhead and extremely efficient 
# generation, signing, and verification.
#
# http://www.monarch.cs.rice.edu/monarch-papers/ndss03rev.pdf
crypto = require 'crypto'
hash = require './hash'

# Manages the signing of values.  The default sizes allow the signing of a SHA1
# hash
#
# 1. `k` is the number of times the scheme should be valid for.  *(Number)*
# 2. `privateKey` is a private key to use.  If one isn't supplied, a random one 
#    will be generated.  *(String)*
class exports.Signer
    constructor: (k, privateKey) ->
        @heads = []
        
        if privateKey? then @heads.push privateKey
        else @heads.push crypto.randomBytes(20).toString 'hex'
        
        until @heads.length is (k + 2)
            [vi, head] = [@heads[@heads.length - 1], '']
            
            i = 0 # Create signature branches.
            until i is 20
                head += hash.chain vi + 's' + (i + 1), 256, 'sha1'
                ++i
            
            i = 0 # Create checksum branches.
            until i is 2
                head += hash.chain vi + 'c' + (i + 1), 256, 'sha1'
                ++i
            
            head = hash.chain head, 1, 'sha1'
            
            @heads.push head
    
    # Get the current public key.  Should be published.
    getPublicKey: -> @heads[@heads.length - 1]
    
    # Get the private key.  Good for allowing the Signer object to be destroyed
    # without loosing the ability to use this keypair in the future.  Returns 
    # (k, privateKey), where k is the number of remaining uses and privateKey 
    # is the private key.
    getPrivateKey: -> [@heads.length - 2, @heads[0]]
    
    # Signs a message.  Every time this function is called, it counts as one 
    # use of the signature scheme.
    #
    # 1. `msg` is the message to be signed.
    sign: (msg) ->
        if not @heads[@heads.length - 3]? then return false
        
        checksum = 0
        h = hash.chain msg, 1, 'sha1'
        sig = []
        
        i = 0 # Create signature branches.
        until i is h.length
            n = parseInt(h[i] + h[i + 1], 16) + 1
            serial = (i / 2) + 1
            vi = hash.chain @heads[@heads.length - 3] + 's' + serial, n, 'sha1'
            sig.push vi
            
            checksum += n
            
            i = i + 2
        
        i = 0 # Create checksum branches.
        checksum = ('00' + ((256 * 20) - checksum).toString(16)).substr(-3)
        until i is 2
            n = parseInt(checksum[i], 16) + 1
            vi = hash.chain @heads[@heads.length - 3] + 'c' + (i + 1), n, 'sha1'
            sig.push vi
            
            ++i
        
        @heads.pop()
        return sig
        

# Verifies candidate signatures.
#
# 1. `publicKey` is an authentic public key for a peer.
class exports.Verifier
    constructor: (@publicKey) ->
    
    forward: (msg, sig) ->
        h = hash.chain msg, 1, 'sha1'
        candPubKey = ''
        checksum = 0
        
        i = 0 # Verify signature branches.
        until i is h.length
            n = parseInt(h[i] + h[i + 1], 16) + 1
            candPubKey += hash.chain sig[i / 2], 256 - n, 'sha1'
            checksum += n
            
            i = i + 2
        
        i = 0 # Verify checksum branches.
        checksum = ('00' + ((256 * 20) - checksum).toString(16)).substr(-3)
        until i is 2
            n = parseInt(checksum[i], 16) + 1
            candPubKey += hash.chain sig[i + 20], 256 - n, 'sha1'
            
            ++i
        
        candPubKey = hash.chain candPubKey, 1, 'sha1'
        candFinal = ''
        
        i = 0 # Create verification signature branches.
        until i is 20
            candFinal += hash.chain candPubKey + 's' + (i + 1), 256, 'sha1'
            ++i
        
        i = 0 # Create verification checksum branches.
        until i is 2
            candFinal += hash.chain candPubKey + 'c' + (i + 1), 256, 'sha1'
            ++i
        
        candFinal = hash.chain candFinal, 1, 'sha1'
        
        [candPubKey, candFinal]
    
    # Attempt to verify a signature.
    #
    # 1. `msg` is the received message.
    # 2. `sig` is the candidate signature provided as authentication.
    verify: (msg, sig) ->
        [candPubKey, candFinal] = @forward msg, sig
        
        if candFinal is @publicKey
            @publicKey = candPubKey
            return true
        else return false
