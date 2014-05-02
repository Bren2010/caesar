# A Merkle Tree is a cryptographic primitive that allows efficient commitment
# to a set of values.
#
# http://en.wikipedia.org/wiki/Merkle_tree
hash = require './hash'

# Manages the Merkle commitment to a set of values.
#
# 1. `vals` is the array of values that should be commited to.  *(Array)*
# 2. `alg` is the hash to use.  Default sha256. *(String)*
class exports.Committer
    constructor: (@vals, @alg = 'sha256') ->
        c = Math.pow(2, Math.ceil(Math.log(@vals.length) / Math.log(2)))
        c = c - @vals.length # Ensure that @vals.length is a power of two.
        
        i = 0
        until i is c
            @vals.push '0000000000'
            ++i
        
        i = 0 # Mask each value.
        until i is @vals.length
            @vals[i] = hash.chain @vals[i], 1, @alg
            ++i
    
    # Calculates the commitment to the given set of objects.  (The head of the 
    # Merkle tree.)  This is what should be published.  It should be noted, this
    # function is deterministic.  Given the same set of objects, the same value
    # will be output.  If this isn't desireable, add a random nonce *to the end 
    # of each commited value.*  Simply adding a random nonce as one of the 
    # commited objects is detectable.
    getCommit: ->
        lvl = @vals
        until lvl.length is 1
            [i, tmp] = [0, []]
            
            until i is lvl.length
                v = hash.chain lvl[i].toString() + lvl[i+1].toString(), 1, @alg
                tmp.push v
                
                i = i + 2
            
            lvl = tmp
        
        return lvl[0]
    
    # Calculate a proof of commitment to a certain value.  This is published 
    # when a commitment to a certain object is 
    #
    # 1. `i` is the index in the original array of values that a proof should 
    #    be drawn for. *(Number)*
    getProof: (j) ->
        [lvl, proof] = [@vals, []]
        until lvl.length is 1
            [i, tmp] = [0, []]
            
            until i is lvl.length
                if i is j then proof.push [1, lvl[i + 1]]
                if (i + 1) is j then proof.push [0, lvl[i]]
                if i is j or (i + 1) is j then j = Math.floor(j / 2)
                
                v = hash.chain lvl[i].toString() + lvl[i+1].toString(), 1, @alg
                tmp.push v
                
                i = i + 2
            
            lvl = tmp
        
        return proof


exports.forward = (val, proof, alg = 'sha256') ->
    val = hash.chain val, 1, alg
    
    for v in proof 
        if v[0] is 0
            val = hash.chain v[1].toString() + val.toString(), 1, alg
        else
            val = hash.chain val.toString() + v[1].toString(), 1, alg
    
    val

# Verify a proof of commitment.
#
# 1. `commitment` is the previously published commitment.  *(Buffer)*
# 2. `val` is the value that is being supposedly proven.  *(String|Buffer)*
# 3. `proof` is the provided proof.  *(Object)*
# 4. `alg` is the hash to use.  Default sha256. *(String)*
exports.verify = (commitment, val, proof, alg = 'sha256') ->
    val = exports.forward val, proof, alg
    
    val.toString() is commitment.toString()

