crypto = require 'crypto'
sha1 = require 'sha1'

# Generates a hash chain (or just a hash).
#
# 1. `value` is the data that will be hashed. *(String||Buffer)*
# 2. `n` is the number of times to compute the hash. *(Number)*
# 3. `alg` is the algorithm to use. *(String)*
exports.chain = (value, n = 1, alg = 'sha512') ->
    sum = (val) ->
        if alg is 'sha1' then return sha1 val
        hash = crypto.createHash alg
        hash.end val
        hash.read()
    
    [n, value] = [n - 1, sum value] until n is 0
    
    value
