crypto = require 'crypto'
ursa = require 'ursa'
msgpack = require 'msgpack'
stream = require 'stream'
keyLib = require './key'

Buffer.prototype.toArray = -> Array.prototype.slice.call this, 0

# Standard and recommended class for encrypting and authenticating stream-like
# data.
#
# 1. `keys` is a hash of key-related data.  May contain the following  fields:
#    - `key` - A random symmetric key, usually through
#      `caesar.key.createRandom()`.  If present, this key will be used on all
#      messages.  If not present, a random key will be created for each message.
#    - `public` - An array or hash of public keys.  If a hash, the key's owner
#      can be identified easier (by anybody--not just the owner).  If present, a
#      keyring will be available to the owners of the corresponding private keys
#      that allows them to read the message without any previous knowledge of
#      the symmetric key.
#    - `private` - An array or hash of private keys.  If a hash, the key's owner
#      can be identified easier (by anybody--not just the owner).  If present, 
#      asymmetric authentication can be used (signatures), which is publicly
#      verifiable.
# 2. `confidential` is whether or not the data should be encrypted to prevent
#    eavesdropping.  *(Boolean)*
# 3. `integrous` is the type of integrity that should be maintained.  Can be
#    null (no integrity), "sym" (symmetric integrity, verifiable by others with
#    the secret key), and "asym" (asymmetric integrity, verifiable by anyone).
#    *(String)*
# 4. `cut` is the maximum size of a plaintext chunk (where it should be cut).
#    If you get strange errors, try lowering this below the default.  *(Number)*
class exports.Encrypter extends stream.Transform
    constructor: (@keys, @confidential, @integrous, @cut = 14336) ->
        if not this instanceof exports.Encrypter
            return new exports.Encrypter @keys, @confidential, @integrous, @cut
        
        stream.Transform.call this, objectMode: true, decodeStrings: true
        @leftover = new Buffer 0
        
        if @confidential isnt true and @confidential isnt false
            throw 'Confidential must be true or false.'
        
        if @integrous? and @integrous isnt 'sym' and @integrous isnt 'asym'
            throw 'Integrous must be null, sym, or asym.'
        
        requiresKey = @confidential or @integrous is 'sym'
        if requiresKey and not @keys.key? and not @keys.public?
            throw 'No symmetric or public key.'
        
        if @integrous is 'asym' and not @keys.private?
            throw 'No private key to sign messages with.'
        
        if not @confidential then @buffer = new stream.PassThrough()
        else if @keys.key?
            @buffer = crypto.createCipher 'aes-256-ctr', @keys.key
    
    _transform: (dump, encoding, done) ->
        while dump.length isnt 0 # Chop up dump.
            len = if dump.length > @cut then @cut else dump.length
            chunk = new Buffer len
            dump.copy chunk
            dump = dump.slice len
            
            if not @keys.key? # Generate random key if needed.
                key = keyLib.createRandom()
                @buffer = crypto.createCipher 'aes-256-ctr', key
            else key = @keys.key
            
            @buffer.write chunk
            data = @buffer.read()
            footer = {}
            
            if @integrous is 'sym' # Calculate HMAC.
                mac = crypto.createHmac 'sha512', key
                mac.end data
                footer.mac = mac.read().toArray()
            
            if @integrous is 'asym' # Calculate signature.
                sigs = {}
                footer.sigs = if @keys.private instanceof Array then [] else {}
                sigs[k] = ursa.createSigner 'sha512' for k of @keys.private
                sigs[k].update data for k of @keys.private
                footer.sigs[k] = sigs[k].sign v for k, v of @keys.private
                footer.sigs[k] = v.toArray() for k, v of footer.sigs
            
            if @keys.public? # Calculate keyring.
                footer.keys = if @keys.public instanceof Array then [] else {}
                footer.keys[k] = v.encrypt key for k, v of @keys.public
                footer.keys[k] = v.toArray() for k, v of footer.keys
            
            footer = msgpack.pack footer
            out = new Buffer 4 + data.length + footer.length
            out.writeUInt16BE data.length, 0
            data.copy out, 2, 0, data.length
            out.writeUInt16BE footer.length, data.length + 2
            footer.copy out, data.length + 4, 0, footer.length
            
            more = @push out
            if not more then return done()
        
        done()
    
    _flush: (done) ->
        @push if @leftover.length is 0 then null else @leftover
        @leftover = new Buffer 0
        done()


# Standard and recommended class for decrypting and verifying stream-like data.
#
# 1. `keys` is a hash of key-related data.  May contain the following  fields:
#    - `key` - A random symmetric key, usually through
#      `caesar.key.createRandom()`.  If present, this key will be used on all
#      messages.  If not present, a keyring must be present to decrypt messages.
#    - `public` - An array or hash of public keys.  If a hash, the key's owner
#      can be identified easier.  If present, they will be used to verify
#      signatures.
#    - `private` - An array or hash of private keys.  If a hash, the key's owner 
#      can be identified easier.  If present, they will be used to derive
#      symmetric keys from a keyring.
# 2. `confidential` is whether or not the data should be encrypted to prevent
#    eavesdropping.  Must match the Encrypter's value.  *(Boolean)*
# 3. `integrous` is the type of integrity that should be maintained.  Can be
#    null (no integrity), "sym" (symmetric integrity, verifiable by others with
#    the secret key), and "asym" (asymmetric integrity, verifiable by anyone).
#    Must match the Encrypter's value.  *(String)*
class exports.Decrypter extends stream.Transform
    constructor: (@keys, @confidential, @integrous) ->
        if not this instanceof exports.Decrypter
            return new exports.Decrypter @keys, @confidential, @integrous
        
        stream.Transform.call this, decodeStrings: true
        
        if @confidential isnt true and @confidential isnt false
            throw 'Confidential must be true or false.'
        
        if @integrous? and @integrous isnt 'sym' and @integrous isnt 'asym'
            throw 'Integrous must be null, sym, or asym.'
        
        requiresKey = @confidential or @integrous is 'sym'
        if requiresKey and not @keys.key? and not @keys.private?
            throw 'No symmetric or private key.'
        
        if @keys.key? and @confidential
            @cipher = crypto.createDecipher 'aes-256-ctr', @keys.key
        else @cipher = new stream.PassThrough()
    
    _transform: (chunk, encoding, done) ->
        dlen = chunk.readUInt16BE 0
        data = chunk.slice 2, 2 + dlen
        
        flen = chunk.readUInt16BE 2 + dlen
        footer = msgpack.unpack chunk.slice 4 + dlen
        
        if not data? then return done 'No payload.'
        if not footer.mac? and @integrous is 'sym' then return done 'No MAC.'
        if not footer.sigs? and @integrous is 'asym' then return done 'No sigs.'
        
        requiresKey = @confidential or @integrous is 'sym'
        if requiresKey and not @keys.key? and not footer.keys?
            return done 'No method of key derivation.'
        
        key = null
        if @keys.key? # Derive key if needed.
            key = @keys.key
        else
            if footer.keys instanceof Array
                for tag in footer.keys
                    for n, privKey of @keys.private
                        try key = privKey.decrypt tag
                        catch err then key = null
                        
                        if key? then break
                    
                    if key? then break
            else
                keys = (key for key of @keys.private when footer.keys[key]?)
                if keys.length is 0
                    return done 'No valid keys for decryption.'
                
                for k in keys
                    try key = @keys.private[k].decrypt new Buffer footer.keys[k]
                    catch err then key = null
                    
                    if key? then break
        
        if not key? then return done 'No key was successfully derived.'
        
        if not @keys.key? # Intialize new cipher if needed.
            @cipher = crypto.createDecipher 'aes-256-ctr', key
        
        if @integrous is 'sym' # Verify an HMAC.
            mac = crypto.createHmac 'sha512', key
            mac.end new Buffer footer.mac
            candidateTag = mac.read().toString 'base64'
            
            mac = crypto.createHmac 'sha512', key
            mac.end data
            tag = mac.read()
            
            mac = crypto.createHmac 'sha512', key
            mac.end tag
            tag = mac.read().toString 'base64'
            
            if candidateTag isnt tag then return done 'Bad MAC.'
        
        if @integrous is 'asym' # Verify a signature.
            ok = false
            if footer.sigs instanceof Array
                for sig in footer.sigs
                    sig = new Buffer sig
                    for pubKey in @keys.public
                        v = ursa.createVerifier 'sha512'
                        v.update data
                        ok = v.verify pubKey, sig, 'base64'
                        if ok then break
                    
                    if ok then break
            else
                keys = (key for key of @keys.public when footer.sigs[key]?)
                if keys.length is 0 then return done 'No valid keys for auth.'
                
                for k in keys
                    try
                        v = ursa.createVerifier 'sha512'
                        v.update data
                        ok = v.verify @keys.public[k], new Buffer footer.sigs[k]
                        if ok then break
                    catch e
            
            if not ok then return done 'Bad signature.'
        
        @cipher.write data # Decrypt the message.
        @push @cipher.read()
        done()


# An implementation of Synthetic IV encryption.  SIV is a method of
# deterministic and authenticated encryption, commonly used in encrypted
# databases and insecure keystores.  This is because given data can be encrypted
# and used in a search for other related SIV encrypted information which can
# then be decrypted (unlike with a hash, for example).  Because SIV is
# deterministic, only use it on data whose structure prevents repetition (like
# user ids, usernames, or randomly generated keys).
#
# 1. `key1` - Randomly generated symmetric key, usually through 
#    `caesar.key.createRandom()`.
# 2. `key2` - See above.  Should be different from key1.
class exports.SIVEncrypter extends stream.Transform
    constructor: (@key1, @key2) ->
        if not this instanceof exports.SIVEncrypter
            return new exports.SIVEncrypter @key1, @key2
        
        stream.Transform.call this, objectMode: true, decodeStrings: true
        @leftover = new Buffer 0
    
    _transform: (dump, encoding, done) ->
        while dump.length isnt 0 # Chop up dump.
            len = if dump.length > 16368 then 16368 else dump.length
            chunk = new Buffer len
            dump.copy chunk
            dump = dump.slice len
            
            hash = crypto.createHash 'sha256' # Calculate IV.
            hash.end chunk
            tag = hash.read()
            
            temp = crypto.createCipher 'aes-256-ctr', @key1
            temp.end tag
            iv = temp.read().slice 0, 16
            
            cipher = crypto.createCipheriv 'aes-256-ctr', @key2, iv # Encrypt.
            cipher.end chunk
            end = Buffer.concat [iv, cipher.read()]
            more = @push end
            if not more then return done()
        
        done()
    
    _flush: (done) ->
        @push if @leftover.length is 0 then null else @leftover
        @leftover = new Buffer 0
        done()


# An implementation of Synthetic IV decryption.  See above.
class exports.SIVDecrypter extends stream.Transform
    constructor: (@key1, @key2) ->
        if not this instanceof exports.SIVDecrypter
            return new exports.SIVDecrypter @key1, @key2
        
        stream.Transform.call this, decodeStrings: true
    
    _transform: (chunk, encoding, done) ->
        iv = chunk.slice 0, 16
        data = chunk.slice 16
        
        decipher = crypto.createDecipheriv 'aes-256-ctr', @key2, iv # Decrypt
        decipher.end data
        pt = decipher.read()
        
        hash = crypto.createHash 'sha256' # Authenticate by calculating IV
        hash.end pt
        tag = hash.read()
        
        temp = crypto.createCipher 'aes-256-ctr', @key1
        temp.end tag
        ivCand = temp.read().slice 0, 16
        
        if iv.toString('base64') isnt ivCand.toString('base64')
            return done 'Failed auth.'
        
        @push pt
        done()


# An implementation of XTS encryption.  XTS is size-preserving encryption used
# for randomly accessible data, like RAM or hard disks, which are split 
# into sectors of fixed size.  Because size must be preserved, no authentication
# can be used, meaning any ciphertext can be altered by an attacker and will 
# still decrypt.
#
# 1. `key` - Randomly generated symmetric key, usually through 
#    `caesar.key.createRandom()`.
# 2. `cut` - The size in bytes of each sector.  If the size of the plaintext is 
#    not divisible by the cut then 0x00s are appended.
class exports.XTSEncrypter extends stream.Transform
    constructor: (@key, @cut = 32) ->
        if not this instanceof exports.XTSEncrypter
            return new exports.XTSEncrypter @key, @cut
        
        stream.Transform.call this, decodeStrings: true
        @cipher = crypto.createCipher 'aes-256-xts', @key
    
    _transform: (dump, encoding, done) ->
        while dump.length isnt 0 # Chop up dump.
            chunk = new Buffer @cut
            dump.copy chunk
            dump = dump.slice @cut
            
            @cipher.write chunk
            @push @cipher.read()
        
        done()


# An implementation of XTS decryption.  See above.
class exports.XTSDecrypter extends stream.Transform
    constructor: (@key, @cut = 32) ->
        if not this instanceof exports.XTSDecrypter
            return new exports.XTSDecrypter @key
        
        stream.Transform.call this, decodeStrings: true
        @decipher = crypto.createDecipher 'aes-256-xts', @key
    
    _transform: (dump, encoding, done) ->
        while dump.length isnt 0 # Chop up dump.
            chunk = new Buffer @cut
            dump.copy chunk
            dump = dump.slice @cut
            
            @decipher.write chunk
            @push @decipher.read()
        
        done()
