crypto = require 'crypto'
ursa = require 'ursa'
stream = require 'stream'
keyLib = require './key.coffee'

class exports.Encrypter extends stream.Transform
    constructor: (@keys, @confidential, @integrous, @cut = 14336) ->
        if not this instanceof exports.Encrypter
            return new exports.Encrypter @keys, @confidential, @integrous, @cut
        
        stream.Transform.call this, objectMode: true, decodeStrings: true
        @leftover = new Buffer 0
        
        # Check for correct values.
        if @confidential isnt true and @confidential isnt false
            throw 'Confidential must be true or false.'
        
        if @integrous? and @integrous isnt 'sym' and @integrous isnt 'asym'
            throw 'Integrous must be null, sym, or asym.'
        
        # Check for key.
        requiresKey = @confidential or @integrous is 'sym'
        if requiresKey and not @keys.key? and not @keys.public?
            throw 'No symmetric or public key.'
        
        if @integrous is 'asym' and not @keys.private?
            throw 'No private key to sign messages with.'
        
        # Create cipher.
        if not @confidential then @buffer = new stream.PassThrough()
        else if @keys.key?
            @buffer = crypto.createCipher 'aes-256-ctr', @keys.key
    
    _transform: (dump, encoding, done) ->
        while dump.length isnt 0
            # Chop up dump.
            len = if dump.length > @cut then @cut else dump.length
            chunk = new Buffer len
            dump.copy chunk
            dump = dump.slice len
            
            if not @keys.key?
                key = keyLib.createRandom()
                @buffer = crypto.createCipher 'aes-256-ctr', key
            else key = @keys.key
            
            @buffer.write chunk
            data = @buffer.read()
            footer = {}
            
            if @integrous is 'sym'
                mac = crypto.createHmac 'sha512', key
                mac.end data
                footer.mac = mac.read().toString 'base64'
            
            if @integrous is 'asym'
                sigs = {}
                footer.sigs = if @keys.private instanceof Array then [] else {}
                sigs[k] = ursa.createSigner 'sha512' for k of @keys.private
                sigs[k].update data for k of @keys.private
                footer.sigs[k] = sigs[k].sign v for k, v of @keys.private
                footer.sigs[k] = v.toString 'base64' for k, v of footer.sigs
            
            if @keys.public?
                footer.keys = if @keys.public instanceof Array then [] else {}
                footer.keys[k] = v.encrypt key for k, v of @keys.public
                footer.keys[k] = v.toString 'base64' for k, v of footer.keys
            
            footer = JSON.stringify footer
            out = new Buffer 4 + data.length + footer.length
            out.writeUInt16BE data.length, 0
            data.copy out, 2, 0, data.length
            out.writeUInt16BE footer.length, data.length + 2
            out.write footer, data.length + 4
            
            more = @push out
            if not more then return done()
        
        done()
    
    _flush: (done) ->
        @push if @leftover.length is 0 then null else @leftover
        @leftover = new Buffer 0
        done()


class exports.Decrypter extends stream.Transform
    constructor: (@keys, @confidential, @integrous) ->
        if not this instanceof exports.Decrypter
            return new exports.Decrypter @keys, @confidential, @integrous
        
        stream.Transform.call this, decodeStrings: true
        
        # Check for correct values.
        if @confidential isnt true and @confidential isnt false
            throw 'Confidential must be true or false.'
        
        if @integrous? and @integrous isnt 'sym' and @integrous isnt 'asym'
            throw 'Integrous must be null, sym, or asym.'
        
        # Check for key.
        requiresKey = @confidential or @integrous is 'sym'
        if requiresKey and not @keys.key? and not @keys.private?
            throw 'No symmetric or private key.'
        
        # Create decipher.
        if @keys.key? and @confidential
            @cipher = crypto.createDecipher 'aes-256-ctr', @keys.key
        else @cipher = new stream.PassThrough()
    
    _transform: (chunk, encoding, done) ->
        # Unpack and validate ciphertext fields.
        dlen = chunk.readUInt16BE 0
        data = chunk.slice 2, 2 + dlen
        
        flen = chunk.readUInt16BE 2 + dlen
        footer = JSON.parse chunk.slice 4 + dlen
        
        if not data? then return done 'No payload.'
        if not footer.mac? and @integrous is 'sym' then return done 'No MAC.'
        if not footer.sigs? and @integrous is 'asym' then return done 'No sigs.'
        
        requiresKey = @confidential or @integrous is 'sym'
        if requiresKey and not @keys.key? and not footer.keys?
            return done 'No method of key derivation.'
        
        # Derive key.
        key = null
        if @keys.key? # We already have it.
            key = @keys.key
        else # We'll have to find it in a keyring.
            if footer.keys instanceof Array
                for tag in footer.keys
                    for n, privKey of @keys.private
                        try key = privKey.decrypt tag, 'base64'
                        catch err then key = null
                        
                        if key? then break
                    
                    if key? then break
            else
                keys = (key for key of @keys.private when footer.keys[key]?)
                if keys.length is 0
                    return done 'No valid keys for decryption.'
                
                for k in keys
                    try key = @keys.private[k].decrypt footer.keys[k], 'base64'
                    catch err then key = null
                    
                    if key? then break
        
        if not key? then return done 'No key was successfully derived.'
        
        if not @keys.key?
            @cipher = crypto.createDecipher 'aes-256-ctr', key
        
        # Verify the message's integrity.
        if @integrous is 'sym' # Verify an HMAC.
            mac = crypto.createHmac 'sha512', key
            mac.end footer.mac, 'base64'
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
                        ok = v.verify @keys.public[k], footer.sigs[k], 'base64'
                        if ok then break
                    catch e
            
            if not ok then return done 'Bad signature.'
        
        # Decrypt the message.
        @cipher.write data
        @push @cipher.read()
        done()


class exports.SIVEncrypter extends stream.Transform
    constructor: (@key1, @key2) ->
        if not this instanceof exports.SIVEncrypter
            return new exports.SIVEncrypter @key1, @key2
        
        stream.Transform.call this, objectMode: true, decodeStrings: true
        @leftover = new Buffer 0
    
    _transform: (dump, encoding, done) ->
        while dump.length isnt 0
            # Chop up dump.
            len = if dump.length > 16368 then 16368 else dump.length
            chunk = new Buffer len
            dump.copy chunk
            dump = dump.slice len
        
            # Calculate IV
            hash = crypto.createHash 'sha256'
            hash.end chunk
            tag = hash.read()
            
            temp = crypto.createCipher 'aes-256-ctr', @key1
            temp.end tag
            iv = temp.read().slice 0, 16
            
            cipher = crypto.createCipheriv 'aes-256-ctr', @key2, iv
            cipher.end chunk
            end = Buffer.concat [iv, cipher.read()]
            more = @push end
            if not more then return done()
        
        done()
    
    _flush: (done) ->
        @push if @leftover.length is 0 then null else @leftover
        @leftover = new Buffer 0
        done()


class exports.SIVDecrypter extends stream.Transform
    constructor: (@key1, @key2) ->
        if not this instanceof exports.SIVDecrypter
            return new exports.SIVDecrypter @key1, @key2
        
        stream.Transform.call this, decodeStrings: true
    
    _transform: (chunk, encoding, done) ->
        iv = chunk.slice 0, 16
        data = chunk.slice 16
        
        # Decrypt
        decipher = crypto.createDecipheriv 'aes-256-ctr', @key2, iv
        decipher.end data
        pt = decipher.read()
        
        # Authenticate by calculating IV
        hash = crypto.createHash 'sha256'
        hash.end pt
        tag = hash.read()
        
        temp = crypto.createCipher 'aes-256-ctr', @key1
        temp.end tag
        ivCand = temp.read().slice 0, 16
        
        if iv.toString('base64') isnt ivCand.toString('base64')
            return done 'Failed auth.'
        
        @push pt
        done()


class exports.XTSEncrypter extends stream.Transform
    constructor: (@key, @cut = 32) ->
        if not this instanceof exports.XTSEncrypter
            return new exports.XTSEncrypter @key, @cut
        
        stream.Transform.call this, decodeStrings: true
        @cipher = crypto.createCipher 'aes-256-xts', @key
    
    _transform: (dump, encoding, done) ->
        while dump.length isnt 0
            # Chop up dump.
            chunk = new Buffer @cut
            dump.copy chunk
            dump = dump.slice @cut
            
            @cipher.write chunk
            @push @cipher.read()
        
        done()


class exports.XTSDecrypter extends stream.Transform
    constructor: (@key, @cut = 32) ->
        if not this instanceof exports.XTSDecrypter
            return new exports.XTSDecrypter @key
        
        stream.Transform.call this, decodeStrings: true
        @decipher = crypto.createDecipher 'aes-256-xts', @key
    
    _transform: (dump, encoding, done) ->
        while dump.length isnt 0
            # Chop up dump.
            chunk = new Buffer @cut
            dump.copy chunk
            dump = dump.slice @cut
            
            @decipher.write chunk
            @push @decipher.read()
        
        done()
