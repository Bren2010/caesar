stream = require 'stream'

class exports.EncodeByLine extends stream.Transform
    constructor: (opts) ->
        if not this instanceof exports.EncodeByLine
            return new exports.DecodeByLine opts
        
        stream.Transform.call this
    
    _transform: (chunk, encoding, done) ->
        @push chunk + "\n"
        done()

class exports.DecodeByLine extends stream.Transform
    constructor: (opts) ->
        if not this instanceof exports.DecodeByLine
            return new exports.DecodeByLine opts
        
        stream.Transform.call this
        @_lastLine = ""
    
    _transform: (chunk, encoding, done) ->
        data = @_lastLine + chunk.toString()
        lines = data.split '\n'
        @_lastLine = lines.splice(lines.length - 1, 1)[0]
        
        @push line for line in lines
        done()
    
    _flush: (done) ->
        console.log @_lastLine
        if @_lastLine.length isnt 0 then @push @_lastLine
        @_lastLine = ""
        done()

class exports.EncodeByLength extends stream.Transform
    constructor: (opts) ->
        if not this instanceof exports.EncodeByLength
            return new exports.EncodeByLength opts
        
        stream.Transform.call this
    
    _transform: (chunk, encoding, done) ->
        buff = new Buffer chunk.length + 2
        buff.writeUInt16BE chunk.length, 0
        
        if chunk instanceof Buffer then chunk.copy buff, 2
        else buff.write chunk, 2, chunk.length, encoding
        
        @push buff
        done()

class exports.DecodeByLength extends stream.Transform
    constructor: (opts) ->
        if not this instanceof exports.DecodeByLength
            return new exports.DecodeByLength opts
        
        stream.Transform.call this
        @_buffer = new Buffer ''
    
    _transform: (chunk, encoding, done) ->
        if not Buffer.isBuffer chunk then chunk = new Buffer chunk, enc
        @_buffer = Buffer.concat [@_buffer, chunk]
        going = true
        
        while going and @_buffer.length > 2
            len = @_buffer.readUInt16BE 0
            if @_buffer.length >= (len + 2)
                temp = new Buffer len
                @_buffer.copy temp, 0, 2, len + 2
                @_buffer = @_buffer.slice len + 2
                @push temp
            else going = false
        
        done()
