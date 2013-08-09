stream = require 'stream'

# A simple transform stream to add a newline onto the end of each packet.  This
# is not binary safe.
#
# 1. `opts` are any options you want passed to the underlying readable and 
#    writeable streams.  Best left alone.
class exports.EncodeByLine extends stream.Transform
    constructor: (opts) ->
        if not this instanceof exports.EncodeByLine
            return new exports.EncodeByLine opts
        
        stream.Transform.call this, opts
    
    _transform: (chunk, encoding, done) ->
        @push chunk + "\n"
        done()

# A simple transform stream to split data by its newlines.  This is not binary 
# safe.
#
# 1. `opts` are any options you want passed to the underlying readable and 
#    writeable streams.  Best left alone.
class exports.DecodeByLine extends stream.Transform
    constructor: (opts) ->
        if not this instanceof exports.DecodeByLine
            return new exports.DecodeByLine opts
        
        stream.Transform.call this, opts
        @_lastLine = ""
    
    _transform: (chunk, encoding, done) ->
        data = @_lastLine + chunk.toString()
        lines = data.split '\n'
        @_lastLine = lines.splice(lines.length - 1, 1)[0]
        
        @push line for line in lines
        done()
    
    _flush: (done) ->
        if @_lastLine.length isnt 0 then @push @_lastLine
        @_lastLine = ""
        done()

# Prepends the data's length to each packet in a short.  This is binary safe.
#
# 1. `opts` are any options you want passed to the underlying readable and 
#    writeable streams.  Best left alone.
class exports.EncodeByLength extends stream.Transform
    constructor: (opts) ->
        if not this instanceof exports.EncodeByLength
            return new exports.EncodeByLength opts
        
        stream.Transform.call this, opts
    
    _transform: (chunk, encoding, done) ->
        buff = new Buffer chunk.length + 2
        buff.writeUInt16BE chunk.length, 0
        
        if chunk instanceof Buffer then chunk.copy buff, 2
        else buff.write chunk, 2, chunk.length, encoding
        
        @push buff
        done()

# Waits until an indicated number of bytes have been written before returning 
# the data (without the short).  This is binary safe.
#
# 1. `opts` are any options you want passed to the underlying readable and 
#    writeable streams.  Best left alone.
class exports.DecodeByLength extends stream.Transform
    constructor: (opts) ->
        if not this instanceof exports.DecodeByLength
            return new exports.DecodeByLength opts
        
        stream.Transform.call this, opts
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
