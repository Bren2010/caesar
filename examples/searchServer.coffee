# A cryptographically secure document storage server with search.  All of the
# cryptography is taken care of, so all of this is participating in I/O and
# storing large blobs of data.
caesar = require './../caesar'
http = require 'http'
crypto = require 'crypto'

server = new caesar.searchable.Server {}

db = {} # A real database should probably be here, but oh well...
port = 3000

listener = http.createServer (req, res) ->
    req.url = req.url.substring(1).split '/'
    
    switch req.url[0]
        # Save arbitrary blobs of arbitrary size to a database under the given 
        # id.  There's not much you can do with them, as they're basically 
        # random data.  Not very interesting.
        when "upload"
            id = req.url[1]
            db[id] = new Buffer 0
            
            req.on 'data', (data) -> db[id] = Buffer.concat [db[id], data]
            req.on 'end', ->
                res.writeHead 200, 'Content-Type': 'text/plain'
                res.end 'ok'
        
        # Manage encrypted indices.  You still shouldn't touch them too much.  
        # Slightly more interesting.
        when "update"
            index = {} # Download the entire index from the client.
            decoder = new caesar.format.DecodeByLine()
            req.pipe decoder
            
            decoder.on 'data', (line) ->
                [key, value] = line.toString().split ':'
                index[key] = value
            
            req.on 'end', -> # Attempt and update.
                domain = index.domain
                replaces = index.replaces.split ','
                docs = index.docs.split ','
                
                delete index.domain
                delete index.replaces
                delete index.docs
                
                index = docs: docs, index: index
                out = server.update domain, index, replaces
                
                res.writeHead 200, 'Content-Type': 'text/plain'
                res.end JSON.stringify out
        
        # The search feature!
        when "search"
            query = {} # Download the entire query.
            decoder = new caesar.format.DecodeByLine()
            req.pipe decoder
            
            decoder.on 'data', (line) ->
                [dn, data] = line.toString().split ':'
                query[dn] = data.split ','
            
            req.on 'end', -> # Search over the indexes.
                out = server.search query
                
                # Typically, its good manners to just send the docs instead.
                res.writeHead 200, 'Content-Type': 'text/plain'
                res.write id + '\n' for id in out
                res.end()
        
        # Never let the user download an index that they uploaded earlier!  They
        # don't need it anyways.
        
        # A way for the client to fetch encrypted documents that they've stored.
        when "document"
            res.writeHead 200, 'Content-Type': 'text/plain'
            res.end db[req.url[1]]
        
        else
            res.writeHead 200, 'Content-Type': 'text/plain'
            res.end 'Error: Path unknown.'

listener.listen port
