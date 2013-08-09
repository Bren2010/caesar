# A cryptographically secure client for uploading encrypted data and searching
# over it.
caesar = require './../caesar'
crypto = require 'crypto'
readline = require 'readline'
fs = require 'fs'
http = require 'http'
async = require 'async' # npm install async

# Setup the file encrypter.
privKey = caesar.key.createPrivate()
key = public: {me: privKey}, private: {me: privKey}

# Setup the search client.
keys = {}
client = new caesar.searchable.Client keys

# This is the most complicated function of all of this.  Here's the gist of 
# what's happening:
#
# 1. Generate a secure index on the given data.
# 2. Request that the server accept the new index.
# 3. If the server's response is true, then end.  Otherwise, add the documents
#    and domain name mentioned in the merge request to the given data
#    appropriately.
# 4. Go to step 1.
update = (domain, replaces, max, indexes...) ->
    # Step 1.
    sindex = client.secureIndex domain, max, indexes...
    
    # Step 2.
    opts =
        host: 'localhost'
        port: 3000
        path: '/update'
        method: 'POST'
    
    req = http.request opts, (res) ->
        data = new Buffer 0
        res.on 'data', (part) -> data = Buffer.concat [data, part]
        res.on 'end', ->
            # Step 3.
            data = JSON.parse data.toString()
            if data is true
                client.outdate replaces...
                console.log 'Done.'
                rl.prompt()
            else
                replaces.push data[0]
                
                download = (id, done) ->
                    decoder = new caesar.format.DecodeByLength()
                    decrypter = new caesar.message.Decrypter key, true, 'sym'
                    indexer = new caesar.searchable.Indexer id
                    nil = fs.createWriteStream '/dev/null'
                    
                    http.get 'http://localhost:3000/document/' + id, (res) ->
                        res.pipe(decoder).pipe(decrypter).pipe(indexer).pipe nil
                        res.on 'end', ->
                            if indexer.size > max then max = indexer.size
                            done null, indexer.index
                
                end = (err, res) -> # Step 4.
                    update domain, replaces, max, indexes.concat(res)...
                
                async.map data[1], download.bind(this), end.bind(this)
    
    req.write 'domain:' + domain + '\n'
    req.write 'replaces:' + replaces.join(',') + '\n'
    req.write 'docs:' + sindex.docs.join(',') + '\n'
    req.write k + ':' + v + '\n' for k, v of sindex.index
    req.end()
    
# User interface.
rl = readline.createInterface input: process.stdin, output: process.stdout
rl.on 'line', (line) ->
    line = line.trim().split ' '
    
    switch line[0]
        when "" then
        when "help"
            console.log '`upload` - Upload a file to the server.'
            console.log '`search` - Searches your documents.'
            console.log '`download {id}` - Downloads document #{id}.'
            console.log '`exit` - Exits.'
            console.log '(All of these will prompt for needed information.)'
        
        when "upload" # Upload an encrypted file and it's index.
            rl.question 'File location: ', (loc) ->
                # Generate a random file id.  See Indexer docs for id rules.
                id = crypto.randomBytes(16).toString 'hex'
                
                # Read the data from the file, pipe it through an indexer to an
                # encrypter to the HTTP socket.
                info = fs.statSync loc
                data = fs.createReadStream loc
                indexer = new caesar.searchable.Indexer id
                encrypter = new caesar.message.Encrypter key, true, 'sym'
                encoder = new caesar.format.EncodeByLength()
                
                opts =
                    host: 'localhost'
                    port: 3000
                    path: '/upload/' + id
                    method: 'POST'
                
                req = http.request opts, (res) ->
                    console.log 'Upload finished.  Publishing index...'
                    res.on 'data', -> # Consume the response.
                    
                    # Generate a random domain name.  See Client docs for domain
                    # name rules.  Attempt to publish index.
                    domain = crypto.randomBytes(16).toString 'hex'
                    update domain, [], info.size, indexer.index
                    console.log id
                
                data.pipe(indexer).pipe(encrypter).pipe(encoder).pipe(req)
        
        when "search" # Search the encrypted data.
            rl.question 'Search query: ', (query) ->
                query = client.createQuery query # Create a secure query.
                
                opts =
                    host: 'localhost'
                    port: 3000
                    path: '/search'
                    method: 'POST'
                
                req = http.request opts, (res) ->
                    decoder = new caesar.format.DecodeByLine()
                    res.pipe(decoder)
                    
                    decoder.on 'data', (line) -> console.log line.toString()
                    res.on 'end', -> rl.prompt()
                
                req.write k + ':' + v.join(',') + '\n' for k, v of query
                req.end()
        
        when "download" # Download an encrypted file and decrypt it.
            # Intuitive way to download files.  Request it, and pipe the data
            # through a decrypter and into an output file.
            if not line[1]?
                console.log 'No id found.'
                return rl.prompt()
            
            rl.question 'Save location: ', (loc) ->
                data = fs.createWriteStream loc
                decrypter = new caesar.message.Decrypter key, true, 'sym'
                
                http.get 'http://localhost:3000/document/' + line[1], (res) ->
                    res.pipe(decrypter).pipe(data)
                    res.on 'end', -> 
                        console.log 'Done.'
                        rl.prompt()
        
        when "exit" then process.exit()
        else console.log 'Command not known.'
    
    
    rl.prompt()

console.log 'Caesar Search Example Client'
console.log 'Type commands or `help` for help.'
rl.prompt()
