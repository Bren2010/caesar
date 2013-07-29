caesar = require '../caesar.coffee'

key1 = caesar.key.createRandom()
key2 = caesar.key.createRandom()

encrypter = new caesar.message.SIVEncrypter key1, key2
decrypter = new caesar.message.SIVDecrypter key1, key2

# This will echo back the user's input.  Play with this pipe and the setup
# above to experiment.
process.stdin.pipe(encrypter).pipe(decrypter).pipe(process.stdout)

console.log 'Type something!'

###
# See streamCipher.coffee for some more examples.
# SIV is used in situations where deterministic encryption is desireable and
# secure, such as in encrypted databases and keystores because it allows 
# querying for associated data at a later point in time.
# For example, encrypt a file full of user ids/usernames or something:
fs = require 'fs'
file = fs.createReadStream './../../users.txt'
out = fs.createWriteStream './../../users.enc.txt'

key1 = caesar.key.createRandom()
key2 = caesar.key.createRandom()

encoder = new caesar.format.EncodeByLength() # Join the ciphertext by lengths.
decoder = new caesar.format.DecodeByLine() # Split the plaintext by newlines.

encrypter = new caesar.message.SIVEncrypter key1, key2

file.pipe(decoder).pipe(encrypter).pipe(encoder).pipe(out)
###
