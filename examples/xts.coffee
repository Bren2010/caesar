caesar = require '../caesar.coffee'

key = caesar.key.createRandom()

encrypter = new caesar.message.XTSEncrypter key
decrypter = new caesar.message.XTSDecrypter key

# This will echo back the user's input.  Play with this pipe and the setup
# above to experiment.  May look a bit odd because 0x00s are appended if the 
# plaintext is too short.  This is by design, not mistake.
process.stdin.pipe(encrypter).pipe(decrypter).pipe(process.stdout)

console.log 'Type something!'

###
# See streamCipher.coffee for some more examples.
# XTS is used for randomly accessible data, like hard disks and RAM.
# For example, encrypt a file:
fs = require 'fs'
file = fs.createReadStream './../../picture.jpg'
out = fs.createWriteStream './../../picture.enc.jpg'

key = caesar.key.createRandom()
encrypter = new caesar.message.XTSEncrypter key

file.pipe(encrypter).pipe(out)
# Just switch the file names and the encrypter to a decrypter to undo.
###
