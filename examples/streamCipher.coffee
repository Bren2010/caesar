caesar = require './../caesar'

encoder = new caesar.format.EncodeByLength()
decoder = new caesar.format.DecodeByLength()

# Symmetric:
keys = key: caesar.key.createRandom()

encrypter = new caesar.message.Encrypter keys, true, "sym"
decrypter = new caesar.message.Decrypter keys, true, "sym"

###
# Asymmetric:
# In practice, the pubilc key should be extracted from this and distributed, 
# and the private key should be kept... private.
alice = new caesar.key.createPrivate()
bob = new caesar.key.createPrivate()

alicesKeys = public: {bob: bob}, private: {alice: alice}
bobsKeys = public: {alice: alice}, private: {bob: bob}

encrypter = new caesar.message.Encrypter alicesKeys, true, "sym"
decrypter = new caesar.message.Decrypter bobsKeys, true, "sym"
###

# This will echo back the user's input.  Play with this pipe and the setup
# above to experiment.
process.stdin.pipe(encrypter).pipe(encoder).pipe(decoder)
    .pipe(decrypter).pipe(process.stdout)

console.log 'Type something!'

# Echo:  process.stdin.pipe(encrypter).pipe(decrypter).pipe(process.stdout)
# Encrypt only: process.stdin.pipe(encrypter)
# ... (etc)
