# One-Time Signature demonstration
caesar = require './../caesar.coffee'

# Generate key.
key = caesar.ots.generateKey()

# Sign message.
sig = new caesar.ots.Sign()
sig.end 'hello world!'

signature = sig.sign key[1]

console.log 'Signature: ', signature

# Verify signature.
ver = new caesar.ots.Verify()
ver.end 'hello world!' # If this is different from the above, verify will fail.

console.log 'Valid? ', ver.verify key[0], signature
