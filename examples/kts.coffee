# k-Time Signature demonstration
caesar = require './../caesar'

# Create a 2-time signer and a verifier..
signer = new caesar.kts.Signer 2
pub = signer.getPublicKey() # The public key must be taken NOW.

ver = new caesar.kts.Verifier pub

# Sign the first message.
sig = signer.sign 'Hello World!'
# If the public key is taken now, it will be the wrong value.

console.log 'First signature: ', sig

# Should return true if everything agrees.
console.log ver.verify 'Hello World!', sig


# Sign a second message.
# Broadcasting the public key again (even though it's different) is unnecessary.
console.log ''
sig = signer.sign 'Goodbye World!'
console.log 'Second signature: ', sig

console.log ver.verify 'Goodbye World!', sig # Should be true

# Try to sign a second message.
console.log ''
sig = signer.sign 'Will return false.'
console.log 'Third signature: ', sig

