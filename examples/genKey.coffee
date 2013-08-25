# Generates random public/private key pairs and outputs them in PEM format.
caesar = require './../caesar'

privKey = caesar.key.createPrivate()

console.log 'Here\'s the public key (feel free to share!):'
console.log privKey.toPublicPem().toString()

console.log 'Here\'s the private key (never ever share!):'
console.log privKey.toPrivatePem().toString()

console.log 'Save both of these somewhere safe!'
