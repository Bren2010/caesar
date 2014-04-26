exports.format = require './format' # Formatting
exports.key = require './key' # Key Management
exports.hash = require './hash' # Hashing
exports.message = require './message' # Message Encryption
exports.searchable = require './searchable' # Searchable Encryption
exports.commitment = require './commitment' # Commitments
exports.opse = require './opse' # Order-Preserving Symmetric Encryption

# Hash-only constructions:
exports.ots = require './ots' # One-Time Signature (HORS)
exports.tree = require './tree' # Merkle Tree
exports.kts = require './kts' # k-Time Signature (Merkle-Winternitz Chain)

# Setup some aliases that indicate/encourage common use-cases.
exports.StreamEncrypter = exports.message.Encrypter # Stream data, like sockets.
exports.StreamDecrypter = exports.message.Decrypter

exports.DiskEncrypter = exports.message.XTSEncrypter # Files or chunked data.
exports.DiskDecrypter = exports.message.XTSDecrypter
