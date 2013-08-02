exports.format = require './format'
exports.key = require './key'
exports.hash = require './hash'
exports.message = require './message'

# Setup some aliases that indicate/encourage common use-cases.
exports.StreamEncrypter = exports.message.Encrypter # Stream data, like sockets.
exports.StreamDecrypter = exports.message.Decrypter

exports.DiskEncrypter = exports.message.XTSEncrypter # Files or chunked data.
exports.DiskDecrypter = exports.message.XTSDecrypter
