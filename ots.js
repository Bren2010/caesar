// Generated by CoffeeScript 1.7.1
(function() {
  var crypto, hash, stream,
    __hasProp = {}.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

  crypto = require('crypto');

  stream = require('stream');

  hash = require('./hash');

  exports.generateKey = function(l, k, t) {
    var i, s, si, v, _i, _len, _ref;
    if (l == null) {
      l = 10;
    }
    if (k == null) {
      k = 20;
    }
    if (t == null) {
      t = 256;
    }
    _ref = [[], []], s = _ref[0], v = _ref[1];
    while (s.length !== t) {
      s.push(crypto.randomBytes(l));
    }
    for (i = _i = 0, _len = s.length; _i < _len; i = ++_i) {
      si = s[i];
      v[i] = hash.chain(si, 1, 'sha1').slice(0, l);
    }
    return [[k, v], [k, s]];
  };

  exports.Sign = (function(_super) {
    __extends(Sign, _super);

    function Sign() {
      if (!this instanceof exports.Sign) {
        return new exports.Sign();
      }
      stream.Writable.call(this);
      this.hash = crypto.createHash('sha1');
    }

    Sign.prototype._write = function(chunk, encoding, cb) {
      return this.hash.write(chunk, encoding, cb);
    };

    Sign.prototype.sign = function(privKey) {
      var j, n, out, sig, _ref;
      this.hash.end();
      out = this.hash.read();
      _ref = [0, []], j = _ref[0], sig = _ref[1];
      while (j !== privKey[0]) {
        n = out.readUInt8(j) % privKey[1].length;
        sig.push(privKey[1][n]);
        ++j;
      }
      return sig;
    };

    return Sign;

  })(stream.Writable);

  exports.Verify = (function(_super) {
    __extends(Verify, _super);

    function Verify() {
      if (!this instanceof exports.Verify) {
        return new exports.Verify();
      }
      stream.Writable.call(this);
      this.hash = crypto.createHash('sha1');
    }

    Verify.prototype._write = function(chunk, encoding, cb) {
      return this.hash.write(chunk, encoding, cb);
    };

    Verify.prototype.verify = function(pubKey, sig) {
      var cand, i, j, n, out, _ref;
      this.hash.end();
      out = this.hash.read();
      _ref = [0, []], j = _ref[0], i = _ref[1];
      while (j !== pubKey[0]) {
        n = out.readUInt8(j) % pubKey[1].length;
        cand = hash.chain(sig[j], 1, 'sha1').slice(0, pubKey[1][0].length);
        if (cand.toString('hex') !== pubKey[1][n].toString('hex')) {
          return false;
        }
        ++j;
      }
      return true;
    };

    return Verify;

  })(stream.Writable);

}).call(this);
