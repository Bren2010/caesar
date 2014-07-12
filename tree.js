// Generated by CoffeeScript 1.7.1
(function() {
  var hash,
    __slice = [].slice;

  hash = require('./hash');

  exports.Committer = (function() {
    function Committer(vals, alg) {
      var c, i;
      this.vals = vals;
      this.alg = alg != null ? alg : 'sha256';
      c = Math.pow(2, Math.ceil(Math.log(this.vals.length) / Math.log(2)));
      c = c - this.vals.length;
      i = 0;
      while (i !== c) {
        this.vals.push('0');
        ++i;
      }
      i = 0;
      while (i !== this.vals.length) {
        this.vals[i] = hash.chain(this.vals[i], 1, this.alg);
        ++i;
      }
    }

    Committer.prototype.getCommit = function() {
      var i, lvl, tmp, v, _ref;
      lvl = this.vals;
      while (lvl.length !== 1) {
        _ref = [0, []], i = _ref[0], tmp = _ref[1];
        while (i !== lvl.length) {
          v = hash.chain(lvl[i].toString() + lvl[i + 1].toString(), 1, this.alg);
          tmp.push(v);
          i = i + 2;
        }
        lvl = tmp;
      }
      return lvl[0];
    };

    Committer.prototype.getProof = function(j) {
      var i, lvl, proof, tmp, v, _ref, _ref1;
      _ref = [this.vals, []], lvl = _ref[0], proof = _ref[1];
      while (lvl.length !== 1) {
        _ref1 = [0, []], i = _ref1[0], tmp = _ref1[1];
        while (i !== lvl.length) {
          if (i === j) {
            proof.push([1, lvl[i + 1]]);
          }
          if ((i + 1) === j) {
            proof.push([0, lvl[i]]);
          }
          if (i === j || (i + 1) === j) {
            j = Math.floor(j / 2);
          }
          v = hash.chain(lvl[i].toString() + lvl[i + 1].toString(), 1, this.alg);
          tmp.push(v);
          i = i + 2;
        }
        lvl = tmp;
      }
      return proof;
    };

    Committer.prototype.getSeveralProof = function() {
      var i, j, lvl, proof, rid, t, tmp, u, v, val, x, _i, _len, _ref, _ref1, _ref2, _ref3;
      j = 1 <= arguments.length ? __slice.call(arguments, 0) : [];
      _ref = [this.vals, [], 0], lvl = _ref[0], proof = _ref[1], rid = _ref[2];
      _ref1 = this.vals;
      for (i in _ref1) {
        val = _ref1[i];
        lvl[i] = [0, val];
      }
      for (_i = 0, _len = j.length; _i < _len; _i++) {
        i = j[_i];
        lvl[i][0] = 1;
      }
      while (lvl.length !== 1) {
        _ref2 = [0, []], i = _ref2[0], tmp = _ref2[1];
        while (i !== lvl.length) {
          x = lvl[i][0] === 0 && lvl[i + 1][0] === 0 ? 0 : 1;
          if (lvl[i][0] === 0 && lvl[i + 1][0] === 1) {
            proof.push([rid, i, lvl[i][1]]);
          } else if (lvl[i][0] === 1 && lvl[i + 1][0] === 0) {
            proof.push([rid, i + 1, lvl[i + 1][1]]);
          }
          _ref3 = [lvl[i][1].toString(), lvl[i + 1][1].toString()], t = _ref3[0], u = _ref3[1];
          v = hash.chain(t + u, 1, this.alg);
          tmp.push([x, v]);
          i = i + 2;
        }
        lvl = tmp;
        ++rid;
      }
      return proof;
    };

    return Committer;

  })();

  exports.forward = function(val, proof, alg) {
    var v, _i, _len;
    if (alg == null) {
      alg = 'sha256';
    }
    val = hash.chain(val, 1, alg);
    for (_i = 0, _len = proof.length; _i < _len; _i++) {
      v = proof[_i];
      if (v[0] === 0) {
        val = hash.chain(v[1].toString() + val.toString(), 1, alg);
      } else {
        val = hash.chain(val.toString() + v[1].toString(), 1, alg);
      }
    }
    return val;
  };

  exports.forwardSeveral = function(vals, size, proof, alg) {
    var i, lvl, rid, t, tmp, u, v, val, _i, _len, _ref, _ref1, _ref2;
    if (alg == null) {
      alg = 'sha256';
    }
    for (i in vals) {
      vals[i].val = hash.chain(vals[i].val, 1, alg);
    }
    _ref = [[], 0], lvl = _ref[0], rid = _ref[1];
    while (lvl.length !== size) {
      lvl.push('0');
    }
    for (_i = 0, _len = vals.length; _i < _len; _i++) {
      val = vals[_i];
      if (val.id < size) {
        lvl[val.id] = val.val;
      }
    }
    while (lvl.length !== 1) {
      _ref1 = [0, []], i = _ref1[0], tmp = _ref1[1];
      while (i !== lvl.length) {
        _ref2 = [lvl[i].toString(), lvl[i + 1].toString()], t = _ref2[0], u = _ref2[1];
        if (lvl[i][0] === '0' && lvl[i + 1] !== '0') {
          if (proof[0][0] === rid && proof[0][1] === i) {
            t = proof[0][2].toString();
            proof.shift();
          } else {
            return false;
          }
        } else if (lvl[i] !== '0' && lvl[i + 1] === '0') {
          if (proof[0][0] === rid && proof[0][1] === (i + 1)) {
            u = proof[0][2].toString();
            proof.shift();
          } else {
            return false;
          }
        }
        if (t === '0' || u === '0') {
          v = '0';
        } else {
          v = hash.chain(t + u, 1, alg);
        }
        tmp.push(v);
        i = i + 2;
      }
      lvl = tmp;
      ++rid;
    }
    if (proof.length !== 0) {
      return false;
    }
    return lvl[0];
  };

  exports.verify = function(commitment, val, proof, alg) {
    if (alg == null) {
      alg = 'sha256';
    }
    val = exports.forward(val, proof, alg);
    return val.toString() === commitment.toString();
  };

  exports.verifySeveral = function(commitment, vals, size, proof, alg) {
    var val;
    if (alg == null) {
      alg = 'sha256';
    }
    val = exports.forwardSeveral(vals, size, proof, alg);
    return val.toString() === commitment.toString();
  };

}).call(this);
