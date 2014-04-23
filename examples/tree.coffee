caesar = require './../caesar'

cmtr = new caesar.tree.Committer ['herp', 'derp', 'kerp', 'lerp', 'serp']
commit = cmtr.getCommit()

console.log 'Commitment:' , commit.toString 'hex'

proof = cmtr.getProof 1

console.log 'Proof:'
console.log val[0], val[1].toString 'hex' for val in proof

# If any of these values disagree, verify should return false.
console.log caesar.tree.verify commit, 'derp', proof
