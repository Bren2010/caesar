caesar = require './../caesar'

cmtr = new caesar.tree.Committer ['herp', 'derp', 'kerp', 'lerp', 'serp', 'querp']
commit = cmtr.getCommit()

console.log 'Commitment:' , commit.toString 'hex'
console.log ''

console.log 'Single Proof:'

proof = cmtr.getProof 1

console.log 'Proof:'
console.log val[0], val[1].toString 'hex' for val in proof

# If any of these values disagree, verify should return false.
console.log 'ok?', caesar.tree.verify commit, 'derp', proof

console.log '\n----------------\n'

console.log 'Several Proof:'

proof = cmtr.getSeveralProof 0, 2

console.log 'Proof:'
console.log val[0], val[1], val[2].toString 'hex' for val in proof

# If any of these values disagree, verify should return false.
vals = [
    {id: 0, val: 'herp'},
    {id: 2, val: 'kerp'},
]

console.log 'ok?', caesar.tree.verifySeveral commit, vals, 8, proof
