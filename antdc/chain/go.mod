module github.com/antdaza/antdchain/antdc/chain

go 1.24.11

require (
    github.com/ethereum/go-ethereum v1.16.7
    github.com/hashicorp/golang-lru v1.0.2
    github.com/sirupsen/logrus v1.9.3
)

replace (
    github.com/antdaza/antdchain/antdc/block => ../block
    github.com/antdaza/antdchain/antdc/checkpoints => ../checkpoints
    github.com/antdaza/antdchain/antdc/monitoring => ../monitoring
    github.com/antdaza/antdchain/antdc/p2p => ../p2p
    github.com/antdaza/antdchain/antdc/pow => ../pow
    github.com/antdaza/antdchain/antdc/reward => ../reward
    github.com/antdaza/antdchain/antdc/state => ../state
    github.com/antdaza/antdchain/antdc/tx => ../tx
    github.com/antdaza/antdchain/antdc/vm => ../vm
    github.com/antdaza/antdchain/antdc/rotatingking => ../rotatingking
)
