FROM golang:1.21.4-bookworm

WORKDIR /usr/src/suave-geth
COPY go.mod go.sum interfaces.go .
COPY accounts /usr/src/suave-geth/accounts
#COPY beacon /usr/src/suave-geth/beacon
#COPY cmd /usr/src/suave-geth/cmd
COPY common /usr/src/suave-geth/common
#COPY consensus /usr/src/suave-geth/consensus
#COPY console /usr/src/suave-geth/console
COPY core /usr/src/suave-geth/core
COPY crypto /usr/src/suave-geth/crypto
#COPY eth /usr/src/suave-geth/eth
COPY ethclient /usr/src/suave-geth/ethclient
#COPY ethdb /usr/src/suave-geth/ethdb
#COPY ethstats /usr/src/suave-geth/ethstats
#COPY event /usr/src/suave-geth/event
#COPY graphql /usr/src/suave-geth/graphql
#COPY internal /usr/src/suave-geth/internal
#COPY les /usr/src/suave-geth/les
#COPY light /usr/src/suave-geth/light
COPY log /usr/src/suave-geth/log
COPY metrics /usr/src/suave-geth/metrics
#COPY miner /usr/src/suave-geth/miner
#COPY node /usr/src/suave-geth/node
COPY p2p /usr/src/suave-geth/p2p
COPY params /usr/src/suave-geth/params
COPY rlp /usr/src/suave-geth/rlp
COPY rpc /usr/src/suave-geth/rpc
#COPY signer /usr/src/suave-geth/signer
#COPY swarm /usr/src/suave-geth/swarm
#COPY trie /usr/src/suave-geth/trie

#COPY . .

COPY suave /usr/src/suave-geth/suave
