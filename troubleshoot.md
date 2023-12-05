trying to run example
```
$ go run suave/devenv/cmd/main.go
# github.com/ethereum/go-ethereum/crypto/secp256k1
cgo: cannot parse gcc output $WORK/b086//_cgo_.o as ELF, Mach-O, PE, XCOFF object
# github.com/ethereum/go-ethereum/rpc
cgo: cannot parse gcc output $WORK/b093//_cgo_.o as ELF, Mach-O, PE, XCOFF object
sylvain@dragonium:~/code/flashbots/suave-geth$ go version
go version go1.19.5 linux/amd64
sylvain@dragonium:~/code/flashbots/suave-geth$ go run suave/devenv/cmd/main.go
# runtime/cgo
cgo: cannot parse $WORK/b094/_cgo_.o as ELF, Mach-O, PE or XCOFF
sylvain@dragonium:~/code/flashbots/suave-geth$ go version
go version go1.21.4 linux/amd64
sylvain@dragonium:~/code/flashbots/suave-geth$ go run suave/devenv/cmd/main.go
# runtime/cgo
cgo: cannot parse $WORK/b092/_cgo_.o as ELF, Mach-O, PE or XCOFF
sylvain@dragonium:~/code/flashbots/suave-geth$ go version
go version go1.20.11 linux/amd64
```
