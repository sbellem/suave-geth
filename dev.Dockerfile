FROM golang:1.21.4 as dev

WORKDIR /usr/src/suave-geth
COPY go.mod go.sum .
RUN go mod download

COPY . .
RUN go run build/ci.go install -static ./cmd/geth

ENV FOUNDRY_BIN /root/.foundry/bin
RUN curl -L https://foundry.paradigm.xyz | bash
RUN ${FOUNDRY_BIN}/foundryup
