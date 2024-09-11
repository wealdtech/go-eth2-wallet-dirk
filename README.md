# go-eth2-wallet-dirk

[![Tag](https://img.shields.io/github/tag/wealdtech/go-eth2-wallet-dirk.svg)](https://github.com/wealdtech/go-eth2-wallet-dirk/releases/)
[![License](https://img.shields.io/github/license/wealdtech/go-eth2-wallet-dirk.svg)](LICENSE)
[![GoDoc](https://godoc.org/github.com/wealdtech/go-eth2-wallet-dirk?status.svg)](https://godoc.org/github.com/wealdtech/go-eth2-wallet-dirk)
[![Travis CI](https://img.shields.io/travis/wealdtech/go-eth2-wallet-dirk.svg)](https://travis-ci.org/wealdtech/go-eth2-wallet-dirk)
[![codecov.io](https://img.shields.io/codecov/c/github/wealdtech/go-eth2-wallet-dirk.svg)](https://codecov.io/github/wealdtech/go-eth2-wallet-dirk)
[![Go Report Card](https://goreportcard.com/badge/github.com/wealdtech/go-eth2-wallet-dirk)](https://goreportcard.com/report/github.com/wealdtech/go-eth2-wallet-dirk)

[Ethereum 2 wallet](https://github.com/wealdtech/go-eth2-wallet) held by [dirk](https://github.com/attestantio/dirk).


## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Maintainers](#maintainers)
- [Contribute](#contribute)
- [License](#license)

## Install

`go-eth2-wallet-dirk` is a standard Go module which can be installed with:

```sh
go get github.com/wealdtech/go-eth2-wallet-dirk
```

## Usage


Access to the wallet is through the `Open()` call.  
Access to the `wallet` is usually via [go-eth2-wallet](https://github.com/wealdtech/go-eth2-wallet); the first two examples below shows how this can be achieved.

This wallet generates keys non-deterministically, _i.e._ there is no relationship between keys or idea of a "seed".

Wallet and account names may be composed of any valid UTF-8 characters; the only restriction is they can not start with the underscore (`_`) character.

Note that although non-deterministic wallets do not have passphrases they still need to be unlocked before accounts can be created.  This can be carried out with `walllet.Unlock(nil)`

### Example

#### Accessing a wallet
```go
package main

import (
    "github.com/wealdtech/go-eth2-wallet-dirk"
    "google.golang.org/grpc/credentials"
)

func main() {
    // Open a wallet
    wallet, err := dirk.Open(context.Background(),
        dirk.WithName("My wallet"),
        dirk.WithEndpoints([]*Endpoint{
            {"host": "host1.example.com", port: 12345},
            {"host": "host2.example.com", port: 12345},
        }),
        dirk.WithCredentials(credentials.NewTLS(tlsConfig)),
    )
    if err != nil {
        panic(err)
    }

    ...
}
```

#### Generating a distributed account
```go
package main

import (
    "github.com/wealdtech/go-eth2-wallet-dirk"
)

func main() {

    // Open a wallet
    wallet, err := dirk.Open(context.Background(),
        dirk.WithName("My wallet"),
        dirk.WithEndpoints([]*Endpoint{
            {"host": "host1.example.com", port: 12345},
            {"host": "host2.example.com", port: 12345},
        }),
        dirk.WithCredentials(credentials.NewTLS(tlsConfig)),
    )
    if err != nil {
        panic(err)
    }

    // Dirk walllets have their own rules as to if a client is allowed to unlock them.
    err = wallet.(e2wtypes.WalletLocker).Unlock(nil)
    if err != nil {
        panic(err)
    }
    // Always immediately defer locking the wallet to ensure it does not remain unlocked outside of the function.
    defer wallet.(e2wtypes.WalletLocker).Lock()
    
    accountCreator, isAccountCreator := wallet.(e2wtypes.WalletDistributedAccountCreator)
    if !isAccountCreator {
        panic(errors.New("not a distributed account creator"))
    }
    account, err := accountCreator.CreateDistributedAccount(context.Background(),"My account", 2, 3, nil)
    if err != nil {
        panic(err)
    }
    // Wallet should be locked as soon as unlocked operations have finished; it is safe to explicitly call wallet.Lock() as well
    // as defer it as per above.
    wallet.(e2wtypes.WalletLocker).Lock()

    ...
}
```

## Maintainers

Jim McDonald: [@mcdee](https://github.com/mcdee).

## Contribute

Contributions welcome. Please check out [the issues](https://github.com/wealdtech/go-eth2-wallet-nd/issues).

## License

[Apache-2.0](LICENSE) © 2020 Weald Technology Trading Ltd
