module github.com/wealdtech/go-eth2-wallet-dirk

go 1.14

require (
	github.com/attestantio/dirk v0.9.0
	github.com/google/uuid v1.1.2
	github.com/herumi/bls-eth-go-binary v0.0.0-20201008062400-71567a52ad65
	github.com/jackc/puddle v1.1.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.6.1
	github.com/wealdtech/eth2-signer-api v1.6.0
	github.com/wealdtech/go-eth2-types/v2 v2.5.0
	github.com/wealdtech/go-eth2-wallet v1.14.1 // indirect
	github.com/wealdtech/go-eth2-wallet-encryptor-unencrypted v1.0.0 // indirect
	github.com/wealdtech/go-eth2-wallet-types/v2 v2.8.0
	golang.org/x/sys v0.0.0-20201014080544-cc95f250f6bc // indirect
	google.golang.org/genproto v0.0.0-20201013134114-7f9ee70cb474 // indirect
	google.golang.org/grpc v1.33.0
)

replace github.com/attestantio/dirk => ../../attestantio/dirk
