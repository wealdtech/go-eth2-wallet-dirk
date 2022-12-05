// Copyright © 2020 Weald Technology Trading
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dirk_test

// Disabled because it results in a link back to Dirk repository for
//	"github.com/attestantio/dirk/testing/resources"
// func TestCredentials(t *testing.T) {
// 	ctx := context.Background()
//
// 	tests := []struct {
// 		name       string
// 		clientCert []byte
// 		clientKey  []byte
// 		caCert     []byte
// 		err        string
// 	}{
// 		{
// 			name: "Nil",
// 			err:  "failed to load client keypair: tls: failed to find any PEM data in certificate input",
// 		},
// 		{
// 			name:      "ClientCertMissing",
// 			clientKey: resources.ClientTest01Key,
// 			caCert:    resources.CACrt,
// 			err:       "failed to load client keypair: tls: failed to find any PEM data in certificate input",
// 		},
// 		{
// 			name:       "ClientCertCorrupt",
// 			clientCert: bytes.ReplaceAll(resources.ClientTest01Crt, []byte{'M'}, []byte{'N'}),
// 			clientKey:  resources.ClientTest01Key,
// 			caCert:     resources.CACrt,
// 			err:        "failed to load client keypair: asn1: structure error: tags don't match (16 vs {class:0 tag:20 length:1113 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} certificate @4",
// 		},
// 		{
// 			name:       "ClientKeyMissing",
// 			clientCert: resources.ClientTest01Crt,
// 			caCert:     resources.CACrt,
// 			err:        "failed to load client keypair: tls: failed to find any PEM data in key input",
// 		},
// 		{
// 			name:       "ClientKeyCorrupt",
// 			clientCert: resources.ClientTest01Crt,
// 			clientKey:  bytes.ReplaceAll(resources.ClientTest01Key, []byte{'M'}, []byte{'N'}),
// 			caCert:     resources.CACrt,
// 			err:        "failed to load client keypair: tls: failed to parse private key",
// 		},
// 		{
// 			name:       "CACertBlank",
// 			clientCert: resources.ClientTest01Crt,
// 			clientKey:  resources.ClientTest01Key,
// 			caCert:     []byte{},
// 			err:        "failed to add CA certificate",
// 		},
// 		{
// 			name:       "CACertCorrupt",
// 			clientCert: resources.ClientTest01Crt,
// 			clientKey:  resources.ClientTest01Key,
// 			caCert:     bytes.ReplaceAll(resources.CACrt, []byte{'M'}, []byte{'N'}),
// 			err:        "failed to add CA certificate",
// 		},
// 		{
// 			name:       "Good",
// 			clientCert: resources.ClientTest01Crt,
// 			clientKey:  resources.ClientTest01Key,
// 			caCert:     resources.CACrt,
// 		},
// 	}
//
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			_, err := dirk.Credentials(ctx, test.clientCert, test.clientKey, test.caCert)
// 			if test.err != "" {
// 				require.EqualError(t, err, test.err)
// 			} else {
// 				require.NoError(t, err)
// 			}
// 		})
// 	}
// }
