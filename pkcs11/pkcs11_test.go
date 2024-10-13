// Copyright 2021 Google LLC
// Copyright 2024 ECAD Labs Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var requireSoftHSMv2 = flag.Bool("require-libsofthsm2", false,
	"When set, tests will fail if libsofthsm2 is not available.")

const (
	libSoftHSMPathUnix = "/usr/lib/softhsm/libsofthsm2.so"
	libSoftHSMPathMac  = "/opt/homebrew/lib/softhsm/libsofthsm2.so"

	testAdminPIN  = "12345"
	testPIN       = "1234"
	testSlotLabel = "TestSlot"
	testCertLabel = "TestCert"
	testKeyLabel  = "TestKey"
)

// Generated with:
// openssl req -subj '/CN=test' -nodes -x509 -newkey rsa:4096 -keyout /dev/null -out /dev/stdout -days 365
const testCertData = `-----BEGIN CERTIFICATE-----
MIIE/zCCAuegAwIBAgIUSxn81BYTB9S1zx4v6EhCOvx5PU8wDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMTA5MjkwMDI3NTBaFw0yMjA5MjkwMDI3
NTBaMA8xDTALBgNVBAMMBHRlc3QwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQC8boHADxkGDGGRlR2GhhkfT7i/+7KrLg/2Px12dIpATtfAOB2gK0sHZpQ3
cui8MKm6dtICpY7sV+9ZTNGpeiTRxoJ+/9KhzMNwOgY8bBUR8QdFrLOW7pdxuJqs
MLJ6IZKyAb02bwHBcBZbsMOVWK8iqMolsdJ6fPYC+aRRExfQg2dEMX7utGbolBLq
IADgmEVeYH2oRDED+a0MSO8nRsO2ef+L6dB038z+xop5kPwjlyEaF8se/arZhfzN
Tgv0m5FYeNXIdwDRqb1vhKXIRC6HkHkdjyGpJhjx+S+mtAITO/wjiuXVdiq37qQi
aIfP7iahmYCmfFleG/czQWs0DPaAXOlOKCdteeUwhPEN9LAXp4LJTukUiidNvtxq
eb7cRo6rucUSLur3rbaGq/YuSHbHeBLS6VrBQ9QZH1fTCsWqhAhR8zz7qqZZk1M7
LBdsOOByxEAKj9IVkXtQDWeL4iH4PrV8fGb+grrqja6IvgPOm7jO2AbCubPR5V02
yhIAggZIOx3Mu93qzxcrn1Y5TH4QhqgCa8Mvxe2mQrZlla3lTLFY6SW3/N3iMqzb
rZx4u/QThCIovrNUr11RhNU4unFrFIHWWrQg52Zh6dxs7y7lwmtV1a4trtM54jsK
DmBWGovSSRwmrOHyp5xSUWTIe0cF4yhgXzKYZsB8kcKzQoX8TwIDAQABo1MwUTAd
BgNVHQ4EFgQUZzvuma3BmzFhKWb64Y2PVq/+aK0wHwYDVR0jBBgwFoAUZzvuma3B
mzFhKWb64Y2PVq/+aK0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AgEAGTtRUGa1Xhx633QWPFgdx3Ylg1paIve882AT1mUN+MyJ88Cx1wvXQwJsf2TI
6iE4uj2PLQvpt6mrNqT1ItdN4iyfCiXqkzZJ1uXOnneJujk+IuhHbUgP78vYSrZO
2akl9S3BgwvDLcV6EOXfo5ERU8rTWfYu64tDNQcaxP0pNoyD6um5BsmB2Jxznn4F
HbrQcBFh4hli1cAbjXeXWgnWuT6Ajz0L98fKaDhx3D7ggMPYd64/XVQBZSw2gCRJ
9i26kFdbmLz6nDq8RKoiXy8dOgtyCj26QevoDlsq5fIdqDATScKL1/cKBFiwT2h0
nbxl1SqoXvP4QRuB7444LEmPrU2TIIhaICoHnCTmr5P2CB4PL8KggVyKHWb3eYR9
5/HsXJA21uQqezNhr+mKTtAob4kpWt1MoICul7uIy4fwjeCcCQpOCBlVt11uroN+
0OqSY5CDjQfZ+2C1gLdKUZ7nomRuBdxWh+f48dtIh46vkw/dXN5prmU7j8QoAbfr
40+3biWKDfbCJ0auEucdM3tLGxim1HlKf7ROmrrS8gEBH23Ww3ibKPBnNiQvTK/L
nBPryTEU4DaFuWh36J5tGuqZFCo9S58dCmajvhAMs2hpw4u6tLCaiaqtUByGnDv9
6ymrXrM0Nw+Ri1Lz+EMZ71I5uC4BItv+uZNm3XJz+/CDrMw=
-----END CERTIFICATE-----`

func newSession(t *testing.T, m *Module) (*Session, error) {
	ids, err := m.SlotIDs()
	require.NoError(t, err)

	id := ids[len(ids)-1]
	opts := createSlotOptions{
		SecurityOfficerPIN: testAdminPIN,
		UserPIN:            testPIN,
		Label:              testSlotLabel,
	}
	if err := m.createSlot(id, opts); err != nil {
		return nil, err
	}

	s, err := m.NewSession(id, OptUserPIN(testPIN), OptReadWrite)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		require.NoError(t, s.Close())
	})

	return s, nil
}

func TestPKCS11(t *testing.T) {
	var path string
	if runtime.GOOS == "darwin" {
		path = libSoftHSMPathMac
	} else {
		path = libSoftHSMPathUnix
	}

	if _, err := os.Stat(path); err != nil {
		if *requireSoftHSMv2 {
			t.Fatalf("libsofthsm2 not installed")
		}
		t.Skipf("libsofthsm2 not installed, skipping testing")
	}

	// See softhsm2.conf(5) for config details
	configPath := filepath.Join(t.TempDir(), "softhsm.conf")
	tokensPath := t.TempDir()

	configData := fmt.Sprintf(`
directories.tokendir = %s
`, tokensPath)
	if err := os.WriteFile(configPath, []byte(configData), 0644); err != nil {
		t.Fatalf("write softhsm config: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", configPath)

	m, err := Open(path)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, m.Close())
	})

	t.Run("Info", func(t *testing.T) {
		info := m.Info()
		require.Equal(t, "SoftHSM", info.Manufacturer)
	})

	ids, err := m.SlotIDs()
	require.NoError(t, err)
	require.Len(t, ids, 1)
	info, err := m.SlotInfo(ids[0])
	require.NoError(t, err)
	require.Equal(t, "SoftHSM project", info.Manufacturer)
	require.Equal(t, SlotTokenPresent, info.Flags)
	if assert.NotNil(t, info.Token) {
		require.Equal(t, TokenRNG|TokenLoginRequired|TokenRestoreKeyNotNeeded|TokenSOPinLocked|TokenSOPinToBeChanged, info.Token.Flags)
	}

	ecdsaTests := []*struct {
		session *Session
		name    string
		opt     ecdsaKeyOptions
	}{
		{
			name: "P256",
			opt: ecdsaKeyOptions{
				Curve:        elliptic.P256(),
				LabelPublic:  testKeyLabel,
				LabelPrivate: testKeyLabel,
			},
		},
		{
			name: "P384",
			opt: ecdsaKeyOptions{
				Curve:        elliptic.P384(),
				LabelPublic:  testKeyLabel,
				LabelPrivate: testKeyLabel,
			},
		},
		{
			name: "P521",
			opt: ecdsaKeyOptions{
				Curve:        elliptic.P521(),
				LabelPublic:  testKeyLabel,
				LabelPrivate: testKeyLabel,
			},
		},
		{
			name: "S256",
			opt: ecdsaKeyOptions{
				Curve:        secp256k1.S256(),
				LabelPublic:  testKeyLabel,
				LabelPrivate: testKeyLabel,
			},
		},
	}

	for _, tt := range ecdsaTests {
		s, err := newSession(t, m)
		require.NoError(t, err)
		tt.session = s
	}

	t.Run("ECDSA", func(t *testing.T) {
		for _, test := range ecdsaTests {
			t.Run(test.name, func(t *testing.T) {
				priv, err := test.session.generateECDSA(&test.opt)
				require.NoError(t, err)

				t.Run("SlotInfo", func(t *testing.T) {
					info, err := test.session.SlotInfo()
					require.NoError(t, err)
					require.Equal(t, "SoftHSM project", info.Manufacturer)
					require.Equal(t, SlotTokenPresent, info.Flags)
					if assert.NotNil(t, info.Token) {
						require.Equal(t, TokenRNG|TokenLoginRequired|TokenUserPinInitialized|TokenRestoreKeyNotNeeded|TokenTokenInitialized, info.Token.Flags)
					}
				})

				t.Run("Objects", func(t *testing.T) {
					objs, err := test.session.Objects()
					require.NoError(t, err)

					expect := []struct {
						class Class
						label string
					}{
						{ClassPublicKey, test.opt.LabelPublic},
						{ClassPrivateKey, test.opt.LabelPrivate},
					}
					for i, o := range objs {
						require.Equal(t, expect[i].class, o.Class())
						require.Equal(t, expect[i].label, o.Label())
					}
				})

				t.Run("Public", func(t *testing.T) {
					objs, err := test.session.Objects(FilterClass(ClassPublicKey))
					require.NoError(t, err)
					require.Equal(t, 1, len(objs))
					obj := objs[0]
					pub, err := obj.PublicKey()
					require.NoError(t, err)

					_, ok := pub.(*ecdsa.PublicKey)
					require.True(t, ok, "unexpected key type %T", pub)
				})

				t.Run("Sign", func(t *testing.T) {
					kp, err := priv.KeyPair(MatchID | MatchLabel)
					require.NoError(t, err)

					signer, ok := kp.(crypto.Signer)
					require.True(t, ok, "unexpected key type %T", kp)
					pub, ok := signer.Public().(*ecdsa.PublicKey)
					require.True(t, ok, "unexpected key type %T", signer.Public())

					digest := sha256.Sum256([]byte("test"))

					sig, err := signer.Sign(rand.Reader, digest[:], nil)
					require.NoError(t, err)
					require.True(t, ecdsa.VerifyASN1(pub, digest[:], sig))
				})
			})
		}
	})

	edSession, err := newSession(t, m)
	require.NoError(t, err)

	t.Run("Ed25519", func(t *testing.T) {
		priv, err := edSession.generateEd25519(&ed25519KeyOptions{
			LabelPublic:  testKeyLabel,
			LabelPrivate: testKeyLabel,
		})
		require.NoError(t, err)

		t.Run("SlotInfo", func(t *testing.T) {
			info, err := edSession.SlotInfo()
			require.NoError(t, err)
			require.Equal(t, "SoftHSM project", info.Manufacturer)
			require.Equal(t, SlotTokenPresent, info.Flags)
			if assert.NotNil(t, info.Token) {
				require.Equal(t, TokenRNG|TokenLoginRequired|TokenUserPinInitialized|TokenRestoreKeyNotNeeded|TokenTokenInitialized, info.Token.Flags)
			}
		})

		t.Run("Objects", func(t *testing.T) {
			objs, err := edSession.Objects()
			require.NoError(t, err)

			expect := []struct {
				class Class
				label string
			}{
				{ClassPublicKey, testKeyLabel},
				{ClassPrivateKey, testKeyLabel},
			}
			for i, o := range objs {
				require.Equal(t, expect[i].class, o.Class())
				require.Equal(t, expect[i].label, o.Label())
			}
		})

		t.Run("Public", func(t *testing.T) {
			objs, err := edSession.Objects(FilterClass(ClassPublicKey))
			require.NoError(t, err)
			require.Equal(t, 1, len(objs))
			obj := objs[0]
			pub, err := obj.PublicKey()
			require.NoError(t, err)

			pub, ok := pub.(ed25519.PublicKey)
			require.True(t, ok, "unexpected key type %T", pub)
			require.Len(t, pub, ed25519.PublicKeySize)
		})

		t.Run("Sign", func(t *testing.T) {
			kp, err := priv.KeyPair(MatchID | MatchLabel)
			require.NoError(t, err)

			signer, ok := kp.(crypto.Signer)
			require.True(t, ok, "unexpected key type %T", kp)
			pub, ok := signer.Public().(ed25519.PublicKey)
			require.True(t, ok, "unexpected key type %T", signer.Public())

			digest := sha256.Sum256([]byte("test"))

			sig, err := signer.Sign(rand.Reader, digest[:], nil)
			require.NoError(t, err)
			require.True(t, ed25519.Verify(pub, digest[:], sig))
		})
	})

	certSession, err := newSession(t, m)
	require.NoError(t, err)

	t.Run("Certificate", func(t *testing.T) {
		b, _ := pem.Decode([]byte(testCertData))
		require.NotNil(t, b)
		cert, err := x509.ParseCertificate(b.Bytes)
		require.NoError(t, err)

		opt := createCertificateOptions{
			X509Certificate: cert,
			Label:           testCertLabel,
		}
		o, err := certSession.createX509Certificate(opt)
		require.NoError(t, err)

		c, err := o.Certificate()
		require.NoError(t, err)

		gotCert, err := c.X509()
		require.NoError(t, err)

		require.Equal(t, cert.Raw, gotCert.Raw)
	})
}
