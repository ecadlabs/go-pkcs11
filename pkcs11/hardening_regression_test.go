//go:build testharness

package pkcs11

import (
	"errors"
	"runtime"
	"sync"
	"testing"

	"github.com/ecadlabs/go-pkcs11/pkcs11/attr"
	"github.com/stretchr/testify/require"
)

func TestGetAttributesConcurrentCallsAreSerialized(t *testing.T) {
	obj := concurrentGetAttrsObject()

	prevProcs := runtime.GOMAXPROCS(0)
	if prevProcs < 4 {
		runtime.GOMAXPROCS(4)
	}
	defer runtime.GOMAXPROCS(prevProcs)

	const workers = 16
	const attempts = 32

	start := make(chan struct{})
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < attempts; j++ {
				var label attr.AttrLabel
				if err := obj.GetAttributes(&label); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.Falsef(t, errors.Is(err, ErrOperationActive), "unexpected concurrent operation: %v", err)
		require.NoError(t, err)
	}
}

func TestGetAttributesRejectsOversizedLength(t *testing.T) {
	obj := oversizedAttrObject()

	var label attr.AttrLabel
	err := obj.GetAttributes(&label)
	require.Error(t, err, "token-reported oversized attribute length should be rejected")
}

func TestSignRejectsOversizedSignatureLength(t *testing.T) {
	key := &RSAPrivateKey{o: oversizedSignObject()}

	sig, err := key.SignPKCS1v15([]byte{1})
	require.Error(t, err, "token-reported oversized signature length should be rejected")
	require.Nil(t, sig)
}

func TestSlotIDsRetriesOnBufferTooSmall(t *testing.T) {
	mod := slotRetryModule()

	ids, err := mod.SlotIDs()
	require.NoError(t, err, "SlotIDs should retry when slot count changes between calls")
	require.Equal(t, []uint{1, 2}, ids)
}
