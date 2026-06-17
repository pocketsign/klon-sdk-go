package klon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildAcrValues(t *testing.T) {
	t.Run("single value", func(t *testing.T) {
		require.Equal(t, "urn:klon:acr:high", BuildAcrValues([]string{AcrHigh}))
	})

	t.Run("multiple values", func(t *testing.T) {
		require.Equal(t, "urn:klon:acr:very_high urn:klon:acr:high", BuildAcrValues([]string{AcrVeryHigh, AcrHigh}))
	})

	t.Run("preserves input order", func(t *testing.T) {
		require.Equal(t, "urn:klon:acr:high urn:klon:acr:very_high", BuildAcrValues([]string{AcrHigh, AcrVeryHigh}))
		require.Equal(t, "urn:klon:acr:very_high urn:klon:acr:low urn:klon:acr:high", BuildAcrValues([]string{AcrVeryHigh, AcrLow, AcrHigh}))
	})

	t.Run("appends manual values", func(t *testing.T) {
		require.Equal(t, "urn:klon:acr:high urn:custom:acr", BuildAcrValues([]string{AcrHigh}, "urn:custom:acr"))
	})

	t.Run("deduplicates values", func(t *testing.T) {
		require.Equal(t, "urn:klon:acr:high", BuildAcrValues([]string{AcrHigh}, "urn:klon:acr:high"))
	})

	t.Run("empty input returns empty string", func(t *testing.T) {
		require.Empty(t, BuildAcrValues(nil))
	})

	t.Run("manual values only", func(t *testing.T) {
		require.Equal(t, "urn:custom:acr urn:other:acr", BuildAcrValues(nil, "urn:custom:acr urn:other:acr"))
	})
}

func TestAllAcrValues(t *testing.T) {
	require.Contains(t, AllAcrValues, AcrLow)
	require.Contains(t, AllAcrValues, AcrHigh)
	require.Contains(t, AllAcrValues, AcrVeryHigh)
	require.Len(t, AllAcrValues, 3)
}
