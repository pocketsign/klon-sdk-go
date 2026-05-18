package klon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildScope(t *testing.T) {
	t.Run("single scope", func(t *testing.T) {
		require.Equal(t, "openid", BuildScope(ScopeOpenID))
	})

	t.Run("multiple scopes", func(t *testing.T) {
		require.Equal(t, "openid profile", BuildScope(ScopeOpenID, ScopeProfile))
	})

	t.Run("preserves input order", func(t *testing.T) {
		require.Equal(t, "profile openid", BuildScope(ScopeProfile, ScopeOpenID))
	})

	t.Run("accepts arbitrary strings", func(t *testing.T) {
		require.Equal(t, "openid custom_scope", BuildScope("openid", "custom_scope"))
	})

	t.Run("empty input returns empty string", func(t *testing.T) {
		require.Empty(t, BuildScope())
	})

	t.Run("deduplicates values", func(t *testing.T) {
		require.Equal(t, "openid", BuildScope(ScopeOpenID, ScopeOpenID))
	})
}

func TestAllScopes(t *testing.T) {
	require.Contains(t, AllScopes, ScopeOpenID)
	require.Contains(t, AllScopes, ScopeProfile)
	require.Contains(t, AllScopes, ScopeEmail)
	require.Contains(t, AllScopes, ScopeOfflineAccess)
	require.Contains(t, AllScopes, ScopeAddress)
	require.Contains(t, AllScopes, ScopePhone)
	require.Contains(t, AllScopes, ScopePersonalInfo)
	require.Len(t, AllScopes, 7)
}
