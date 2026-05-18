package klon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildPrompt(t *testing.T) {
	t.Run("single value", func(t *testing.T) {
		require.Equal(t, "login", BuildPrompt(PromptLogin))
	})

	t.Run("multiple values", func(t *testing.T) {
		require.Equal(t, "login consent", BuildPrompt(PromptLogin, PromptConsent))
	})

	t.Run("deduplicates values", func(t *testing.T) {
		require.Equal(t, "login", BuildPrompt(PromptLogin, PromptLogin))
	})

	t.Run("empty input returns empty string", func(t *testing.T) {
		require.Empty(t, BuildPrompt())
	})

	t.Run("preserves input order", func(t *testing.T) {
		require.Equal(t, "consent login", BuildPrompt(PromptConsent, PromptLogin))
	})
}

func TestAllPrompts(t *testing.T) {
	require.Contains(t, AllPrompts, PromptNone)
	require.Contains(t, AllPrompts, PromptLogin)
	require.Contains(t, AllPrompts, PromptConsent)
	require.Len(t, AllPrompts, 3)
}
