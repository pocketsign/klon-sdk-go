package klon

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildAuthorizationDetails(t *testing.T) {
	t.Run("single resource access", func(t *testing.T) {
		result, err := BuildAuthorizationDetails([]AuthorizationDetailInput{
			{Identifiers: []string{ResourceMergedFullName}, Actions: []ResourceAction{ResourceActionRead}},
		})
		require.NoError(t, err)

		var parsed []AuthorizationDetail
		require.NoError(t, json.Unmarshal([]byte(result), &parsed))
		require.Len(t, parsed, 1)
		require.Equal(t, "urn:klon:resource_access", parsed[0].Type)
		require.Equal(t, []string{"klon/merged_full_name"}, parsed[0].Identifiers)
		require.Equal(t, []ResourceAction{"read"}, parsed[0].Actions)
	})

	t.Run("multiple resource accesses", func(t *testing.T) {
		boolTrue := true
		result, err := BuildAuthorizationDetails([]AuthorizationDetailInput{
			{Identifiers: []string{ResourceMergedFullName}, Actions: []ResourceAction{ResourceActionRead}, Required: &boolTrue},
			{Identifiers: []string{ResourceMergedFullAddress}, Actions: []ResourceAction{ResourceActionRead}},
		})
		require.NoError(t, err)

		var parsed []json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(result), &parsed))
		require.Len(t, parsed, 2)

		var first map[string]any
		require.NoError(t, json.Unmarshal(parsed[0], &first))
		require.Equal(t, true, first["required"])

		var second map[string]any
		require.NoError(t, json.Unmarshal(parsed[1], &second))
		_, hasRequired := second["required"]
		require.False(t, hasRequired)
	})

	t.Run("required and prefill", func(t *testing.T) {
		boolTrue := true
		result, err := BuildAuthorizationDetails([]AuthorizationDetailInput{
			{
				Identifiers: []string{ResourceMergedFullName},
				Actions:     []ResourceAction{ResourceActionRead},
				Required:    &boolTrue,
				Prefill:     &boolTrue,
			},
		})
		require.NoError(t, err)

		var parsed []map[string]any
		require.NoError(t, json.Unmarshal([]byte(result), &parsed))
		require.Equal(t, true, parsed[0]["required"])
		require.Equal(t, true, parsed[0]["prefill"])
	})

	t.Run("omits required/prefill when nil", func(t *testing.T) {
		result, err := BuildAuthorizationDetails([]AuthorizationDetailInput{
			{Identifiers: []string{ResourceMergedFullName}, Actions: []ResourceAction{ResourceActionRead}},
		})
		require.NoError(t, err)

		var parsed []map[string]any
		require.NoError(t, json.Unmarshal([]byte(result), &parsed))
		_, hasRequired := parsed[0]["required"]
		_, hasPrefill := parsed[0]["prefill"]
		require.False(t, hasRequired)
		require.False(t, hasPrefill)
	})

	t.Run("read and write actions", func(t *testing.T) {
		result, err := BuildAuthorizationDetails([]AuthorizationDetailInput{
			{Identifiers: []string{"your-org/custom"}, Actions: []ResourceAction{ResourceActionRead, ResourceActionWrite}},
		})
		require.NoError(t, err)

		var parsed []AuthorizationDetail
		require.NoError(t, json.Unmarshal([]byte(result), &parsed))
		require.Equal(t, []ResourceAction{"read", "write"}, parsed[0].Actions)
	})

	t.Run("empty input returns empty JSON array", func(t *testing.T) {
		result, err := BuildAuthorizationDetails(nil)
		require.NoError(t, err)
		require.Equal(t, "[]", result)
	})

	t.Run("type is auto-populated", func(t *testing.T) {
		result, err := BuildAuthorizationDetails([]AuthorizationDetailInput{
			{Identifiers: []string{ResourceMergedFullName}, Actions: []ResourceAction{ResourceActionRead}},
		})
		require.NoError(t, err)

		var parsed []AuthorizationDetail
		require.NoError(t, json.Unmarshal([]byte(result), &parsed))
		require.Equal(t, "urn:klon:resource_access", parsed[0].Type)
	})
}

func TestParseAuthorizationDetails(t *testing.T) {
	t.Run("parses valid JSON array", func(t *testing.T) {
		input := `[{"type":"urn:klon:resource_access","identifiers":["klon/merged_full_name"],"actions":["read"]}]`
		result, err := ParseAuthorizationDetails(input)
		require.NoError(t, err)
		require.Len(t, result, 1)
		require.Equal(t, "urn:klon:resource_access", result[0].Type)
		require.Equal(t, []string{"klon/merged_full_name"}, result[0].Identifiers)
		require.Equal(t, []ResourceAction{"read"}, result[0].Actions)
	})

	t.Run("parses required and prefill", func(t *testing.T) {
		input := `[{"type":"urn:klon:resource_access","identifiers":["klon/merged_full_name"],"actions":["read","write"],"required":true,"prefill":false}]`
		result, err := ParseAuthorizationDetails(input)
		require.NoError(t, err)
		require.NotNil(t, result[0].Required)
		require.True(t, *result[0].Required)
		require.NotNil(t, result[0].Prefill)
		require.False(t, *result[0].Prefill)
	})

	t.Run("parses empty array", func(t *testing.T) {
		result, err := ParseAuthorizationDetails("[]")
		require.NoError(t, err)
		require.Empty(t, result)
	})

	t.Run("error on invalid JSON", func(t *testing.T) {
		_, err := ParseAuthorizationDetails("invalid json")
		require.ErrorContains(t, err, "failed to parse authorization_details")
	})

	t.Run("error on non-array JSON", func(t *testing.T) {
		_, err := ParseAuthorizationDetails(`{"type": "object"}`)
		require.ErrorContains(t, err, "authorization_details must be an array")
	})

	t.Run("error on invalid type", func(t *testing.T) {
		input := `[{"type":"invalid_type","identifiers":["klon/merged_full_name"],"actions":["read"]}]`
		_, err := ParseAuthorizationDetails(input)
		require.ErrorContains(t, err, "authorization_details[0]")
	})

	t.Run("error on invalid action", func(t *testing.T) {
		input := `[{"type":"urn:klon:resource_access","identifiers":["klon/merged_full_name"],"actions":["read","delete"]}]`
		_, err := ParseAuthorizationDetails(input)
		require.ErrorContains(t, err, "authorization_details[0]")
	})

	t.Run("error on non-boolean required", func(t *testing.T) {
		input := `[{"type":"urn:klon:resource_access","identifiers":["klon/merged_full_name"],"actions":["read"],"required":"yes"}]`
		_, err := ParseAuthorizationDetails(input)
		require.ErrorContains(t, err, "authorization_details[0]")
	})
}

func TestResourceConstants(t *testing.T) {
	require.Equal(t, "klon/signing_first_name", ResourceSigningFirstName)
	require.Equal(t, "klon/merged_full_name", ResourceMergedFullName)
	require.Equal(t, "klon/email_address", ResourceEmailAddress)
	require.Equal(t, "klon/face_image", ResourceFaceImage)
}
