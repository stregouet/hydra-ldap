package hydra

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterClaims(t *testing.T) {

	t.Run("one field", func(t *testing.T) {
		cfg := Config{
			ClaimScopes: []string{
				"name:profile",
			},
		}

		initialClaims := map[string]string{
			"family_name": "Dupont",
			"name":        "Jean",
			"email":       "jean.dupont@example.com",
		}
		result := FilterClaims(&cfg, initialClaims, []string{"profile"})
		expected := map[string]string{
			"name": "Jean",
		}

		assert.Equal(t, expected, result)
	})

	t.Run("profile and email scope", func(t *testing.T) {
		cfg := Config{
			ClaimScopes: []string{
				"name:profile",
				"email:email",
			},
		}

		initialClaims := map[string]string{
			"family_name": "Dupont",
			"name":        "Jean",
			"email":       "jean.dupont@example.com",
		}
		result := FilterClaims(&cfg, initialClaims, []string{"profile", "email"})
		expected := map[string]string{
			"name":  "Jean",
			"email": "jean.dupont@example.com",
		}

		assert.Equal(t, expected, result)
	})
}
