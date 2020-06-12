package hydra

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalClaim(t *testing.T) {
	t.Run("with roles", func(t *testing.T) {
		c := Claim{
			Details: map[string]string{
				"name":  "Joe",
				"email": "joe@example.com",
			},
			Roles: []string{"user", "admin"},
		}
		expected := map[string]interface{}{
			"name":  "Joe",
			"email": "joe@example.com",
			"roles": []string{"user", "admin"},
		}
		assert.Equal(t, expected, c.prepareMarshal())
	})

	t.Run("without roles", func(t *testing.T) {
		c := Claim{
			Details: map[string]string{
				"name":  "Joe",
				"email": "joe@example.com",
			},
		}
		expected := map[string]interface{}{
			"name":  "Joe",
			"email": "joe@example.com",
		}
		assert.Equal(t, expected, c.prepareMarshal())
	})
}

func TestFilterClaims(t *testing.T) {

	t.Run("one field", func(t *testing.T) {
		cfg := Config{
			ClaimScopes: []string{
				"name:profile",
			},
		}

		initialClaims := Claim{
			Details: map[string]string{
				"family_name": "Dupont",
				"name":        "Jean",
				"email":       "jean.dupont@example.com",
			},
		}
		result := FilterClaims(&cfg, &initialClaims, []string{"profile"})
		expected := &Claim{
			Details: map[string]string{
				"name": "Jean",
			},
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

		initialClaims := Claim{
			Details: map[string]string{
				"family_name": "Dupont",
				"name":        "Jean",
				"email":       "jean.dupont@example.com",
			},
		}
		result := FilterClaims(&cfg, &initialClaims, []string{"profile", "email"})
		expected := &Claim{
			Details: map[string]string{
				"name":  "Jean",
				"email": "jean.dupont@example.com",
			},
		}

		assert.Equal(t, expected, result)
	})
}
