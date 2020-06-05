package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttrsMap(t *testing.T) {
	c := Config{
		Attrs: []string{"name:name", "sn:family_name"},
	}
	result := c.attrsMap()
	expected := map[string]string{
		"name": "name",
		"sn":   "family_name",
	}
	assert.Equal(t, expected, result)
}
