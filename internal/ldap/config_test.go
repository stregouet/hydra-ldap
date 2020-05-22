package ldap

import (
  "reflect"
  "testing"
)

func TestAttrsMap(t *testing.T) {
  c := Config{
    Attrs: []string{"name:name", "sn:family_name"},
  }
  result := c.attrsMap()
  expected := map[string]string{
    "name": "name",
    "sn": "family_name",
  }
  if !reflect.DeepEqual(result, expected) {
    t.Errorf("got %#v, expecting %#v", result, expected)
  }
}
