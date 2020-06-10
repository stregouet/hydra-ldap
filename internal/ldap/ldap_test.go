package ldap

import (
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	ldaplib "gopkg.in/ldap.v2"
)

// test
//  utilisateur non trouvé
//  utilisateur trouvé mais error de mot de passe
//  utilisateur trouvé et bon mot de passe
func TestIsAuthorized(t *testing.T) {
	var (
		username = "titi"
		dn       = "uid=titi,ou=users,dc=example,dc=com"
		password = "secret"
	)
	t.Run("invalid credential", func(t *testing.T) {
		moq := new(fakeClient)
		moq.On("searchUser",
			fmt.Sprintf(userFilter, username),
			make([]string, 0),
		).Return(
			&ldaplib.SearchResult{
				Entries: []*ldaplib.Entry{
					&ldaplib.Entry{
						DN: dn,
					},
				},
			},
			nil,
		)

		moq.On("bind",
			dn,
			password,
		).Return(
			ldaplib.NewError(ldaplib.LDAPResultInvalidCredentials, errors.New("oups")),
		)

		got, err := isAuthorized(moq, username, password)
		if assert.Error(t, err) {
			assert.Equal(t, errInvalidCredentials, err)
		}
		assert.False(t, got)
	})

	t.Run("user not found", func(t *testing.T) {
		moq := new(fakeClient)
		moq.On("searchUser",
			fmt.Sprintf(userFilter, username),
			make([]string, 0),
		).Return(
			&ldaplib.SearchResult{
				Entries: make([]*ldaplib.Entry, 0),
			},
			nil,
		)

		got, err := isAuthorized(moq, username, password)
		if assert.Error(t, err) {
			assert.Equal(t, errUserNotFound, err)
		}
		assert.False(t, got)
	})

	t.Run("everything ok", func(t *testing.T) {
		moq := new(fakeClient)
		moq.On("searchUser",
			fmt.Sprintf(userFilter, username),
			make([]string, 0),
		).Return(
			&ldaplib.SearchResult{
				Entries: []*ldaplib.Entry{
					&ldaplib.Entry{
						DN: dn,
					},
				},
			},
			nil,
		)
		moq.On("bind",
			dn,
			password,
		).Return(nil)

		got, err := isAuthorized(moq, username, password)
		assert.NoError(t, err)
		assert.True(t, got)
	})
}

func TestOIDCClaims(t *testing.T) {
	var (
		username = "titi"
		dn       = "uid=titi,ou=users,dc=example,dc=com"
	)
	cfg := Config{
		Attrs: []string{"name:name", "sn:family_name"},
	}
	t.Run("user not found", func(t *testing.T) {
		moq := new(fakeClient)
		moq.On("searchUser",
			fmt.Sprintf(userFilter, username),
			[]string{"name", "sn"},
		).Return(
			&ldaplib.SearchResult{
				Entries: make([]*ldaplib.Entry, 0),
			},
			nil,
		)
		_, err := cfg.findOIDCClaims(moq, username)
		assert.Equal(t, errUserNotFound, err)
	})

	t.Run("everything ok", func(t *testing.T) {
		moq := new(fakeClient)
		moq.On("searchUser",
			fmt.Sprintf(userFilter, username),
			[]string{"name", "sn"},
		).Return(
			&ldaplib.SearchResult{
				Entries: []*ldaplib.Entry{
					&ldaplib.Entry{
						DN: dn,
						Attributes: []*ldaplib.EntryAttribute{
							&ldaplib.EntryAttribute{
								Name:   "name",
								Values: []string{"Titi"},
							},
							&ldaplib.EntryAttribute{
								Name:   "sn",
								Values: []string{"Titi Dupont"},
							},
						},
					},
				},
			},
			nil,
		)
		claims, err := cfg.findOIDCClaims(moq, username)
		assert.NoError(t, err)
		expected := map[string]string{
			"name":        "Titi",
			"family_name": "Titi Dupont",
		}
		assert.Equal(t, expected, claims)
	})
}

type fakeClient struct {
	mock.Mock
}

func (c *fakeClient) searchUser(filter string, attrs []string) (*ldaplib.SearchResult, error) {
	if attrs != nil {
		sort.Strings(attrs)
	}
	args := c.Called(filter, attrs)
	return args.Get(0).(*ldaplib.SearchResult), args.Error(1)
}
func (c *fakeClient) bind(bindDN, password string) error {
	args := c.Called(bindDN, password)
	return args.Error(0)
}
