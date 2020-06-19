package ldap

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	ldaplib "gopkg.in/ldap.v2"

	"github.com/stregouet/hydra-ldap/internal/hydra"
)

func TestIsAuthorized(t *testing.T) {
	var (
		username = "titi"
		dn       = "uid=titi,ou=users,dc=example,dc=com"
		password = "secret"
	)
	t.Run("invalid credential", func(t *testing.T) {
		c, moq := makeClient(nil)
		moq.On("searchBase",
			"ou=users",
			fmt.Sprintf(userFilter, username),
			make([]string, 0),
		).Return(
			makeLdapResult([]map[string]string{
				{"dn": dn},
			}),
			nil,
		)

		moq.On("Bind",
			dn,
			password,
		).Return(
			ldaplib.NewError(ldaplib.LDAPResultInvalidCredentials, errors.New("oups")),
		)

		err := c.IsAuthorized(username, password)
		if assert.Error(t, err) {
			assert.Equal(t, ErrInvalidCredentials, err)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		c, moq := makeClient(nil)
		moq.On("searchBase",
			"ou=users",
			fmt.Sprintf(userFilter, username),
			make([]string, 0),
		).Return(
			makeLdapResult(make([]map[string]string, 0)),
			nil,
		)

		err := c.IsAuthorized(username, password)
		if assert.Error(t, err) {
			assert.Equal(t, ErrUserNotFound, err)
		}
	})

	t.Run("user not in group", func(t *testing.T) {
		c, moq := makeClient(nil)
		moq.On("searchBase",
			"ou=users",
			fmt.Sprintf(userFilter, username),
			make([]string, 0),
		).Return(
			makeLdapResult([]map[string]string{
				{"dn": dn},
			}),
			nil,
		)
		moq.On("searchBase",
			"ou=client-id,ou=groups",
			fmt.Sprintf(roleFilter, dn),
			[]string{"cn"},
		).Return(
			makeLdapResult([]map[string]string{}),
			nil,
		)
		moq.On("Bind",
			dn,
			password,
		).Return(nil)

		err := c.IsAuthorized(username, password)
		if assert.Error(t, err) {
			assert.Equal(t, ErrUnauthorize, errors.Cause(err))
		}
	})

	t.Run("everything ok", func(t *testing.T) {
		c, moq := makeClient(nil)
		moq.On("searchBase",
			"ou=users",
			fmt.Sprintf(userFilter, username),
			make([]string, 0),
		).Return(
			makeLdapResult([]map[string]string{
				{"dn": dn},
			}),
			nil,
		)
		moq.On("searchBase",
			"ou=client-id,ou=groups",
			fmt.Sprintf(roleFilter, dn),
			[]string{"cn"},
		).Return(
			makeLdapResult([]map[string]string{
				{"cn": "admin"},
			}),
			nil,
		)
		moq.On("Bind",
			dn,
			password,
		).Return(nil)

		err := c.IsAuthorized(username, password)
		assert.NoError(t, err)
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
		c, moq := makeClient(&cfg)
		moq.On("searchBase",
			"ou=users",
			fmt.Sprintf(userFilter, username),
			[]string{"name", "sn"},
		).Return(
			makeLdapResult(make([]map[string]string, 0)),
			nil,
		)
		_, err := c.FindOIDCClaims(username)
		assert.Equal(t, ErrUserNotFound, err)
	})

	t.Run("everything ok", func(t *testing.T) {
		c, moq := makeClient(&cfg)
		moq.On("searchBase",
			"ou=users",
			fmt.Sprintf(userFilter, username),
			[]string{"name", "sn"},
		).Return(
			makeLdapResult([]map[string]string{
				{"dn": dn, "name": "Titi", "sn": "Titi Dupont"},
			}),
			nil,
		)
		moq.On("searchBase",
			"ou=client-id,ou=groups",
			fmt.Sprintf(roleFilter, dn),
			[]string{"cn"},
		).Return(
			makeLdapResult([]map[string]string{
				{"cn": "admin"},
			}),
			nil,
		)
		claims, err := c.FindOIDCClaims(username)
		assert.NoError(t, err)
		expected := hydra.Claim{
			Details: map[string]string{
				"name":        "Titi",
				"family_name": "Titi Dupont",
			},
			Roles: []string{"admin"},
		}
		assert.Equal(t, &expected, claims)
	})
}

func makeLdapResult(entries []map[string]string) *ldaplib.SearchResult {
	result := ldaplib.SearchResult{Entries: make([]*ldaplib.Entry, 0)}
	for _, entry := range entries {
		ldapEntry := new(ldaplib.Entry)
		for k, v := range entry {
			if k == "dn" {
				ldapEntry.DN = v
			} else {
				ldapEntry.Attributes = append(ldapEntry.Attributes, &ldaplib.EntryAttribute{
					Name:   k,
					Values: []string{v},
				})
			}
		}
		result.Entries = append(result.Entries, ldapEntry)
	}
	return &result
}

type fakeConn struct {
	mock.Mock
}

func makeClient(cfg *Config) (client, *fakeConn) {
	moq := new(fakeConn)
	if cfg == nil {
		cfg = new(Config)
	}
	if cfg.RoleBaseDN == "" {
		cfg.RoleBaseDN = "ou=groups"
	}
	if cfg.Basedn == "" {
		cfg.Basedn = "ou=users"
	}
	ctx := context.Background()
	moq.On("openConn", ctx, "", false).Return(nil)
	moq.On("Close").Return()
	return client{
		ctx:   ctx,
		appId: "client-id",
		cfg:   cfg,
		conn:  moq,
	}, moq
}

func (c *fakeConn) openConn(ctx context.Context, endpoint string, istls bool) error {
	args := c.Called(ctx, endpoint, istls)
	return args.Error(0)
}
func (c *fakeConn) Close() {
	c.Called()
}
func (c *fakeConn) searchBase(basedn, filter string, attrs []string) (*ldaplib.SearchResult, error) {
	if attrs != nil {
		sort.Strings(attrs)
	}
	args := c.Called(basedn, filter, attrs)
	return args.Get(0).(*ldaplib.SearchResult), args.Error(1)
}
func (c *fakeConn) Bind(username, password string) error {
	args := c.Called(username, password)
	return args.Error(0)
}
