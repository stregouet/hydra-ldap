package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/pkg/errors"
	ldaplib "gopkg.in/ldap.v2"

	"github.com/stregouet/hydra-ldap/internal/logging"
)

var (
	// ErrUnauthorize is an error that happens when a user is not member of client-id group
	ErrUnauthorize = fmt.Errorf("unauthorized for this app/client")
	// ErrUserNotFound is an error that happens when requested username is not found in ldap database
	ErrUserNotFound = fmt.Errorf("user not found")
	// ErrInvalidCredentials is an error that happens when a user's password is invalid.
	ErrInvalidCredentials = fmt.Errorf("invalid credentials")
	// errConnectionTimeout is an error that happens when no one LDAP endpoint responds.
	errConnectionTimeout = fmt.Errorf("connection timeout")
	// errMissedUsername is an error that happens
	errMissedUsername = errors.New("username is missed")
	// errUnknownUsername is an error that happens
	errUnknownUsername = errors.New("unknown username")

	// ldap search filter for user
	userFilter = "(&(|(objectClass=organizationalPerson)(objectClass=inetOrgPerson))(|(uid=%[1]s)(mail=%[1]s)(userPrincipalName=%[1]s)(sAMAccountName=%[1]s)))"
	// ldap search filter for roles
	roleFilter = "(member=%s)"
)

type ConnInterface interface {
	openConn(ctx context.Context, endpoint string, istls bool) error
	searchBase(basedn, filter string, attrs []string) (*ldaplib.SearchResult, error)
	Bind(user, password string) error
	Close()
}

type conn struct {
	ldaplib.Client
}

func (c *conn) openConn(ctx context.Context, endpoint string, istls bool) error {
	var tcpcn net.Conn
	var err error
	d := net.Dialer{Timeout: ldaplib.DefaultTimeout}
	tcpcn, err = d.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return errors.Wrap(err, "open tcp to ldap server failed")
	}

	if istls {
		tcpcn = tls.Client(tcpcn, &tls.Config{InsecureSkipVerify: true})
	}
	ldapcn := ldaplib.NewConn(tcpcn, istls)

	ldapcn.Start()
	c.Client = ldapcn
	return nil
}

func (c *conn) searchBase(basedn, filter string, attrs []string) (*ldaplib.SearchResult, error) {
	req := ldaplib.NewSearchRequest(basedn, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
	res, err := c.Search(req)
	if err != nil {
		if ldapErr, ok := err.(*ldaplib.Error); ok && ldapErr.ResultCode == ldaplib.LDAPResultNoSuchObject {
			return nil, errors.Wrap(err, "search failed (probably due to bad `BaseDN`)")
		}
		return nil, err
	}
	return res, nil
}

type client struct {
	ctx  context.Context
	cfg  *Config
	conn ConnInterface

	appId string
}

func (cfg *Config) NewClientWithContext(ctx context.Context) *client {
	return &client{
		ctx:  ctx,
		cfg:  cfg,
		conn: new(conn),
	}
}

func (c *client) WithAppId(appId string) *client {
	c.appId = appId
	return c
}

func (c *client) searchUser(filter string, attrs []string) (*ldaplib.SearchResult, error) {
	return c.conn.searchBase(c.cfg.Basedn, filter, attrs)
}

func (c *client) searchRoles(filter string, attrs []string) (*ldaplib.SearchResult, error) {
	basedn := fmt.Sprintf("ou=%s,%s", c.appId, c.cfg.RoleBaseDN)
	logging.Debug().Str("basedn", basedn).Str("filter", filter).Msg("will search roles")
	return c.conn.searchBase(basedn, filter, attrs)
}

func (c *client) bind(bindDN, password string) error {
	err := c.conn.Bind(bindDN, password)
	if ldapErr, ok := err.(*ldaplib.Error); ok && ldapErr.ResultCode == ldaplib.LDAPResultInvalidCredentials {
		return ErrInvalidCredentials
	}
	return err
}

func (c *client) inAppRole(userDN string) error {
	filter := fmt.Sprintf(roleFilter, userDN)
	res, err := c.searchRoles(filter, []string{"cn"})
	if err != nil {
		return errors.Wrap(err, "while searching roles")
	}
	if len(res.Entries) == 0 {
		return ErrUnauthorize
	}
	return nil
}

func (c *client) findUserDN(username string) (string, error) {
	entry, err := c.findUserDetails(username, make([]string, 0))
	if err != nil {
		return "", err
	}

	return entry["dn"], nil
}

func (c *client) findUserDetails(username string, attrs []string) (map[string]string, error) {
	filter := fmt.Sprintf(userFilter, username)
	res, err := c.searchUser(filter, attrs)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) != 1 {
		return nil, ErrUserNotFound
	}

	var entries []map[string]string
	for _, v := range res.Entries {
		entry := map[string]string{
			"dn": v.DN,
		}
		for _, attr := range v.Attributes {
			// We need the first value only for the named attribute.
			entry[attr.Name] = attr.Values[0]
		}
		entries = append(entries, entry)
	}
	return entries[0], nil
}

func (c *client) IsAuthorized(username, password string) error {
	if err := c.conn.openConn(c.ctx, c.cfg.Endpoint, c.cfg.Tls); err != nil {
		return err
	}
	defer c.conn.Close()
	dn, err := c.findUserDN(username)
	if err != nil {
		return err
	}
	if err := c.bind(dn, password); err != nil {
		return err
	}
	if err := c.inAppRole(dn); err != nil {
		return err
	}
	return nil
}

func (c *client) FindOIDCClaims(subject string) (map[string]string, error) {
	if err := c.conn.openConn(c.ctx, c.cfg.Endpoint, c.cfg.Tls); err != nil {
		return nil, err
	}
	defer c.conn.Close()

	attrs := make([]string, 0)
	for ldapAttrName, _ := range c.cfg.attrsMap() {
		attrs = append(attrs, ldapAttrName)
	}
	details, err := c.findUserDetails(subject, attrs)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]string)

	for ldapAttr, oidcAttr := range c.cfg.attrsMap() {
		if value, ok := details[ldapAttr]; ok {
			claims[oidcAttr] = value
		}
	}
	return claims, nil
}
