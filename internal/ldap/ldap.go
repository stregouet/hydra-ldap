package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/pkg/errors"
	ldaplib "gopkg.in/ldap.v2"
)

var (
	// errUnauthorize is an error that happens when a user is not member of client-id group
	errUnauthorize = fmt.Errorf("unauthorized for this app/client")
	// errInvalidCredentials is an error that happens when a user's password is invalid.
	errInvalidCredentials = fmt.Errorf("invalid credentials")
	// errConnectionTimeout is an error that happens when no one LDAP endpoint responds.
	errConnectionTimeout = fmt.Errorf("connection timeout")
	// errMissedUsername is an error that happens
	errMissedUsername = errors.New("username is missed")
	// errUnknownUsername is an error that happens
	errUnknownUsername = errors.New("unknown username")

	// ldap search filter for user
	userFilter = "(&(|(objectClass=organizationalPerson)(objectClass=inetOrgPerson))(|(uid=%[1]s)(mail=%[1]s)(userPrincipalName=%[1]s)(sAMAccountName=%[1]s)))"
)

// TODO to delete
type Connection struct {
	*Config
}

type ldapConn struct {
	*ldaplib.Conn
	*Config
}

// TODO to delete
func New(cfg *Config) *Connection {
	return &Connection{
		Config: cfg,
	}
}

func (conn *ldapConn) searchBase(filter string, attrs []string) (*ldaplib.SearchResult, error) {
	req := ldaplib.NewSearchRequest(conn.Basedn, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
	res, err := conn.Search(req)
	if err != nil {
		if ldapErr, ok := err.(*ldaplib.Error); ok && ldapErr.ResultCode == ldaplib.LDAPResultNoSuchObject {
			return nil, errors.Wrap(err, "search failed (probably due to bad `BaseDN`)")
		}
		return nil, err
	}
	return res, nil
}

func (conn *ldapConn) findUserDetails(username string, attrs []string) (map[string]string, error) {
	filter := fmt.Sprintf(userFilter, username)
	res, err := conn.searchBase(filter, nil)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("cannot find user")
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

func (conn *ldapConn) findUserDN(username string) (string, error) {
	entry, err := conn.findUserDetails(username, []string{"dn"})
	if err != nil {
		return "", err
	}

	return entry["dn"], nil
}

func (c *ldapConn) Bind(bindDN, password string) error {
	err := c.Conn.Bind(bindDN, password)
	if ldapErr, ok := err.(*ldaplib.Error); ok && ldapErr.ResultCode == ldaplib.LDAPResultInvalidCredentials {
		return errInvalidCredentials
	}
	return err
}

func (c *Config) IsAuthorized(ctx context.Context, username, password string) (bool, error) {
	conn, err := c.Open(ctx)
	if err != nil {
		return false, errors.Wrap(err, "trying to open connection failed")
	}
	defer conn.Close()
	// TODO bind ?
	userDN, err := conn.findUserDN(username)
	if err != nil {
		return false, errors.Wrap(err, "trying to find user DN failed")
	}

	log.Printf("will try to bind with %s", userDN)

	if err := conn.Bind(userDN, password); err != nil {
		if err == errInvalidCredentials {
			return false, nil
		}
		return false, errors.Wrap(err, "trying to bind failed")
	}

	return true, nil
}

func (c *Config) FindOIDCClaims(ctx context.Context, subject string) (map[string]interface{}, error) {
	conn, err := c.Open(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "trying to open connection failed")
	}
	defer conn.Close()
	attrs := []string{"dn"}
	for ldapAttrName, _ := range c.attrsMap() {
		attrs = append(attrs, ldapAttrName)
	}
	details, err := conn.findUserDetails(subject, attrs)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]string)

	for ldapAttr, oidcAttr := range c.attrsMap() {
		if value, ok := details[ldapAttr]; ok {
			claims[oidcAttr] = value
		}
	}
	return nil, nil
}

func (c *Config) Open(ctx context.Context) (*ldapConn, error) {
	var tcpcn net.Conn
	var err error
	d := net.Dialer{Timeout: ldaplib.DefaultTimeout}

	if c.Tls {
		tcpcn, err = tls.DialWithDialer(&d, "tcp", c.Endpoint, nil)
		if err != nil {
			return nil, errors.Wrap(err, "open tls to ldap server failed")
		}
	} else {
		tcpcn, err = d.DialContext(ctx, "tcp", c.Endpoint)
		if err != nil {
			return nil, errors.Wrap(err, "open tcp to ldap server failed")
		}
	}

	ldapcn := ldaplib.NewConn(tcpcn, c.Tls)

	ldapcn.Start()
	return &ldapConn{Conn: ldapcn, Config: c}, nil

}
