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

type ldapConn struct {
	ldaplib.Client
	*Config
}


type ldapConn2 struct {
	ldaplib.Client
  
  baseDN string
  userFilter string

}

type Client interface {
  Init(cfg *Config) error
  OpenConn(ctx context.Context) error
  searchBase(filter string, attrs []string) (*ldaplib.SearchResult, error)

  // Bind(userDN, password string) error
  // FindUserDN(username string) (string, error)
}

func (conn *ldapConn2) Init(cfg *Config) error {
  // TODO init userFilter with default value
  return nil
}

func (conn *ldapConn2) OpenConn(ctx context.Context) error {
  return nil
}
func (conn *ldapConn2) searchBase(filter string, attrs []string) (*ldaplib.SearchResult, error) {
  return nil, nil
}

// func (conn *ldapConn2) Close() {
//   conn.Client.Close()
// }

func findUserDN(client Client, username string) (string, error) {
	entry, err := findUserDetails(client, username, []string{"dn"})
	if err != nil {
		return "", err
	}

	return entry["dn"], nil
}

func findUserDetails(client Client, username string, attrs []string) (map[string]string, error) {
	filter := fmt.Sprintf(userFilter, username)
	res, err := client.searchBase(filter, nil)
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

func (conn *ldapConn2) Bind(userDN, password string) error {
  return nil
}


func (conn *ldapConn) makeSearchRequest(filter string, attrs []string) *ldaplib.SearchRequest {
	return ldaplib.NewSearchRequest(conn.Basedn, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
}

func (conn *ldapConn) searchBase(filter string, attrs []string) (*ldaplib.SearchResult, error) {
	res, err := conn.Search(conn.makeSearchRequest(filter, attrs))
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
	err := c.Client.Bind(bindDN, password)
	if ldapErr, ok := err.(*ldaplib.Error); ok && ldapErr.ResultCode == ldaplib.LDAPResultInvalidCredentials {
		return errInvalidCredentials
	}
	return err
}

func (cfg *Config) IsAuthorized(ctx context.Context, username, password string) (bool, error) {
  conn := new(ldapConn2)
  conn.Init(cfg)
  if err := conn.OpenConn(ctx); err != nil {
    return false, err
  }
  defer conn.Close()
  return isAuthorized(ctx, conn, username, password)
}

func isAuthorized(ctx context.Context, cli Client, username, password string) (bool, error) {
  dn, err := findUserDN(cli, username)
  if err != nil {
    return false, err
  }
  if err := bind(dn, password); err != nil {
    return false, err
  }
  return true, nil
}

// func (c *Config) IsAuthorized(ctx context.Context, username, password string) (bool, error) {
// 	conn, err := c.Open(ctx)
// 	if err != nil {
// 		return false, errors.Wrap(err, "trying to open connection failed")
// 	}
// 	defer conn.Close()
// 	// TODO bind ?
// 	userDN, err := conn.findUserDN(username)
// 	if err != nil {
// 		return false, errors.Wrap(err, "trying to find user DN failed")
// 	}

// 	log.Printf("will try to bind with %s", userDN)

// 	if err := conn.Bind(userDN, password); err != nil {
// 		if err == errInvalidCredentials {
// 			return false, nil
// 		}
// 		return false, errors.Wrap(err, "trying to bind failed")
// 	}

// 	return true, nil
// }

func (c *Config) FindOIDCClaims(ctx context.Context, subject string) (map[string]interface{}, error) {
	conn, err := c.Open(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "trying to open connection failed")
	}
	defer conn.Close()
	attrs := make([]string, len(c.Attrs))
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
  tcpcn, err = d.DialContext(ctx, "tcp", c.Endpoint)
  if err != nil {
    return nil, errors.Wrap(err, "open tcp to ldap server failed")
  }

	if c.Tls {
    tcpcn = tls.Client(tcpcn, &tls.Config{InsecureSkipVerify: true})
	}
	ldapcn := ldaplib.NewConn(tcpcn, c.Tls)

	ldapcn.Start()
	return &ldapConn{Client: ldapcn, Config: c}, nil

}
