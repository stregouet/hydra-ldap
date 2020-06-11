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
	// errUnauthorize is an error that happens when a user is not member of client-id group
	errUnauthorize = fmt.Errorf("unauthorized for this app/client")
	// errUserNotFound is an error that happens when requested username is not found in ldap database
	errUserNotFound = fmt.Errorf("user not found")
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
	// ldap search filter for roles
	roleFilter = "(member=%s)"
)

type ldapConn struct {
	ldaplib.Client
	*Config
}

type Client interface {
	searchUser(filter string, attrs []string) (*ldaplib.SearchResult, error)
	searchRoles(filter, appId string, attrs []string) (*ldaplib.SearchResult, error)
	bind(user, password string) error
}

func (conn *ldapConn) Init(cfg *Config) {
	conn.Config = cfg
}

func (conn *ldapConn) OpenConn(ctx context.Context) error {
	var tcpcn net.Conn
	var err error
	d := net.Dialer{Timeout: ldaplib.DefaultTimeout}
	tcpcn, err = d.DialContext(ctx, "tcp", conn.Endpoint)
	if err != nil {
		return errors.Wrap(err, "open tcp to ldap server failed")
	}

	if conn.Tls {
		tcpcn = tls.Client(tcpcn, &tls.Config{InsecureSkipVerify: true})
	}
	ldapcn := ldaplib.NewConn(tcpcn, conn.Tls)

	ldapcn.Start()
	conn.Client = ldapcn
	return nil
}

func (conn *ldapConn) searchUser(filter string, attrs []string) (*ldaplib.SearchResult, error) {
	return conn.searchBase(conn.Basedn, filter, attrs)
}

func (conn *ldapConn) searchRoles(filter, appId string, attrs []string) (*ldaplib.SearchResult, error) {
	basedn := fmt.Sprintf("ou=%s,%s", appId, conn.RoleBaseDN)
	logging.Debug().Str("basedn", basedn).Str("filter", filter).Msg("will search roles")
	return conn.searchBase(basedn, filter, attrs)
}

func (conn *ldapConn) searchBase(basedn, filter string, attrs []string) (*ldaplib.SearchResult, error) {
	req := ldaplib.NewSearchRequest(basedn, ldaplib.ScopeWholeSubtree, ldaplib.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
	res, err := conn.Search(req)
	if err != nil {
		if ldapErr, ok := err.(*ldaplib.Error); ok && ldapErr.ResultCode == ldaplib.LDAPResultNoSuchObject {
			return nil, errors.Wrap(err, "search failed (probably due to bad `BaseDN`)")
		}
		return nil, err
	}
	return res, nil
}

func (conn *ldapConn) bind(bindDN, password string) error {
	return conn.Bind(bindDN, password)
}

func bind(client Client, bindDN, password string) error {
	err := client.bind(bindDN, password)
	if ldapErr, ok := err.(*ldaplib.Error); ok && ldapErr.ResultCode == ldaplib.LDAPResultInvalidCredentials {
		return errInvalidCredentials
	}
	return err
}

func inAppRole(client Client, userDN, appId string) error {
	filter := fmt.Sprintf(roleFilter, userDN)
	res, err := client.searchRoles(filter, appId, []string{"cn"})
	if err != nil {
		return errors.Wrap(err, "while searching roles")
	}
	if len(res.Entries) == 0 {
		return errUnauthorize
	}
	return nil
}

func findUserDN(client Client, username string) (string, error) {
	entry, err := findUserDetails(client, username, make([]string, 0))
	if err != nil {
		return "", err
	}

	return entry["dn"], nil
}

func findUserDetails(client Client, username string, attrs []string) (map[string]string, error) {
	filter := fmt.Sprintf(userFilter, username)
	res, err := client.searchUser(filter, attrs)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) != 1 {
		return nil, errUserNotFound
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

func (cfg *Config) IsAuthorized(ctx context.Context, username, password, appId string) (bool, error) {
	conn := new(ldapConn)
	conn.Init(cfg)
	if err := conn.OpenConn(ctx); err != nil {
		return false, err
	}
	defer conn.Close()
	return isAuthorized(conn, username, password, appId)
}

func isAuthorized(cli Client, username, password, appId string) (bool, error) {
	dn, err := findUserDN(cli, username)
	if err != nil {
		return false, err
	}
	if err := bind(cli, dn, password); err != nil {
		return false, err
	}
	if err := inAppRole(cli, dn, appId); err != nil {
		return false, err
	}
	return true, nil
}

func (cfg *Config) FindOIDCClaims(ctx context.Context, subject string) (map[string]string, error) {
	conn := new(ldapConn)
	conn.Init(cfg)
	if err := conn.OpenConn(ctx); err != nil {
		return nil, err
	}
	defer conn.Close()
	return cfg.findOIDCClaims(conn, subject)
}

func (cfg *Config) findOIDCClaims(client Client, subject string) (map[string]string, error) {
	attrs := make([]string, 0)
	for ldapAttrName, _ := range cfg.attrsMap() {
		attrs = append(attrs, ldapAttrName)
	}
	details, err := findUserDetails(client, subject, attrs)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]string)

	for ldapAttr, oidcAttr := range cfg.attrsMap() {
		if value, ok := details[ldapAttr]; ok {
			claims[oidcAttr] = value
		}
	}
	return claims, nil
}

// func (c *Config) FindOIDCClaims(ctx context.Context, subject string) (map[string]interface{}, error) {
// conn, err := c.Open(ctx)
// if err != nil {
// 	return nil, errors.Wrap(err, "trying to open connection failed")
// }
// defer conn.Close()
// attrs := make([]string, len(c.Attrs))
// for ldapAttrName, _ := range c.attrsMap() {
// 	attrs = append(attrs, ldapAttrName)
// }
// details, err := conn.findUserDetails(subject, attrs)
// if err != nil {
// 	return nil, err
// }
// claims := make(map[string]string)

// for ldapAttr, oidcAttr := range c.attrsMap() {
// 	if value, ok := details[ldapAttr]; ok {
// 		claims[oidcAttr] = value
// 	}
// }
// return nil, nil
// }
