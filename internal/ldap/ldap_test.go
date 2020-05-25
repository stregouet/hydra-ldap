package ldap

import (
  "context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
  "github.com/stretchr/testify/assert"
	ldaplib "gopkg.in/ldap.v2"
)

func TestFindUserDN(t *testing.T) {
	c := Config{}
	moq := new(fakeClient)
	conn := ldapConn{
		Client: moq,
		Config: &c,
	}

	moq.On("Search",
    conn.makeSearchRequest(fmt.Sprintf(userFilter, "toto"), nil),
	).Return(
		&ldaplib.SearchResult{
			// Entries: make([]*ldaplib.Entry, 0),
			Entries: []*ldaplib.Entry{
        &ldaplib.Entry{
          DN: "titi",
        },
      },
		},
		nil,
	)

	got, err := conn.findUserDN("toto")
	if err != nil {
		t.Errorf("unexpected error %#v", err)
    return
	}
  assert.Equal(t, "uid=toto,dc=example,dc.com", got)
}


func TestIsAuthorized(t *testing.T) {
  moq := new(fakeMyClient)
  result, err := isAuthorized(context.Background(), moq, "toto", "titi")

}


type fakeMyClient struct {
  mock.Mock
}

func (c *fakeMyClient) Init(cfg *Config) error {
  return nil
}
func (c *fakeMyClient) OpenConn(ctx context.Context) error {
  return nil
}
func (c *fakeMyClient) searchBase(filter string, attrs []string) (*ldaplib.SearchResult, error) {
	args := c.Called(filter, attrs)
	return args.Get(0).(*ldaplib.SearchResult), args.Error(1)
}

type fakeClient struct {
	mock.Mock
}

func (c *fakeClient) Start() {}
func (c *fakeClient) Close() {}
func (c *fakeClient) StartTLS(config *tls.Config) error {
	return nil
}
func (c *fakeClient) SetTimeout(time.Duration) {}
func (c *fakeClient) Bind(username, password string) error {
	return nil
}
func (c *fakeClient) SimpleBind(simpleBindRequest *ldaplib.SimpleBindRequest) (*ldaplib.SimpleBindResult, error) {
	return nil, nil
}
func (c *fakeClient) Add(addRequest *ldaplib.AddRequest) error {
	return nil
}
func (c *fakeClient) Del(delRequest *ldaplib.DelRequest) error {
	return nil
}
func (c *fakeClient) Modify(modifyRequest *ldaplib.ModifyRequest) error {
	return nil
}
func (c *fakeClient) Compare(dn, attribute, value string) (bool, error) {
	return false, nil
}
func (c *fakeClient) PasswordModify(passwordModifyRequest *ldaplib.PasswordModifyRequest) (*ldaplib.PasswordModifyResult, error) {
	return nil, nil
}
func (c *fakeClient) Search(searchRequest *ldaplib.SearchRequest) (*ldaplib.SearchResult, error) {
	args := c.Called(searchRequest)
	return args.Get(0).(*ldaplib.SearchResult), args.Error(1)
}
func (c *fakeClient) SearchWithPaging(searchRequest *ldaplib.SearchRequest, pagingSize uint32) (*ldaplib.SearchResult, error) {
	return nil, nil
}
