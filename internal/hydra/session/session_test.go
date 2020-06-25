package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	// "github.com/pkg/errors"
)

func TestGetConsent(t *testing.T) {
	info := &reqInfo{
		subject: "toto",
		reqType: GET_CONSENT_REQ,
	}
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/sessions/consent?subject=toto"))
	assert.NoError(t, err)
	t.Run("error", func(t *testing.T) {
		client := new(fakeClient)
		client.On("Get", ref).Return(
			&http.Response{
				Body:       newClosableBuffer("{}"),
				StatusCode: 404,
			},
			nil,
		)
		var sess []ConsentSession
		err = call(client, info, &sess)
		assert.Error(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		client := new(fakeClient)
		client.On("Get", ref).Return(
			&http.Response{
				Body:       newClosableBuffer(`[{"grant_scope": ["openid"]}]`),
				StatusCode: 200,
			},
			nil,
		)
		var sess []ConsentSession
		err = call(client, info, &sess)
		assert.NoError(t, err)
		assert.Equal(
			t,
			[]ConsentSession{
				{GrantScope: []string{"openid"}},
			},
			sess,
		)
	})
}

func TestRemoveConsent(t *testing.T) {
	info := &reqInfo{
		subject:  "toto",
		clientId: "app",
		reqType:  DEL_CONSENT_REQ,
	}
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/sessions/consent?client=app&subject=toto"))
	assert.NoError(t, err)
	t.Run("hydra error", func(t *testing.T) {
		client := new(fakeClient)
		client.On("Delete", ref).Return(
			&http.Response{
				Body:       newClosableBuffer(`{"error": "sth wrong"}`),
				StatusCode: 500,
			},
			nil,
		)
		err = call(client, info, nil)
		assert.Error(t, err)
		assert.Equal(t, "sth wrong", err.Error())
	})

	t.Run("ok", func(t *testing.T) {
		client := new(fakeClient)
		client.On("Delete", ref).Return(
			&http.Response{
				Body:       newClosableBuffer(``),
				StatusCode: 204,
			},
			nil,
		)
		err = call(client, info, nil)
		assert.NoError(t, err)
	})
}

func TestRemoveLogin(t *testing.T) {
	info := &reqInfo{
		subject: "toto",
		reqType: DEL_LOGIN_REQ,
	}
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/sessions/login?subject=toto"))
	assert.NoError(t, err)
	t.Run("ok", func(t *testing.T) {
		client := new(fakeClient)
		client.On("Delete", ref).Return(
			&http.Response{
				Body:       newClosableBuffer(""),
				StatusCode: 204,
			},
			nil,
		)
		err = call(client, info, nil)
		assert.NoError(t, err)
	})
}

type closableBuffer struct {
	*bytes.Buffer
}

func (b *closableBuffer) Close() error {
	return nil
}
func newClosableBuffer(content string) *closableBuffer {
	return &closableBuffer{
		bytes.NewBufferString(content),
	}
}

type fakeClient struct {
	mock.Mock
}

func (c *fakeClient) GetContext() context.Context {
	return context.Background()
}

func (c *fakeClient) PutJSON(u *url.URL, body io.Reader) (*http.Response, error) {
	args := c.Called(u, body)
	return args.Get(0).(*http.Response), args.Error(1)

}

func (c *fakeClient) Get(u *url.URL) (*http.Response, error) {
	args := c.Called(u)
	return args.Get(0).(*http.Response), args.Error(1)
}

func (c *fakeClient) Delete(u *url.URL) (*http.Response, error) {
	args := c.Called(u)
	return args.Get(0).(*http.Response), args.Error(1)
}
