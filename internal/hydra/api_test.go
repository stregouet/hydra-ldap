package hydra

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

	"github.com/pkg/errors"
)

func TestGetRequest(t *testing.T) {
	info := &reqInfo{
		challenge: "123",
		reqType:   LOGIN_REQ,
		reqVerb:   GET_VERB,
	}
	ref, err := url.Parse(fmt.Sprintf("oauth2/auth/requests/login?login_challenge=123"))
	assert.NoError(t, err)
	t.Run("challenge not found", func(t *testing.T) {
		client := new(fakeClient)
		client.On("Get", ref).Return(
			&http.Response{
				Body:       newClosableBuffer(""),
				StatusCode: 404,
			},
			nil,
		)
		var bodyResponse interface{}
		err = call(client, info, nil, bodyResponse)
		assert.Equal(t, errors.Cause(err), ErrChallengeNotFound)
	})

	t.Run("unknown error", func(t *testing.T) {
		client := new(fakeClient)
		client.On("Get", ref).Return(
			&http.Response{
				Body:       newClosableBuffer(`{"error": "oups"}`),
				StatusCode: 500,
			},
			nil,
		)
		var bodyResponse interface{}
		err = call(client, info, nil, bodyResponse)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), `"oups"`)
	})

	t.Run("no error", func(t *testing.T) {
		client := new(fakeClient)
		client.On("Get", ref).Return(
			&http.Response{
				Body:       newClosableBuffer(`{}`),
				StatusCode: 200,
			},
			nil,
		)
		var hr HydraResp
		err = call(client, info, nil, &hr)
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
	return nil
}

func (c *fakeClient) PutJSON(u *url.URL, body io.Reader) (*http.Response, error) {
	args := c.Called(u, body)
	return args.Get(0).(*http.Response), args.Error(1)

}

func (c *fakeClient) Get(u *url.URL) (*http.Response, error) {
	args := c.Called(u)
	return args.Get(0).(*http.Response), args.Error(1)
}
