package session

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/stregouet/hydra-ldap/internal/hydra"
)

func TestFilterSession(t *testing.T) {
	now := time.Now()
	sess := []ConsentSession{
		{
			HandledAt: now,
			ConsentRequest: ConsentReq{
				Client: hydra.ClientInfo{
					Id: "client1",
				},
			},
		},
		{
			HandledAt: now.Add(1 * time.Second),
			ConsentRequest: ConsentReq{
				Client: hydra.ClientInfo{
					Id: "client1",
				},
			},
		},
		{
			HandledAt: now.Add(2 * time.Second),
			ConsentRequest: ConsentReq{
				Client: hydra.ClientInfo{
					Id: "client0",
				},
			},
		},
	}

	expected := []ConsentSession{
		{
			HandledAt: now.Add(1 * time.Second),
			ConsentRequest: ConsentReq{
				Client: hydra.ClientInfo{
					Id: "client1",
				},
			},
		},
		{
			HandledAt: now.Add(2 * time.Second),
			ConsentRequest: ConsentReq{
				Client: hydra.ClientInfo{
					Id: "client0",
				},
			},
		},
	}

	assert.ElementsMatch(t, expected, Filter(sess))
}
