package rights

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/openabstractions/abstraction-identity/listen"
)

type Client struct {
	Endpoint string
	Admin    string
}

// ErrNoService, wrapped, is the one error that is not an answer: nothing
// listened at the endpoint. Everything else a Client returns is what the
// service said.
var ErrNoService = errors.New("rights: no service")

func DefaultEndpoint() string { return listen.Endpoint("rights") }

func DefaultStateDir() string {
	d, err := os.UserConfigDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "openabstractions", "rights")
}

func (c *Client) open(req Request) (Response, net.Conn, error) {
	req.Admin = c.Admin
	nc, err := listen.Dial(c.Endpoint)
	if err != nil {
		return Response{}, nil, fmt.Errorf("%w at %s: %v", ErrNoService, c.Endpoint, err)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		nc.Close()
		return Response{}, nil, err
	}
	if _, err := nc.Write(append(raw, '\n')); err != nil {
		nc.Close()
		return Response{}, nil, err
	}
	sc := bufio.NewScanner(nc)
	sc.Buffer(make([]byte, maxLine), maxLine)
	if !sc.Scan() {
		nc.Close()
		return Response{}, nil, errors.New("rights: the service closed the connection")
	}
	var resp Response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		nc.Close()
		return Response{}, nil, err
	}
	if resp.Error != "" {
		nc.Close()
		return Response{}, nil, errors.New(resp.Error)
	}
	return resp, nc, nil
}

func (c *Client) Do(req Request) (Response, error) {
	resp, nc, err := c.open(req)
	if nc != nil {
		nc.Close()
	}
	return resp, err
}

func (c *Client) Register(name string, rights ...string) (string, error) {
	resp, err := c.Do(Request{Op: OpRegister, Name: name, Rights: rights})
	return resp.Secret, err
}

func (c *Client) Ask(secret, right string) (string, time.Time, error) {
	resp, err := c.Do(Request{Op: OpAsk, Secret: secret, Right: right})
	return resp.Token, resp.Expires, err
}

func (c *Client) Check(token string) (App, string, error) {
	resp, err := c.Do(Request{Op: OpCheck, Token: token})
	if err != nil {
		return App{}, "", err
	}
	return *resp.App, resp.Right, nil
}

type Lease struct {
	conn net.Conn
	done chan struct{}
}

func (c *Client) Hold(token, why string) (*Lease, error) {
	_, nc, err := c.open(Request{Op: OpHold, Token: token, Why: why})
	if err != nil {
		return nil, err
	}
	l := &Lease{conn: nc, done: make(chan struct{})}
	go func() {
		nc.Read(make([]byte, 1))
		close(l.done)
	}()
	return l, nil
}

func (l *Lease) Done() <-chan struct{} { return l.done }

func (l *Lease) Release() error { return l.conn.Close() }

func (c *Client) Apps() ([]App, error) {
	resp, err := c.Do(Request{Op: OpApps})
	return resp.Apps, err
}

func (c *Client) Grant(app, right string) error {
	_, err := c.Do(Request{Op: OpGrant, App: app, Right: right})
	return err
}

func (c *Client) Revoke(app, right string) error {
	_, err := c.Do(Request{Op: OpRevoke, App: app, Right: right})
	return err
}

func (c *Client) Forget(app string) error {
	_, err := c.Do(Request{Op: OpForget, App: app})
	return err
}

func (c *Client) Holds() ([]Hold, error) {
	resp, err := c.Do(Request{Op: OpHolds})
	return resp.Holds, err
}
