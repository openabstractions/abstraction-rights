package rights

import (
	"bufio"

	"encoding/json"
	"errors"
	"fmt"
	"github.com/openabstractions/abstraction-identity/listen"
	"testing"
)

func TestClientRefusalCompatibility(t *testing.T) {
	for _, tc := range []struct{ name, frame, code, message string }{
		{"legacy", `{"error":"old server refusal"}`, "", "old server refusal"},
		{"unknown", `{"code":"future_code","error":"new refusal"}`, "future_code", "new refusal"},
		{"code_only", `{"code":"future_code"}`, "future_code", ""},
		{"known", `{"code":"` + CodeBadToken + `","error":"human reason"}`, CodeBadToken, "human reason"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := endpoint(t, t.TempDir(), "rights-codes")
			listener, err := listen.Listen(at)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				c, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer c.Close()
				if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
					done <- err
					return
				}
				_, err = fmt.Fprintln(c, tc.frame)
				done <- err
			}()
			_, err = (&Client{Endpoint: at}).Do(Request{})
			var remote *RemoteError
			if !errors.As(err, &remote) {
				t.Fatalf("not a remote refusal: %v", err)
			}
			if remote.Code != tc.code || remote.Message != tc.message {
				t.Fatalf("lost refusal: %+v", remote)
			}
			if err.Error() == "" {
				t.Fatal("empty refusal text")
			}
			if serverErr := <-done; serverErr != nil {
				t.Fatal(serverErr)
			}
		})
	}
}

func TestRefusalWireCompatibility(t *testing.T) {
	raw, err := json.Marshal(Response{Code: CodeBadToken, Error: "unchanged"})
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if old.Error != "unchanged" {
		t.Fatal("old client lost error")
	}
	if (Response{}).Err() != nil {
		t.Fatal("success became refusal")
	}
}

func TestRefusalKeepsSentinel(t *testing.T) {
	original := fmt.Errorf("context: %w", ErrBadToken)
	raw, err := json.Marshal(failure(original))
	if err != nil {
		t.Fatal(err)
	}
	var received Response
	if err := json.Unmarshal(raw, &received); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(received.Err(), ErrBadToken) {
		t.Fatalf("identity lost: %v", received.Err())
	}
	if received.Error != original.Error() {
		t.Fatal("legacy text changed")
	}
}

func TestServiceRefusalHasCode(t *testing.T) {
	h := start(t)
	_, _, err := h.app.Check("invalid")
	if !errors.Is(err, ErrBadToken) {
		t.Fatalf("token identity lost: %v", err)
	}
	_, err = h.app.Do(Request{Op: OpRegister, Name: "example", Rights: []string{"unknown"}})
	if !errors.Is(err, ErrUnknownRight) {
		t.Fatalf("right identity lost: %v", err)
	}
}

func TestEmptyNativeErrorStillRefusesLegacyClient(t *testing.T) {
	out := failure(errors.New(""))
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if old.Error == "" || out.Code != CodeInternal {
		t.Fatalf("legacy success: %s", raw)
	}
}
