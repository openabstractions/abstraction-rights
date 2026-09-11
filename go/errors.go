package rights

import "errors"

// Refusal codes are stable protocol identifiers. Error text remains diagnostic.
const (
	CodeInternal          = "internal"
	CodeInvalidRequest    = "invalid_request"
	CodeCallerRefused     = "caller_refused"
	CodeUnknownOperation  = "unknown_operation"
	CodeNotAdministrator  = "not_administrator"
	CodePending           = "pending"
	CodeDenied            = "denied"
	CodeDeniedPermanently = "denied_permanently"
	CodeUnsupportedHold   = "unsupported_hold"
	CodePlatformRefused   = "platform_refused"
	CodeUnknownApp        = "unknown_app"
	CodeUnknownRight      = "unknown_right"
	CodeNotGranted        = "not_granted"
	CodeBadSecret         = "bad_secret"
	CodeBadToken          = "bad_token"
)

// RemoteError is a service refusal. Code is empty for a legacy text-only reply.
// Unknown codes are retained; callers must treat them as refusals too.
type RemoteError struct {
	Code    string
	Message string
}

func (e *RemoteError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return "rights: " + e.Code
}

// Unwrap preserves native error identity for recognized refusal codes.
func (e *RemoteError) Unwrap() error {
	switch e.Code {
	case CodeUnknownApp:
		return ErrUnknownApp
	case CodeUnknownRight:
		return ErrUnknownRight
	case CodeNotGranted:
		return ErrNotGranted
	case CodeBadSecret:
		return ErrBadSecret
	case CodeBadToken:
		return ErrBadToken
	}
	return nil
}

// Err reports refusal even when a newer server sends a code without prose.
func (r Response) Err() error {
	if r.Error == "" && r.Code == "" {
		return nil
	}
	return &RemoteError{Code: r.Code, Message: r.Error}
}

func failure(err error) Response {
	code := CodeInternal
	switch {
	case errors.Is(err, ErrUnknownApp):
		code = CodeUnknownApp
	case errors.Is(err, ErrUnknownRight):
		code = CodeUnknownRight
	case errors.Is(err, ErrNotGranted):
		code = CodeNotGranted
	case errors.Is(err, ErrBadSecret):
		code = CodeBadSecret
	case errors.Is(err, ErrBadToken):
		code = CodeBadToken
	}
	message := err.Error()
	if message == "" {
		message = "rights: " + code
	}
	return Response{Error: message, Code: code}
}
