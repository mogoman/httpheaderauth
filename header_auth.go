package httpheaderauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
)

type AuthOptions struct {
	HeaderKey           string
	HeaderValue         string
	AuthFunc            func(string, *http.Request) bool
	UnauthorizedHandler http.Handler
}

type headerAuth struct {
	h    http.Handler
	opts AuthOptions
}

func (b headerAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if we have a user-provided error handler, else set a default
	if b.opts.UnauthorizedHandler == nil {
		b.opts.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}

	// Check that the provided details match
	if b.authenticate(r) == false {
		b.opts.UnauthorizedHandler.ServeHTTP(w, r)
		return
	}

	// Call the next handler on success.
	b.h.ServeHTTP(w, r)
}

func (b *headerAuth) authenticate(r *http.Request) bool {
	if r == nil {
		return false
	}

	if b.opts.AuthFunc == nil && b.opts.HeaderKey == "" {
		return false
	}

	auth := r.Header.Get(b.opts.HeaderKey)

	if len(auth) == 0 {
		return false
	}

	// Default to Simple mode if no AuthFunc is defined.
	if b.opts.AuthFunc == nil {
		b.opts.AuthFunc = b.simpleHeaderAuthFunc
	}

	return b.opts.AuthFunc(auth, r)
}

func (b *headerAuth) simpleHeaderAuthFunc(auth string, r *http.Request) bool {
	// Equalize lengths of supplied and required credentials
	// by hashing them
	givenAuth := sha256.Sum256([]byte(auth))
	requiredAuth := sha256.Sum256([]byte(b.opts.HeaderValue))

	// Compare the supplied credentials to those set in our options
	if subtle.ConstantTimeCompare(givenAuth[:], requiredAuth[:]) == 1 {
		return true
	}

	return false
}

func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func HeaderAuth(o AuthOptions) func(http.Handler) http.Handler {
	fn := func(h http.Handler) http.Handler {
		return headerAuth{h, o}
	}
	return fn
}

func SimpleHeaderAuth(headerKey string, headerValue string) func(http.Handler) http.Handler {
	opts := AuthOptions{
		HeaderKey:   headerKey,
		HeaderValue: headerValue,
	}
	return HeaderAuth(opts)
}

