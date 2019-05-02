package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis"
)

const (
	// Cookies are limited to 4kb including the length of the cookie name,
	// the cookie name can be up to 256 bytes
	maxCookieLength = 3840
)

// Store is the interface to storing cookies.
type Store interface {
	Store(requestCookie *http.Cookie, value string, expires time.Time, cookieMaker func(string) *http.Cookie) ([]*http.Cookie, error)
	Load(request *http.Request) (string, error)
	Clear(requestCookie *http.Cookie) (bool, error)
}

// RedisCookieStore is an Redis-backed implementation of a Store.
// It stores the cookies according to the cookie ticket, which is composed of
// a Prefix (the same as the CookieName) and a handle (a random identifier)
type RedisCookieStore struct {
	Client     *redis.Client
	Block      cipher.Block
	CookieName string
}

// BrowserCookieStore is the traditional cookie store that creates the default cookies
type BrowserCookieStore struct {
	CookieName string
}

// Store returns cookies to send back to the user.
func (store *BrowserCookieStore) Store(requestCookie *http.Cookie, value string, expires time.Time, cookieMaker func(string) *http.Cookie) ([]*http.Cookie, error) {
	c := cookieMaker(value)
	if len(c.Value) > 4096-len(store.CookieName) {
		return splitCookie(c), nil
	}
	return []*http.Cookie{c}, nil
}

// Clear creates a clear cookie that's sent back.
func (store *BrowserCookieStore) Clear(requestCookie *http.Cookie) (bool, error) {
	return false, nil
}

// Load returns the value for the cookie
func (store *BrowserCookieStore) Load(request *http.Request) (string, error) {
	c, err := loadCookie(request, store.CookieName)
	if err != nil {
		return "", fmt.Errorf("failed to load cookie %s", err)
	}
	return c.Value, nil
}

// NewRedisCookieStore constructs a new Redis-backed Server cookie store.
func NewRedisCookieStore(url string, cookieName string, block cipher.Block) (Store, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		panic(err)
	}

	client := redis.NewClient(opt)

	rs := &RedisCookieStore{
		Client:     client,
		Block:      block,
		CookieName: cookieName,
	}
	// Create client as usually.
	return rs, nil
}

// Store stores the cookie locally and returns a new response cookie value to be
// sent back to the client. That value is used to lookup the cookie later.
func (store *RedisCookieStore) Store(requestCookie *http.Cookie, value string, expires time.Time, cookieMaker func(string) *http.Cookie) ([]*http.Cookie, error) {
	var cookieHandle string
	var iv []byte
	if requestCookie != nil {
		var err error
		cookieHandle, iv, err = parseCookieTicket(store.CookieName, requestCookie.Value)
		if err != nil {
			return nil, err
		}
	} else {
		cookieIDBytes := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, cookieIDBytes); err != nil {
			return nil, fmt.Errorf("failed to create initialization vector %s", err)
		}
		cookieID := fmt.Sprintf("%x", cookieIDBytes)

		iv = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, fmt.Errorf("failed to create initialization vector %s", err)
		}
		cookieHandle = fmt.Sprintf("%s-%s", store.CookieName, cookieID)
	}

	ciphertext := make([]byte, len(value))
	stream := cipher.NewCFBEncrypter(store.Block, iv)
	stream.XORKeyStream(ciphertext, []byte(value))

	expiration := expires.Sub(time.Now())
	err := store.Client.Set(cookieHandle, ciphertext, expiration).Err()
	if err != nil {
		return nil, err
	}

	cookieTicket := cookieHandle + "." + base64.RawURLEncoding.EncodeToString(iv)
	if requestCookie == nil {
		responseCookie := cookieMaker(cookieTicket)
		return []*http.Cookie{responseCookie}, nil
	}
	return nil, nil
}

// Clear takes in the client cookie from the request and uses it to
// clear any lingering server cookies, when possible. It returns true if anything
// was deleted.
func (store *RedisCookieStore) Clear(requestCookie *http.Cookie) (bool, error) {
	var err error
	cookieHandle, _, err := parseCookieTicket(store.CookieName, requestCookie.Value)
	if err != nil {
		return false, err
	}

	deleted, err := store.Client.Del(cookieHandle).Result()
	if err != nil {
		return false, err
	}
	return deleted > 0, nil
}

// Load takes in the client cookie from the request and uses it to lookup
// the stored value.
func (store *RedisCookieStore) Load(request *http.Request) (string, error) {
	c, err := request.Cookie(store.CookieName)
	if err != nil {
		return "", fmt.Errorf("unable to load cookie: %s", err)
	}
	cookieHandle, iv, err := parseCookieTicket(store.CookieName, c.Value)
	if err != nil {
		return "", err
	}

	result, err := store.Client.Get(cookieHandle).Result()
	if err != nil {
		return "", err
	}

	resultBytes := []byte(result)

	stream := cipher.NewCFBDecrypter(store.Block, iv)
	stream.XORKeyStream(resultBytes, resultBytes)
	return string(resultBytes), nil
}

func parseCookieTicket(cookieName string, ticket string) (string, []byte, error) {
	prefix := cookieName + "-"
	if !strings.HasPrefix(ticket, prefix) {
		return "", nil, fmt.Errorf("failed to decode cookie handle")
	}
	trimmedTicket := strings.TrimPrefix(ticket, prefix)

	cookieParts := strings.Split(trimmedTicket, ".")
	if len(cookieParts) != 2 {
		return "", nil, fmt.Errorf("failed to decode cookie")
	}
	cookieID, ivBase64 := cookieParts[0], cookieParts[1]
	cookieHandle := prefix + cookieID

	// cookieID must be a hexadecimal string
	_, err := hex.DecodeString(cookieID)
	if err != nil {
		return "", nil, fmt.Errorf("server cookie failed sanity checks")
		// s is not a valid
	}

	iv, err := base64.RawURLEncoding.DecodeString(ivBase64)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode initialization vector %s", err)
	}
	return cookieHandle, iv, nil
}

func copyCookie(c *http.Cookie) *http.Cookie {
	return &http.Cookie{
		Name:       c.Name,
		Value:      c.Value,
		Path:       c.Path,
		Domain:     c.Domain,
		Expires:    c.Expires,
		RawExpires: c.RawExpires,
		MaxAge:     c.MaxAge,
		Secure:     c.Secure,
		HttpOnly:   c.HttpOnly,
		Raw:        c.Raw,
		Unparsed:   c.Unparsed,
	}
}

// splitCookie reads the full cookie generated to store the session and splits
// it into a slice of cookies which fit within the 4kb cookie limit indexing
// the cookies from 0
func splitCookie(c *http.Cookie) []*http.Cookie {
	if len(c.Value) < maxCookieLength {
		return []*http.Cookie{c}
	}
	cookies := []*http.Cookie{}
	valueBytes := []byte(c.Value)
	count := 0
	for len(valueBytes) > 0 {
		newCookie := copyCookie(c)
		newCookie.Name = fmt.Sprintf("%s_%d", c.Name, count)
		count++
		if len(valueBytes) < maxCookieLength {
			newCookie.Value = string(valueBytes)
			valueBytes = []byte{}
		} else {
			newValue := valueBytes[:maxCookieLength]
			valueBytes = valueBytes[maxCookieLength:]
			newCookie.Value = string(newValue)
		}
		cookies = append(cookies, newCookie)
	}
	return cookies
}

// joinCookies takes a slice of cookies from the request and reconstructs the
// full session cookie
func joinCookies(cookies []*http.Cookie) (*http.Cookie, error) {
	if len(cookies) == 0 {
		return nil, fmt.Errorf("list of cookies must be > 0")
	}
	if len(cookies) == 1 {
		return cookies[0], nil
	}
	c := copyCookie(cookies[0])
	for i := 1; i < len(cookies); i++ {
		c.Value += cookies[i].Value
	}
	c.Name = strings.TrimRight(c.Name, "_0")
	return c, nil
}

// loadCookie retreieves the sessions state cookie from the http request.
// If a single cookie is present this will be returned, otherwise it attempts
// to reconstruct a cookie split up by splitCookie
func loadCookie(req *http.Request, cookieName string) (*http.Cookie, error) {
	c, err := req.Cookie(cookieName)
	if err == nil {
		return c, nil
	}
	cookies := []*http.Cookie{}
	err = nil
	count := 0
	for err == nil {
		var c *http.Cookie
		c, err = req.Cookie(fmt.Sprintf("%s_%d", cookieName, count))
		if err == nil {
			cookies = append(cookies, c)
			count++
		}
	}
	if len(cookies) == 0 {
		return nil, fmt.Errorf("Could not find cookie %s", cookieName)
	}
	return joinCookies(cookies)
}
