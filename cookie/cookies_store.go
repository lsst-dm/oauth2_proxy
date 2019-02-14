package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// ServerCookiesStore is the interface to storing cookies.
// It takes in cookies
type ServerCookiesStore interface {
	Store(responseCookie *http.Cookie) (string, error)
	Clear(requestCookie *http.Cookie) error
	Load(requestCookie *http.Cookie) (string, error)
}

type FileSystemCookieStore struct {
	BasePath string
	Block    cipher.Block
}

// Store stores the cookie locally and returns a new response cookie value to be
// sent back to the client. That value is used to lookup the cookie later.
func (store FileSystemCookieStore) Store(responseCookie *http.Cookie) (string, error) {
	// cookie is actually stored locally
	hasher := sha1.New()
	hasher.Write([]byte(responseCookie.Value))
	cookieHandle := fmt.Sprintf("%x", hasher.Sum(nil))

	ciphertext := make([]byte, len(responseCookie.Value))
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to create initialization vector %s", err)
	}

	stream := cipher.NewCFBEncrypter(store.Block, iv)
	stream.XORKeyStream(ciphertext, []byte(responseCookie.Value))
	err := ioutil.WriteFile(filepath.Join(store.BasePath, cookieHandle), ciphertext, 0700)
	if err != nil {
		return "", err
	}

	newCookieValue := cookieHandle + "." + base64.StdEncoding.EncodeToString(iv)
	return newCookieValue, nil
}

// Clear takes in the client cookie from the request and uses it to
// clear any lingering server cookies, when possible.
func (store FileSystemCookieStore) Clear(requestCookie *http.Cookie) error {
	var err error
	cookieHandle, _, err := parseCookieValue(requestCookie.Value)
	if err != nil {
		return err
	}

	err = os.Remove(filepath.Join(store.BasePath, cookieHandle))
	if err != nil {
		return err
	}

	return nil
}

// Load takes in the client cookie from the request and uses it to lookup
// the stored value.
func (store FileSystemCookieStore) Load(requestCookie *http.Cookie) (string, error) {
	cookieHandle, iv, err := parseCookieValue(requestCookie.Value)
	if err != nil {
		return "", err
	}

	encrypted, err := ioutil.ReadFile(filepath.Join(store.BasePath, cookieHandle))
	if err != nil {
		return "", err
	}

	stream := cipher.NewCFBDecrypter(store.Block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return string(encrypted), nil
}

func parseCookieValue(value string) (string, []byte, error) {
	cookieParts := strings.Split(value, ".")
	if len(cookieParts) != 2 {
		return "", nil, fmt.Errorf("failed to decode cookie")
	}
	cookieHandle, ivBase64 := cookieParts[0], cookieParts[1]

	// sanitize input
	sanitizedCookieHandle := filepath.Base(cookieHandle)
	if cookieHandle != sanitizedCookieHandle || len(sanitizedCookieHandle) > 256 {
		return "", nil, fmt.Errorf("server cookie failed sanity checks")
	}

	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode initialization vector %s", err)
	}
	return sanitizedCookieHandle, iv, nil
}
