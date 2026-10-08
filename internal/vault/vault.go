// Package vault stores an authenticated, encrypted snapshot; secrets never go to disk in plaintext.
package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/spapas/totpvault/internal/totp"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	headerSize  = 48 // magic/version (8), Argon2 salt (16), XChaCha nonce (24).
	maxFileSize = 8 << 20
	maxAccounts = 10000
)

var (
	magic             = []byte{'T', 'O', 'T', 'P', 'V', 'L', 'T', 1}
	ErrAuthentication = errors.New("wrong master password or damaged vault")
	ErrChanged        = errors.New("vault changed on disk; lock and unlock again before saving")
	ErrLocked         = errors.New("vault is locked")
)

// Version 1 fixes Argon2id parameters, preventing untrusted files from requesting arbitrary resources.
func derive(password string, salt []byte) []byte {
	p := []byte(password)
	defer clear(p)
	return argon2.IDKey(p, salt, 3, 64*1024, 4, 32)
}

type payload struct {
	Accounts []totp.Account `json:"accounts"`
}

type Session struct {
	path        string
	key         []byte
	salt        []byte
	accounts    []totp.Account
	fingerprint [32]byte
}

func CheckPassword(password string) error {
	if utf8.RuneCountInString(password) < 12 {
		return errors.New("use at least 12 characters for the master password")
	}
	if len(password) > 1024 {
		return errors.New("master password is too long")
	}
	return nil
}

func Create(path, password string) (*Session, error) {
	if err := CheckPassword(password); err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	s := &Session{path: path, salt: salt, key: derive(password, salt)}
	data, err := s.encrypt(nil)
	if err != nil {
		s.Lock()
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		s.Lock()
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		s.Lock()
		return nil, err
	}
	err = writeSync(f, data)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		s.Lock()
		return nil, err
	}
	s.fingerprint = sha256.Sum256(data)
	return s, nil
}

func read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err == nil && len(b) > maxFileSize {
		err = errors.New("vault exceeds size limit")
	}
	return b, err
}

func Unlock(path, password string) (*Session, error) {
	if len(password) > 1024 {
		return nil, errors.New("master password is too long")
	}
	b, err := read(path)
	if err != nil {
		return nil, err
	}
	if len(b) < headerSize+chacha20poly1305.Overhead || !bytes.Equal(b[:8], magic) {
		return nil, errors.New("unsupported or damaged vault format")
	}
	s := &Session{path: path, salt: append([]byte(nil), b[8:24]...), fingerprint: sha256.Sum256(b)}
	s.key = derive(password, s.salt)
	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		s.Lock()
		return nil, err
	}
	plain, err := aead.Open(nil, b[24:48], b[48:], b[:48])
	if err != nil {
		s.Lock()
		return nil, ErrAuthentication
	}
	defer clear(plain)
	var p payload
	if err = json.Unmarshal(plain, &p); err != nil {
		s.Lock()
		return nil, errors.New("invalid vault payload")
	}
	if p.Accounts, err = normalize(p.Accounts); err != nil {
		s.Lock()
		return nil, err
	}
	s.accounts = p.Accounts
	return s, nil
}

func normalize(accounts []totp.Account) ([]totp.Account, error) {
	if len(accounts) > maxAccounts {
		return nil, errors.New("too many accounts")
	}
	result := make([]totp.Account, len(accounts))
	for i, a := range accounts {
		normalized, err := totp.Normalize(a)
		if err != nil {
			return nil, fmt.Errorf("invalid account: %w", err)
		}
		result[i] = normalized
	}
	return result, nil
}

func (s *Session) Accounts() []totp.Account { return append([]totp.Account(nil), s.accounts...) }

func (s *Session) Lock() {
	clear(s.key)
	s.key = nil
	for i := range s.accounts {
		s.accounts[i] = totp.Account{}
	}
	s.accounts = nil
}

func (s *Session) encrypt(accounts []totp.Account) ([]byte, error) {
	if s.key == nil {
		return nil, ErrLocked
	}
	plain, err := json.Marshal(payload{Accounts: accounts})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	header := make([]byte, headerSize)
	copy(header, magic)
	copy(header[8:24], s.salt)
	if _, err = rand.Read(header[24:48]); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return nil, err
	}
	b := aead.Seal(header, header[24:48], plain, header)
	if len(b) > maxFileSize {
		return nil, errors.New("vault exceeds size limit")
	}
	return b, nil
}

func (s *Session) Save(accounts []totp.Account) error {
	accounts, err := normalize(accounts)
	if err != nil {
		return err
	}
	b, err := s.encrypt(accounts)
	if err != nil {
		return err
	}
	if err = s.replace(b); err != nil {
		return err
	}
	s.accounts = append([]totp.Account(nil), accounts...)
	return nil
}

func (s *Session) ChangePassword(password string) error {
	if s.key == nil {
		return ErrLocked
	}
	if err := CheckPassword(password); err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	next := &Session{key: derive(password, salt), salt: salt}
	b, err := next.encrypt(s.accounts)
	if err == nil {
		err = s.replace(b)
	}
	if err != nil {
		next.Lock()
		return err
	}
	clear(s.key)
	s.key, s.salt = next.key, salt
	return nil
}

func writeSync(f *os.File, b []byte) error {
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	return err
}

func (s *Session) replace(b []byte) error {
	old, err := read(s.path)
	if err != nil {
		return err
	}
	if sha256.Sum256(old) != s.fingerprint {
		return ErrChanged
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".totpvault-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	err = writeSync(f, b)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	s.fingerprint = sha256.Sum256(b)
	// Persist the directory entry where supported. Windows cannot sync directories.
	if dir, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
