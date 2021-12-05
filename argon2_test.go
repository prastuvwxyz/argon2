package argon2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgon2(t *testing.T) {
	t.Run(`
		Given scratch config.
		When success build params manually.
		Then success create hash and no error.
	`, func(t *testing.T) {
		c := new(Config).SetTime(1).
			SetMemory(64 * 102).
			SetParallelism(2).
			SetSaltLength(16).
			SetKeyLength(32).
			SetMode(Mode[Argon2id]).
			SetVersion(Version[Version13])
		hash, err := c.CreateHash("foo")
		assert.NoError(t, err)
		assert.IsType(t, []byte{}, hash)

		argon, err := NewWithHash(string(hash))
		assert.NoError(t, err)

		match, err := argon.Match("foo")
		assert.NoError(t, err)
		assert.True(t, match)
	})

	t.Run(`
		Given default config.
		When mode is Argon2i.
		Then success create hash and no error.
	`, func(t *testing.T) {
		hash, err := Default().SetMode(Mode[Argon2i]).CreateHash("foo")
		assert.NoError(t, err)
		assert.IsType(t, []byte{}, hash)

		argon, err := NewWithHash(string(hash))
		assert.NoError(t, err)

		match, err := argon.Match("foo")
		assert.NoError(t, err)
		assert.True(t, match)
	})

	t.Run(`
		Given default config.
		When encode But salt is nil.
		Then error salt not found.
	`, func(t *testing.T) {
		c := Default()
		_, err := c.encode()
		assert.Error(t, err)
		assert.Equal(t, ErrSaltNotFound, err)
	})

	t.Run(`
		Given default config.
		When encode But key is nil.
		Then error key not found.
	`, func(t *testing.T) {
		c := Default()
		var err error
		c.Salt, err = c.generateSalt()
		assert.NoError(t, err)
		assert.NotNil(t, c.Salt)

		_, err = c.encode()
		assert.Error(t, err)
		assert.Equal(t, ErrKeyNotFound, err)
	})

	t.Run(`
		Given hash.
		When hash segment not valid.
		Then error invalid hash.
	`, func(t *testing.T) {
		_, err := NewWithHash("argon2id$v=13$m=6528,t=1,p=2$dI54H+DNb1aVA4mnMkb8qA$Kq26FzQd+ewxNfrPdq25v1vY8+MAx53MsUGgaKAZCTk")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidHash, err)
	})

	t.Run(`
		Given hash.
		When mode format is unknown.
		Then error mode not supported.
	`, func(t *testing.T) {
		_, err := NewWithHash("$unknown$v=13$m=6528,t=1,p=2$dI54H+DNb1aVA4mnMkb8qA$Kq26FzQd+ewxNfrPdq25v1vY8+MAx53MsUGgaKAZCTk")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidMode, err)
	})

	t.Run(`
		Given hash.
		When missing version format.
		Then error input does not match format.
	`, func(t *testing.T) {
		_, err := NewWithHash("$argon2id$version=13$m=6528,t=1,p=2$dI54H+DNb1aVA4mnMkb8qA$Kq26FzQd+ewxNfrPdq25v1vY8+MAx53MsUGgaKAZCTk")
		assert.Error(t, err)
		assert.Equal(t, "input does not match format", err.Error())
	})

	t.Run(`
		Given hash.
		When version format is 10.
		Then error version not supported.
	`, func(t *testing.T) {
		_, err := NewWithHash("$argon2id$v=10$m=6528,t=1,p=2$dI54H+DNb1aVA4mnMkb8qA$Kq26FzQd+ewxNfrPdq25v1vY8+MAx53MsUGgaKAZCTk")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidVersion, err)
	})

	t.Run(`
		Given hash.
		When missing memory format.
		Then error input does not match format.
	`, func(t *testing.T) {
		_, err := NewWithHash("$argon2id$v=13$t=1,p=2$dI54H+DNb1aVA4mnMkb8qA$Kq26FzQd+ewxNfrPdq25v1vY8+MAx53MsUGgaKAZCTk")
		assert.Error(t, err)
		assert.Equal(t, "input does not match format", err.Error())
	})

	t.Run(`
		Given hash.
		When invalid salt format.
		Then error illegal base64 data at input byte 20.
	`, func(t *testing.T) {
		_, err := NewWithHash("$argon2id$v=13$m=6528,t=1,p=2$dI54H+DNb1aVA4mnMkb8qa$Kq26FzQd+ewxNfrPdq25v1vY8+MAx53MsUGgaKAZCTk")
		assert.Error(t, err)
		assert.Equal(t, "illegal base64 data at input byte 20", err.Error())
	})

	t.Run(`
		Given hash.
		When invalid key format.
		Then error illegal base64 data at input byte 42.
	`, func(t *testing.T) {
		_, err := NewWithHash("$argon2id$v=13$m=6528,t=1,p=2$dI54H+DNb1aVA4mnMkb8qA$Kq26FzQd+ewxNfrPdq25v1vY8+MAx53MsUGgaKAZCTa")
		assert.Error(t, err)
		assert.Equal(t, "illegal base64 data at input byte 42", err.Error())
	})

	t.Run(`
		Given default config.
		When trying match password.
		Then error invalid argin config.
	`, func(t *testing.T) {
		c := Default()
		match, err := c.Match("bar")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidArgonConfig, err)
		assert.False(t, match)
	})

	t.Run(`
		Given default config.
		When success create hash foo
			But match bar.
		Then match is false and no error.
	`, func(t *testing.T) {
		hash, err := Default().SetMode(Mode[Argon2id]).CreateHash("foo")
		assert.NoError(t, err)
		assert.IsType(t, []byte{}, hash)

		argon, err := NewWithHash(string(hash))
		assert.NoError(t, err)

		match, err := argon.Match("bar")
		assert.NoError(t, err)
		assert.False(t, match)
	})

	t.Run(`
		Given default config.
		When success create hash bar
			And success match bar.
		Then match is false and no error.
	`, func(t *testing.T) {
		hash, err := Default().SetMode(Mode[Argon2id]).CreateHash("bar")
		assert.NoError(t, err)
		assert.IsType(t, []byte{}, hash)

		argon, err := NewWithHash(string(hash))
		assert.NoError(t, err)

		match, err := argon.Match("bar")
		assert.NoError(t, err)
		assert.True(t, match)
	})
}
