package auth

import (
	"bytes"
	"fmt"
	"image/png"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// SetupTOTP generates a fresh TOTP secret and returns it both as a base32
// string and a PNG QR code suitable for scanning into an authenticator app.
func SetupTOTP(issuer, accountName string) (secretBase32 string, qrPNG []byte, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", nil, fmt.Errorf("totp generate: %w", err)
	}

	img, err := key.Image(256, 256)
	if err != nil {
		return "", nil, fmt.Errorf("totp image: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", nil, fmt.Errorf("png encode: %w", err)
	}

	return key.Secret(), buf.Bytes(), nil
}

// VerifyTOTP returns true iff code matches the current 30-second window for
// secretBase32 (with one window of leeway, matching the library default).
func VerifyTOTP(secretBase32, code string) bool {
	return totp.Validate(code, secretBase32)
}

// QRCodePNG renders an otpauth:// URL into a PNG of the given pixel size.
// Used when we need to redisplay the QR after the original setup response
// (the secret stays the same; the QR stays the same).
func QRCodePNG(otpauthURL string, sizePx int) ([]byte, error) {
	key, err := otp.NewKeyFromURL(otpauthURL)
	if err != nil {
		return nil, fmt.Errorf("totp parse url: %w", err)
	}
	img, err := key.Image(sizePx, sizePx)
	if err != nil {
		return nil, fmt.Errorf("totp image: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("png encode: %w", err)
	}
	return buf.Bytes(), nil
}
