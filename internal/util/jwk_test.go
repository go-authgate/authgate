package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
)

// helpers ---------------------------------------------------------------

func jwkFromRSA(t *testing.T, pub *rsa.PublicKey, kid string) JWK {
	t.Helper()
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func jwkFromEC(t *testing.T, pub *ecdsa.PublicKey, kid string) JWK {
	t.Helper()
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := make([]byte, byteLen)
	yBytes := make([]byte, byteLen)
	copy(xBytes[byteLen-len(pub.X.Bytes()):], pub.X.Bytes())
	copy(yBytes[byteLen-len(pub.Y.Bytes()):], pub.Y.Bytes())
	return JWK{
		Kty: "EC",
		Use: "sig",
		Kid: kid,
		Alg: "ES256",
		Crv: pub.Curve.Params().Name,
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

// tests -----------------------------------------------------------------

func TestParseJWKSet_RSA_Roundtrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	set := JWKSet{Keys: []JWK{jwkFromRSA(t, &priv.PublicKey, "test-key")}}
	blob, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	parsed, err := ParseJWKSet(string(blob))
	if err != nil {
		t.Fatalf("ParseJWKSet: %v", err)
	}
	if len(parsed.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(parsed.Keys))
	}
	k := parsed.FindByKid("test-key")
	if k == nil {
		t.Fatal("FindByKid: nil")
	}
	pub, err := k.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
	if rsaPub.N.Cmp(priv.PublicKey.N) != 0 || rsaPub.E != priv.PublicKey.E {
		t.Fatal("RSA key mismatch after roundtrip")
	}
}

func TestParseJWKSet_EC_Roundtrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	set := JWKSet{Keys: []JWK{jwkFromEC(t, &priv.PublicKey, "ec-key")}}
	blob, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseJWKSet(string(blob))
	if err != nil {
		t.Fatalf("ParseJWKSet: %v", err)
	}
	k := parsed.FindByKid("ec-key")
	pub, err := k.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if ecPub.X.Cmp(priv.PublicKey.X) != 0 || ecPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("EC key mismatch after roundtrip")
	}
}

func TestParseJWKSet_EmptyKeys(t *testing.T) {
	_, err := ParseJWKSet(`{"keys":[]}`)
	if !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS, got %v", err)
	}
}

func TestParseJWKSet_InvalidJSON(t *testing.T) {
	_, err := ParseJWKSet(`not json`)
	if !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS, got %v", err)
	}
}

func TestFindByKid_SingleKeyNoKid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	set := &JWKSet{Keys: []JWK{jwkFromRSA(t, &priv.PublicKey, "")}}
	if got := set.FindByKid(""); got == nil {
		t.Fatal("expected single key match when kid empty")
	}
}

func TestFindByKid_MultipleKeysEmptyKid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	set := &JWKSet{Keys: []JWK{
		jwkFromRSA(t, &priv.PublicKey, "a"),
		jwkFromRSA(t, &priv.PublicKey, "b"),
	}}
	if got := set.FindByKid(""); got != nil {
		t.Fatal("expected nil when multiple keys and empty kid")
	}
}

func TestToPublicKey_UnsupportedKty(t *testing.T) {
	k := &JWK{Kty: "oct"}
	_, err := k.ToPublicKey()
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got %v", err)
	}
}

func TestToPublicKey_RSA_MissingField(t *testing.T) {
	k := &JWK{Kty: "RSA", N: "AQAB"} // missing e
	_, err := k.ToPublicKey()
	if !errors.Is(err, ErrJWKFieldMissing) {
		t.Fatalf("expected ErrJWKFieldMissing, got %v", err)
	}
}

func TestToPublicKey_RSA_WeakKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024) // below min 2048
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	k := jwkFromRSA(t, &priv.PublicKey, "weak")
	_, err = k.ToPublicKey()
	if !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for weak key, got %v", err)
	}
}

func TestToPublicKey_EC_UnsupportedCurve(t *testing.T) {
	k := &JWK{Kty: "EC", Crv: "P-384", X: "AA", Y: "AA"}
	_, err := k.ToPublicKey()
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got %v", err)
	}
}

func TestToPublicKey_EC_PointNotOnCurve(t *testing.T) {
	k := &JWK{
		Kty: "EC",
		Crv: "P-256",
		// Valid base64 but nonsense coordinates → not on curve
		X: base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		Y: base64.RawURLEncoding.EncodeToString([]byte{5, 6, 7, 8}),
	}
	_, err := k.ToPublicKey()
	if !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for off-curve point, got %v", err)
	}
}
