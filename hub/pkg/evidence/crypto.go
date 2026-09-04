package evidence

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// MasterKey represents the 256-bit AES master evidence encryption key.
type MasterKey [32]byte

// LoadOrCreateMasterKey reads or initializes the master evidence key file.
func LoadOrCreateMasterKey(path string) (*MasterKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		rawHex := string(data)
		keyBytes, err := hex.DecodeString(rawHex)
		if err == nil && len(keyBytes) == 32 {
			var k MasterKey
			copy(k[:], keyBytes)
			return &k, nil
		}
	}

	var k MasterKey
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random master key: %w", err)
	}

	if err := os.WriteFile(path, []byte(hex.EncodeToString(k[:])), 0600); err != nil {
		return nil, fmt.Errorf("failed to write master key file: %w", err)
	}
	return &k, nil
}

// LoadOrCreateReceiptKey reads or generates the dedicated Ed25519 receipt signing keypair.
func LoadOrCreateReceiptKey(keyPath string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if data, err := os.ReadFile(keyPath); err == nil {
		rawHex := strings.TrimSpace(string(data))
		keyBytes, err := hex.DecodeString(rawHex)
		if err == nil && len(keyBytes) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(keyBytes)
			pub := priv.Public().(ed25519.PublicKey)
			return priv, pub, nil
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate receipt key: %w", err)
	}

	privHex := hex.EncodeToString(priv)
	if err := os.WriteFile(keyPath, []byte(privHex), 0600); err != nil {
		return nil, nil, fmt.Errorf("failed to write receipt private key: %w", err)
	}

	pubPath := keyPath + ".pub"
	pubHex := hex.EncodeToString(pub)
	_ = os.WriteFile(pubPath, []byte(pubHex), 0644)

	return priv, pub, nil
}

// GenerateDataKey generates a random 256-bit AES data key.
func GenerateDataKey() ([32]byte, error) {
	var dk [32]byte
	if _, err := io.ReadFull(rand.Reader, dk[:]); err != nil {
		return dk, err
	}
	return dk, nil
}

// WrapDataKey encrypts a per-item data key using the master key.
func WrapDataKey(masterKey *MasterKey, dataKey [32]byte) (string, error) {
	block, err := aes.NewCipher(masterKey[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, dataKey[:], nil)
	return hex.EncodeToString(ciphertext), nil
}

// UnwrapDataKey decrypts a wrapped data key using the master key.
func UnwrapDataKey(masterKey *MasterKey, wrappedHex string) ([32]byte, error) {
	var dk [32]byte
	wrapped, err := hex.DecodeString(wrappedHex)
	if err != nil {
		return dk, err
	}
	block, err := aes.NewCipher(masterKey[:])
	if err != nil {
		return dk, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return dk, err
	}
	nonceSize := gcm.NonceSize()
	if len(wrapped) < nonceSize {
		return dk, errors.New("wrapped key too short")
	}
	nonce, ciphertext := wrapped[:nonceSize], wrapped[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return dk, fmt.Errorf("unwrap data key failed: %w", err)
	}
	if len(plaintext) != 32 {
		return dk, errors.New("invalid unwrapped key length")
	}
	copy(dk[:], plaintext)
	return dk, nil
}

// CanonicalItemAAD generates deterministic, unambiguous length-prefixed associated data
// for authenticated encryption of evidence objects.
func CanonicalItemAAD(tenantID, bundleID, itemID, name string, offset, totalSize int64) []byte {
	var buf bytes.Buffer
	buf.WriteString("OMINULL-EVIDENCE-ITEM-V1\x00")
	writeLPStr(&buf, tenantID)
	writeLPStr(&buf, bundleID)
	writeLPStr(&buf, itemID)
	writeLPStr(&buf, name)
	_ = binary.Write(&buf, binary.BigEndian, offset)
	_ = binary.Write(&buf, binary.BigEndian, totalSize)
	return buf.Bytes()
}

// EncryptItemData encrypts evidence bytes with the item data key and associated data.
func EncryptItemData(dataKey [32]byte, plaintext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(dataKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

// DecryptItemData decrypts evidence bytes using the data key and associated data.
func DecryptItemData(dataKey [32]byte, ciphertext []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(dataKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, aad)
}

// ComputeDigest returns the lowercase hex SHA-256 digest of data.
func ComputeDigest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// VerifyManifestSignature validates the Ed25519 signature of a canonical endpoint manifest.
func VerifyManifestSignature(manifest *Manifest, pubKeyHex string) error {
	if manifest == nil {
		return errors.New("nil manifest")
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(manifest.Signature))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature format")
	}
	canonical := manifest.CanonicalBytes()
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sigBytes) {
		return errors.New("manifest signature verification failed")
	}
	return nil
}

// VerifyReceiptSignature validates the Ed25519 signature of a canonical hub receipt.
func VerifyReceiptSignature(receipt *EvidenceReceipt, pubKeyHex string) error {
	if receipt == nil {
		return errors.New("nil receipt")
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("invalid hub Ed25519 public key")
	}
	sigBytes, err := hex.DecodeString(strings.TrimSpace(receipt.ReceiptSignature))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return errors.New("invalid receipt signature format")
	}
	canonical := receipt.CanonicalBytes()
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sigBytes) {
		return errors.New("receipt signature verification failed")
	}
	computedHash := receipt.ComputeReceiptHash()
	if computedHash != receipt.ReceiptHash {
		return errors.New("receipt hash does not match canonical receipt content")
	}
	return nil
}
