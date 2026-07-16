package backend

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/foxboron/sbctl/config"
	"github.com/foxboron/sbctl/hierarchy"
	"github.com/foxboron/sbctl/logging"

	"github.com/go-piv/piv-go/v2/piv"
)

type YubikeyData struct {
	Algorithm   piv.Algorithm   `json:"algorithm"`
	PinPolicy   piv.PINPolicy   `json:"pinPolicy"`
	TouchPolicy piv.TouchPolicy `json:"touchPolicy"`
	Slot        string          `json:"slot"`
	PublicKey   string          `json:"publicKey"`
}

type Yubikey struct {
	keytype       BackendType
	cert          *x509.Certificate
	yubikeyReader *config.YubikeyReader
	slot          piv.Slot
	algorithm     piv.Algorithm
	pinPolicy     piv.PINPolicy
	touchPolicy   piv.TouchPolicy
}

func NewYubikeyKey(yubikeyReader *config.YubikeyReader, hier hierarchy.Hierarchy, keyType string) (*Yubikey, error) {
	var slot piv.Slot
	var slotName string
	var pivAlg piv.Algorithm

	algorithm, slotNumber := splitYubiKeyType(keyType)

	slot, slotName, err := resolvePIVSlot(slotNumber)
	if err != nil {
		return nil, err
	}

	cert, err := yubikeyReader.GetPIVKeyCert(slot)
	if err != nil {
		if !errors.Is(err, piv.ErrNotFound) {
			return nil, fmt.Errorf("failed finding yubikey: %v", err)
		}
	}

	// if there is a key and overwrite is false, use it
	if cert != nil && !yubikeyReader.Overwrite {
		var keyAlgName string

		switch yubiPub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			// RSA Public Key
			bitlen := yubiPub.N.BitLen()
			if bitlen < 2048 {
				return nil, fmt.Errorf("yubikey: key creation failed; %s key present in %s slot is less than 2048 bits", cert.PublicKeyAlgorithm.String(), slotName)
			}
			keyAlgName = fmt.Sprintf("RSA%d", bitlen)
			logging.Println(fmt.Sprintf("Using existing %s Key MD5: %x in Yubikey PIV %s Slot", keyAlgName, md5sum(cert.PublicKey), slotName))

		default:
			return nil, fmt.Errorf("yubikey: unsupported key type: %s", cert.PublicKey)
		}
		switch keyAlgName {
		case "RSA2048":
			pivAlg = piv.AlgorithmRSA2048
		case "RSA3072":
			pivAlg = piv.AlgorithmRSA3072
		case "RSA4096":
			pivAlg = piv.AlgorithmRSA4096
		default:
			return nil, fmt.Errorf("yubikey: unsupported existing yubikey key algorithm: %s", keyAlgName)
		}

		return &Yubikey{
			keytype:       YubikeyBackend,
			cert:          cert,
			yubikeyReader: yubikeyReader,
			slot:          slot,
			algorithm:     pivAlg,
			pinPolicy:     piv.PINPolicyAlways,
			touchPolicy:   piv.TouchPolicyAlways,
		}, nil
	}

	// if overwrite and there is an existing piv key, print warning
	if cert != nil && yubikeyReader.Overwrite {
		logging.Warn("Overwriting existing key %s in Yubikey PIV %s Slot", cert.PublicKeyAlgorithm.String(), slotName)
	}

	switch algorithm {
	case "RSA2048":
		pivAlg = piv.AlgorithmRSA2048
	case "RSA3072":
		pivAlg = piv.AlgorithmRSA3072
	case "RSA4096":
		pivAlg = piv.AlgorithmRSA4096

	default:
		return nil, fmt.Errorf("yubikey: unsupported public key algorithm %s", algorithm)
	}

	// Get management key
	mgmtKey, err := yubikeyReader.GetManagementKey()
	if err != nil {
		return nil, err
	}

	// Generate a private key on the YubiKey.
	key := piv.Key{
		Algorithm:   pivAlg,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	logging.Println(fmt.Sprintf("Creating %s key in Yubikey PIV %s Slot...\nPlease press Yubikey to confirm presence", slotName, algorithm))
	newKey, err := yubikeyReader.GenerateKey(mgmtKey, slot, key)
	if err != nil {
		return nil, err
	}
	logging.Println(fmt.Sprintf("Created %s key in Yubikey PIV %s Slot MD5: %x", algorithm, slotName, md5sum(newKey)))

	cert, err = yubikeyReader.GetPIVKeyCert(slot)
	if err != nil {
		return nil, err
	}

	priv, err := yubikeyReader.PrivateKey(slot, cert.PublicKey)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	c := x509.Certificate{
		SerialNumber:       serialNumber,
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(20, 0, 0),
		Subject: pkix.Name{
			Country:    []string{hier.Description()},
			CommonName: hier.Description(),
		},
	}

	logging.Println(fmt.Sprintf("Please press Yubikey to confirm presence for %s MD5: %x", algorithm, md5sum(cert.PublicKey)))
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, cert.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return &Yubikey{
		keytype:       YubikeyBackend,
		cert:          cert,
		yubikeyReader: yubikeyReader,
		slot:          slot,
		algorithm:     pivAlg,
		pinPolicy:     piv.PINPolicyAlways,
		touchPolicy:   piv.TouchPolicyAlways,
	}, nil
}

func YubikeyFromBytes(yubikeyReader *config.YubikeyReader, keyb, pemb []byte) (*Yubikey, error) {
	var yubiData YubikeyData
	var slot piv.Slot
	err := json.Unmarshal(keyb, &yubiData)
	if err != nil {
		return nil, fmt.Errorf("yubikey: error unmarshalling yubikey: %v", err)
	}

	slot, _, err = resolvePIVSlot(yubiData.Slot)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemb)
	if block == nil {
		return nil, fmt.Errorf("yubikey: no pem block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("yubikey: failed to parse cert: %w", err)
	}

	return &Yubikey{
		keytype:       YubikeyBackend,
		cert:          cert,
		yubikeyReader: yubikeyReader,
		slot:          slot,
		algorithm:     yubiData.Algorithm,
		pinPolicy:     yubiData.PinPolicy,
		touchPolicy:   yubiData.TouchPolicy,
	}, nil
}

func (f *Yubikey) Type() BackendType              { return f.keytype }
func (f *Yubikey) Certificate() *x509.Certificate { return f.cert }

func (f *Yubikey) Signer() crypto.Signer {
	priv, err := f.yubikeyReader.PrivateKey(f.slot, f.cert.PublicKey)
	if err != nil {
		panic(err)
	}
	logging.Println(fmt.Sprintf("Signing operation... please press Yubikey to confirm presence for key %s MD5: %x",
		f.cert.PublicKeyAlgorithm.String(),
		md5sum(f.cert.PublicKey)))
	return priv.(crypto.Signer)
}

func (f *Yubikey) Description() string { return f.Certificate().Subject.SerialNumber }

// save YubiKey data to file
func (f *Yubikey) PrivateKeyBytes() []byte {
	pubKey, _ := x509.MarshalPKIXPublicKey(f.cert.PublicKey)
	yubiData := YubikeyData{
		Slot:        f.slot.String(),
		Algorithm:   f.algorithm,
		PinPolicy:   f.pinPolicy,
		TouchPolicy: f.touchPolicy,
		PublicKey:   base64.StdEncoding.EncodeToString(pubKey),
	}

	b, err := json.Marshal(yubiData)
	if err != nil {
		panic(err)
	}
	return b
}

func (f *Yubikey) CertificateBytes() []byte {
	b := new(bytes.Buffer)
	if err := pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw}); err != nil {
		panic("yubikey: failed producing PEM encoded certificate")
	}
	return b.Bytes()
}

func md5sum(key crypto.PublicKey) []byte {
	h := md5.New()
	pubKey, _ := x509.MarshalPKIXPublicKey(key)
	h.Write(pubKey)
	return h.Sum(nil)
}

func resolvePIVSlot(slot string) (piv.Slot, string, error) {
	var pivSlot piv.Slot
	var slotName string

	switch strings.ToLower(slot) {
	case "9c":
		pivSlot = piv.SlotSignature
		slotName = "Signature"
	case "9a":
		pivSlot = piv.SlotAuthentication
		slotName = "Authentication"
	case "9e":
		pivSlot = piv.SlotCardAuthentication
		slotName = "CardAuthentication"
	case "9d":
		pivSlot = piv.SlotKeyManagement
		slotName = "KeyManagement"
	default:
		// maybe one of retired slots
		var found bool = false
		slotHexVal, err := strconv.ParseUint(slot, 16, 8)
		if err == nil {
			pivSlot, found = piv.RetiredKeyManagementSlot(uint32(slotHexVal))
		}
		if !found {
			return piv.Slot{}, "", fmt.Errorf("yubikey: Invalid key slot %s", slot)
		}
		slotName = fmt.Sprintf("RetiredKeyManagementSlot:0x%s", slot)
	}
	return pivSlot, slotName, nil
}

func splitYubiKeyType(keyType string) (string, string) {
	arr := strings.SplitN(keyType, ":", 3)

	switch len(arr) {
	case 2:
		return arr[1], piv.SlotSignature.String()
	case 3:
		return arr[1], arr[2]
	default:
		return "RSA4096", piv.SlotSignature.String()
	}
}
