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
	algorithm     piv.Algorithm
	pinPolicy     piv.PINPolicy
	touchPolicy   piv.TouchPolicy
}

func NewYubikeyKey(yubikeyReader *config.YubikeyReader, hier hierarchy.Hierarchy, keyConfig *config.KeyConfig) (*Yubikey, error) {
	var pivAlg piv.Algorithm

	logging.Println(fmt.Sprintf("\nCreating %s (%s) key...", hier.Description(), hier.String()))

	cert, err := yubikeyReader.GetPIVKeyCert()
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
				return nil, fmt.Errorf("yubikey: key creation failed; %s key present in signature slot is less than 2048 bits", cert.PublicKeyAlgorithm.String())
			}
			keyAlgName = fmt.Sprintf("RSA%d", bitlen)
			logging.Println(fmt.Sprintf("Using existing %s Key MD5: %x in Yubikey PIV Signature Slot", keyAlgName, md5sum(cert.PublicKey)))

		default:
			if yubikeyReader.Overwrite {
				return nil, fmt.Errorf("yubikey: unsupported key type: %s", cert.PublicKey)
			}
		}
		switch keyAlgName {
		case "RSA2048":
			pivAlg = piv.AlgorithmRSA2048
		case "RSA3072":
			pivAlg = piv.AlgorithmRSA3072
		case "RSA4096":
			pivAlg = piv.AlgorithmRSA4096
		default:
			if !yubikeyReader.Overwrite {
				return nil, fmt.Errorf("yubikey: unsupported existing yubikey key algorithm: %s", keyAlgName)
			}
		}

		return &Yubikey{
			keytype:       YubikeyBackend,
			cert:          cert,
			yubikeyReader: yubikeyReader,
			algorithm:     pivAlg,
			pinPolicy:     piv.PINPolicyAlways,
			touchPolicy:   piv.TouchPolicyAlways,
		}, nil
	}

	// if overwrite and there is an existing piv key, print warning
	if cert != nil && yubikeyReader.Overwrite {
		logging.Warn("Overwriting existing key %s in Yubikey PIV Signature Slot", cert.PublicKeyAlgorithm.String())
	}

	switch keyConfig.Algorithm {
	case "RSA2048":
		pivAlg = piv.AlgorithmRSA2048
	case "RSA3072":
		pivAlg = piv.AlgorithmRSA3072
	case "RSA4096":
		pivAlg = piv.AlgorithmRSA4096

	default:
		return nil, fmt.Errorf("yubikey: unsupported public key algorithm %s", keyConfig.Algorithm)
	}

	// Generate a private key on the YubiKey.
	key := piv.Key{
		Algorithm:   pivAlg,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	logging.Println(fmt.Sprintf("Creating %s key...\nPlease press Yubikey to confirm presence", keyConfig.Algorithm))
	newKey, err := yubikeyReader.GenerateKey(piv.DefaultManagementKey, piv.SlotSignature, key)
	if err != nil {
		return nil, err
	}
	logging.Println(fmt.Sprintf("Created %s key MD5: %x", keyConfig.Algorithm, md5sum(newKey)))

	ykCert, err := yubikeyReader.GetPIVKeyCert()
	if err != nil {
		return nil, err
	}

	priv, err := yubikeyReader.PrivateKey(piv.SlotSignature, ykCert.PublicKey)
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
		Subject:            parseSubject(keyConfig.Subject, hier),
	}

	logging.Println(fmt.Sprintf("Please press Yubikey to confirm presence for %s MD5: %x", keyConfig.Algorithm, md5sum(cert.PublicKey)))
	derBytes, err := x509.CreateCertificate(rand.Reader, &c, &c, ykCert.PublicKey, priv)
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
		algorithm:     pivAlg,
		pinPolicy:     piv.PINPolicyAlways,
		touchPolicy:   piv.TouchPolicyAlways,
	}, nil
}

func YubikeyFromBytes(yubikeyReader *config.YubikeyReader, keyb, pemb []byte) (*Yubikey, error) {
	var yubiData YubikeyData
	err := json.Unmarshal(keyb, &yubiData)
	if err != nil {
		return nil, fmt.Errorf("yubikey: error unmarshalling yubikey: %v", err)
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
		algorithm:     yubiData.Algorithm,
		pinPolicy:     yubiData.PinPolicy,
		touchPolicy:   yubiData.TouchPolicy,
	}, nil
}

func (f *Yubikey) Type() BackendType              { return f.keytype }
func (f *Yubikey) Certificate() *x509.Certificate { return f.cert }

func (f *Yubikey) Signer() crypto.Signer {
	priv, err := f.yubikeyReader.PrivateKey(piv.SlotSignature, f.cert.PublicKey)
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
		Slot:        piv.SlotSignature.String(),
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

func parseSubject(subj string, hier hierarchy.Hierarchy) pkix.Name {
	var subject pkix.Name

	if subj != "" {
		subject = pkix.Name{}

		fields := strings.SplitSeq(subj, "/")
		for field := range fields {
			if field == "" {
				continue
			}
			kv := strings.SplitN(field, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.ToUpper(strings.TrimSpace(kv[0]))
			value := strings.TrimSpace(kv[1])

			switch key {
			case "C":
				subject.Country = append(subject.Country, value)
			case "O":
				subject.Organization = append(subject.Organization, value)
			case "OU":
				subject.OrganizationalUnit = append(subject.OrganizationalUnit, value)
			case "L":
				subject.Locality = append(subject.Locality, value)
			case "ST":
				subject.Province = append(subject.Province, value)
			case "CN":
				subject.CommonName = value
			case "SERIALNUMBER":
				subject.SerialNumber = value
			default:
			}
		}

		// Basic sanity: CN must be supplied
		if subject.CommonName == "" {
			panic("yubikey: subject missing common name")
		}
	} else {
		// return default
		subject = pkix.Name{
			Country:    []string{"WW"},
			CommonName: hier.Description(),
		}
	}

	return subject
}
