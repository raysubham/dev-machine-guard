package credentials

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// The fixtures below are real keys generated at test time rather than pasted
// blobs. Structural validation is the thing under test, so a fixture that only
// looks like a key would pass for the wrong reason — and generating them keeps
// key material out of the repository entirely.

// sshString renders one length-prefixed field of the OpenSSH key format.
func sshString(value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(out[:4], uint32(len(value)))
	copy(out[4:], value)
	return out
}

// opensshBlob builds the binary container the current OpenSSH format wraps. The
// key count and the private section are parameters because a container declaring
// no keys, more keys than it carries, or none of the material it announced is
// exactly what a truncated file looks like from the outside.
func opensshBlob(cipher, kdf, algorithm string, keyCount uint32, private []byte) []byte {
	return opensshContainer(cipher, kdf, opensshKDFOptions(kdf), algorithm, keyCount, private)
}

// opensshContainer is the same builder with the derivation options spelled out,
// for the fixtures where those options are what is under test.
func opensshContainer(cipher, kdf string, options []byte, algorithm string, keyCount uint32, private []byte) []byte {
	blob := []byte(opensshMagic)
	blob = append(blob, sshString([]byte(cipher))...)
	blob = append(blob, sshString([]byte(kdf))...)
	blob = append(blob, sshString(options)...)

	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, keyCount)
	blob = append(blob, count...)

	for range keyCount {
		pub := sshString([]byte(algorithm))
		pub = append(pub, sshString(bytes.Repeat([]byte{'p'}, 32))...)
		blob = append(blob, sshString(pub)...)
	}
	return append(blob, sshString(private)...)
}

// opensshKDFOptions is the salt and round count the one defined derivation
// states. Every other name carries nothing here.
func opensshKDFOptions(kdf string) []byte {
	if kdf != "bcrypt" {
		return nil
	}
	options := sshString(bytes.Repeat([]byte{'s'}, 16))
	return binary.BigEndian.AppendUint32(options, 16)
}

// authenticationTag appends what an authenticating cipher writes past the end of
// the private section it declared.
func authenticationTag(blob []byte) []byte {
	return append(blob, bytes.Repeat([]byte{'t'}, 16)...)
}

// declaringKeyCount rewrites the count a container states without touching the
// bodies behind it, which is what a container truncated after its header looks
// like from the outside.
func declaringKeyCount(blob []byte, count uint32) []byte {
	// Past the magic and the three length-prefixed header fields.
	at := len(opensshMagic)
	for range 3 {
		at += 4 + int(binary.BigEndian.Uint32(blob[at:]))
	}
	binary.BigEndian.PutUint32(blob[at:], count)
	return blob
}

// opensshPrivateBody is the unencrypted private half: the consistency number the
// writer states twice, the algorithm the public half already named, then the key
// and its padding to the block size.
func opensshPrivateBody(algorithm string) []byte {
	key := sshString(bytes.Repeat([]byte{'k'}, 32))
	return opensshPadded(algorithm, append(key, sshString([]byte("a-key"))...))
}

// opensshPadded is the same half with its fields supplied and squared with the
// block size the way a writer squares them, for the fixtures where a record that
// walks cleanly to its end is what is under test.
func opensshPadded(algorithm string, fields []byte) []byte {
	body := append([]byte{1, 2, 3, 4, 1, 2, 3, 4}, sshString([]byte(algorithm))...)
	body = append(body, fields...)
	// The bytes squaring the record with the block size count up from one, which
	// is what a reader walks back from to find where the fields ended.
	for pad := 1; len(body)%8 != 0; pad++ {
		body = append(body, byte(pad))
	}
	return body
}

// hardwareOpening is what a device-backed record states before the handle: the
// fields describing the public half, however many the algorithm writes it from,
// what the key was registered for, and the byte of flags — the one thing this
// format writes with no length in front of it, and so the one record that cannot
// simply be walked field by field.
func hardwareOpening(publicFields int, flags byte) []byte {
	var fields []byte
	for range publicFields {
		fields = append(fields, sshString(bytes.Repeat([]byte{'p'}, 32))...)
	}
	fields = append(fields, sshString([]byte("ssh:"))...)
	return append(fields, flags)
}

// deviceHandle stands in for what a device answers to, which is the whole of the
// material such a key holds.
var deviceHandle = bytes.Repeat([]byte{'h'}, 64)

// hardwareKey is a whole device-backed key: the opening, then the handle given,
// the field held in reserve and the comment.
func hardwareKey(algorithm string, publicFields int, flags byte, handle []byte) []byte {
	fields := hardwareOpening(publicFields, flags)
	fields = append(fields, sshString(handle)...)
	fields = append(fields, sshString(nil)...)
	fields = append(fields, sshString([]byte("a-key"))...)
	return pemArmour(opensshType, opensshBlob("none", "none", algorithm, 1, opensshPadded(algorithm, fields)))
}

// opensshRecord is the same half with everything behind its algorithm supplied,
// for the fixtures where what follows the opening is what is under test. The
// tail is written as given and padded to the block size with a byte no padding
// ever holds, so the record is refused for what the tail says and not for its
// length.
func opensshRecord(algorithm string, tail []byte) []byte {
	body := []byte{1, 2, 3, 4, 1, 2, 3, 4}
	body = append(body, sshString([]byte(algorithm))...)
	body = append(body, tail...)
	for len(body)%8 != 0 {
		body = append(body, 'x')
	}
	return body
}

// misPadded rewrites the last byte of a record, which is the last byte of the
// run that squares it with the block size.
func misPadded(body []byte) []byte {
	body[len(body)-1] = 'x'
	return body
}

// opensshKey wraps a well-formed container in its armour. An encrypted private
// half is ciphertext, so it is bytes of an acceptable length and nothing more.
func opensshKey(cipher, kdf, algorithm string) []byte {
	private := opensshPrivateBody(algorithm)
	if kdf != "none" {
		private = bytes.Repeat([]byte{'k'}, 160)
	}
	return pemArmour(opensshType, opensshBlob(cipher, kdf, algorithm, 1, private))
}

// pemArmour wraps bytes in a PEM block of the given type.
func pemArmour(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// puttyFile renders the container's lines. Every field a fixture might leave out
// or fill in to disagree with the rest is a parameter, because that is what a
// truncated or hand-edited file looks like; an empty one omits its line.
func puttyFile(version, algorithm, encryption, publicAlgorithm, authentication string) []byte {
	public := base64.StdEncoding.EncodeToString(sshString([]byte(publicAlgorithm)))
	private := base64.StdEncoding.EncodeToString(sshString(bytes.Repeat([]byte{'k'}, 32)))
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s: %s\n", puttyHeader, version, algorithm)
	if encryption != "" {
		fmt.Fprintf(&b, "Encryption: %s\n", encryption)
	}
	b.WriteString("Comment: a-key\n")
	b.WriteString("Public-Lines: 1\n" + public + "\n")
	if version == "3" && encryption != "" && encryption != "none" {
		b.WriteString("Key-Derivation: Argon2id\nArgon2-Memory: 8192\nArgon2-Passes: 13\nArgon2-Parallelism: 1\nArgon2-Salt: 0011\n")
	}
	b.WriteString("Private-Lines: 1\n" + private + "\n")
	if authentication != "" {
		b.WriteString("Private-MAC: " + authentication + "\n")
	}
	return []byte(b.String())
}

// puttyKey builds a complete key in either published version of the format.
func puttyKey(version int, encryption string) []byte {
	return puttyFile(strconv.Itoa(version), "ssh-ed25519", encryption, "ssh-ed25519", "00")
}

// puttyPrivate rewrites the encoded private half, for the fixtures where what
// the body holds is what is under test.
func puttyPrivate(data, body []byte) []byte {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "Private-Lines:") {
			lines[i+1] = base64.StdEncoding.EncodeToString(body)
			break
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// without drops every line beginning with one of the named fields, which is what
// a container hand-edited down past a mandatory field looks like.
func without(data []byte, fields ...string) []byte {
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if !slices.ContainsFunc(fields, func(f string) bool { return strings.HasPrefix(line, f) }) {
			kept = append(kept, line)
		}
	}
	return []byte(strings.Join(kept, "\n"))
}

// testECKey is generated once: every fixture needing a real key shares it, and
// the elliptic-curve one is the cheapest to produce.
var testECKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
})

var testECPrivateKeyDER = sync.OnceValue(func() []byte {
	der, err := x509.MarshalECPrivateKey(testECKey())
	if err != nil {
		panic(err)
	}
	return der
})

var testECPrivateKeyPEM = sync.OnceValue(func() []byte {
	return pemArmour(pemECPrivate, testECPrivateKeyDER())
})

var testPKCS8PrivateKeyPEM = sync.OnceValue(func() []byte {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pemArmour(pemPKCS8Private, der)
})

var testRSAPrivateKeyPEM = sync.OnceValue(func() []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return pemArmour(pemRSAPrivate, x509.MarshalPKCS1PrivateKey(key))
})

var testPublicKeyPEM = sync.OnceValue(func() []byte {
	der, err := x509.MarshalPKIXPublicKey(testECKey().Public())
	if err != nil {
		panic(err)
	}
	return pemArmour("PUBLIC KEY", der)
})

var testCertificatePEM = sync.OnceValue(func() []byte {
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, testECKey().Public(), testECKey())
	if err != nil {
		panic(err)
	}
	return pemArmour("CERTIFICATE", der)
})

// encryptedPKCS8PEM builds the encrypted container's structure — a scheme, the
// parameters that scheme takes, and a ciphertext — without encrypting anything,
// which is exactly as much as the classifier is allowed to look at.
func encryptedPKCS8PEM(scheme asn1.ObjectIdentifier) []byte {
	return encryptedPKCS8Parameters(scheme, pkcs8SchemeParameters(scheme))
}

// encryptedPKCS8Parameters is the same container with the parameters spelled
// out, for the fixtures where the agreement between a scheme and its parameters
// is what is under test.
func encryptedPKCS8Parameters(scheme asn1.ObjectIdentifier, parameters []byte) []byte {
	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	type encryptedPrivateKeyInfo struct {
		Algorithm algorithmIdentifier
		Data      []byte
	}
	der, err := asn1.Marshal(encryptedPrivateKeyInfo{
		Algorithm: algorithmIdentifier{Algorithm: scheme, Parameters: asn1.RawValue{FullBytes: parameters}},
		Data:      bytes.Repeat([]byte{0x01}, 48),
	})
	if err != nil {
		panic(err)
	}
	return pemArmour(pemPKCS8Encrypted, der)
}

// pkcs8SchemeParameters builds the parameters a scheme is defined to carry: the
// current one states a derivation and a cipher, and every earlier one states the
// salt and iteration count it derived with. Nothing here is a real derivation —
// the shape is the whole of what the classifier reads.
func pkcs8SchemeParameters(scheme asn1.ObjectIdentifier) []byte {
	derived := pkcs8DerivationParameters([]byte("salt-of-the-scheme"), 2048)
	if !scheme.Equal(pkcs8PBES2) {
		return derived
	}
	nonce, err := asn1.Marshal([]byte("sixteen-byte-iv."))
	if err != nil {
		panic(err)
	}
	return pbes2Parameters(asn1.RawValue{FullBytes: derived}, asn1.RawValue{FullBytes: nonce})
}

// pkcs8DerivationParameters builds the pair every derivation these containers
// name opens with: what it started from, and how hard it worked. It is also the
// whole of the parameters for the schemes that came before the current one,
// which state those two directly.
func pkcs8DerivationParameters(salt []byte, work int) []byte {
	parameters, err := asn1.Marshal(struct {
		Salt []byte
		Work int
	}{Salt: salt, Work: work})
	if err != nil {
		panic(err)
	}
	return parameters
}

// pbes2Parameters builds the current scheme's parameters from the two structures
// it is defined to state: how the key was derived, and what it was encrypted
// with. Both are taken as written so a fixture can state either one wrongly.
func pbes2Parameters(derivation, cipher asn1.RawValue) []byte {
	return pbes2Named(pkcs8Derivations[0], aes256CBC, derivation, cipher)
}

// aes256CBC is the cipher an encrypted container is written with by default.
var aes256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

// pbes2Named is the same parameters naming the two algorithms given, for the
// fixtures where the algorithm rather than its parameters is what is under test.
func pbes2Named(derivationOID, cipherOID asn1.ObjectIdentifier, derivation, cipher asn1.RawValue) []byte {
	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	parameters, err := asn1.Marshal(struct {
		Derivation algorithmIdentifier
		Cipher     algorithmIdentifier
	}{
		Derivation: algorithmIdentifier{Algorithm: derivationOID, Parameters: derivation},
		Cipher:     algorithmIdentifier{Algorithm: cipherOID, Parameters: cipher},
	})
	if err != nil {
		panic(err)
	}
	return parameters
}

// pkcs8EnvelopePEM builds an unencrypted container directly, for the shapes the
// standard library's own marshaller cannot produce: a curve written out by its
// parameters rather than by its name is what a widely used export flag emits.
func pkcs8EnvelopePEM(algorithm asn1.ObjectIdentifier, parameters, key []byte) []byte {
	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	der, err := asn1.Marshal(struct {
		Version   int
		Algorithm algorithmIdentifier
		Key       []byte
	}{
		Algorithm: algorithmIdentifier{Algorithm: algorithm, Parameters: asn1.RawValue{FullBytes: parameters}},
		Key:       key,
	})
	if err != nil {
		panic(err)
	}
	return pemArmour(pemPKCS8Private, der)
}

// ellipticCurveOID and explicitCurveParameters are the algorithm an elliptic
// curve container names and a parameter block spelling the curve out in place of
// naming it.
var (
	ellipticCurveOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	// ecPrivateKey is the structure an elliptic curve container wraps: the one
	// version it has, and a scalar standing in for the secret.
	ecPrivateKey = sync.OnceValue(func() []byte {
		key, err := asn1.Marshal(struct {
			Version    int
			PrivateKey []byte
		}{Version: 1, PrivateKey: bytes.Repeat([]byte{'k'}, 32)})
		if err != nil {
			panic(err)
		}
		return key
	})

	explicitCurveParameters = sync.OnceValue(func() []byte {
		parameters, err := asn1.Marshal(struct {
			Version int
			Field   asn1.ObjectIdentifier
		}{Version: 1, Field: asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}})
		if err != nil {
			panic(err)
		}
		return parameters
	})
)

// testEncryptedPKCS8PEM names the scheme a current tool writes.
var testEncryptedPKCS8PEM = sync.OnceValue(func() []byte {
	return encryptedPKCS8PEM(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13})
})

// legacyEncryptedPEM is the older armour, which marks encryption with headers
// rather than a different begin line.
func legacyEncryptedPEM(headers map[string]string) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    pemRSAPrivate,
		Headers: headers,
		Bytes:   bytes.Repeat([]byte{0x02}, 64),
	})
}

// ecParametersPEM is the curve identifier a generator emits ahead of the key it
// makes. It names a curve and holds no secret.
func ecParametersPEM() []byte {
	return pemArmour("EC PARAMETERS", []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07})
}

// sshPublicKeyLine renders the single-line published format.
func sshPublicKeyLine() string {
	blob := sshString([]byte("ssh-ed25519"))
	blob = append(blob, sshString(bytes.Repeat([]byte{'p'}, 32))...)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " a-user@example.invalid"
}

func TestClassifySSHKey(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		want      string
		material  bool
		malformed bool
	}{
		{name: "current format with no passphrase", data: opensshKey("none", "none", "ssh-ed25519"), want: model.CredentialProtectionPlaintext, material: true},
		// Which cipher is named decides nothing beyond whether there is one:
		// cipher defaults change between releases, and a name this build has never
		// seen still describes a key that cannot be used without its passphrase.
		{name: "current format with a passphrase", data: opensshKey("aes256-ctr", "bcrypt", "ssh-ed25519"), want: model.CredentialProtectionProtected, material: true},
		{name: "unfamiliar cipher with a derivation function is still protected", data: opensshKey("some-future-cipher", "bcrypt", "ssh-ed25519"), want: model.CredentialProtectionProtected, material: true},
		// A hardware-backed key stores a handle rather than the secret and has no
		// passphrase to derive from, so reading the algorithm is what keeps the
		// safest key a developer can own from reading as an unprotected one. Both
		// are written the way the format writes them, a bare byte of flags among
		// the fields and all: a record that walks straight through would prove
		// nothing about the one a device actually writes.
		{name: "hardware-backed key with no derivation function", data: hardwareKey("sk-ssh-ed25519@openssh.com", 1, 0x01, deviceHandle), want: model.CredentialProtectionProtected, material: true},
		{name: "hardware-backed key of the other algorithm", data: hardwareKey("sk-ecdsa-sha2-nistp256@openssh.com", 2, 0x01, deviceHandle), want: model.CredentialProtectionProtected, material: true},
		// The flags say what the device asks of whoever uses the key, and a key that
		// asks nothing states them as a zero — which is a byte a length prefix could
		// begin with, so the record has to be read for where its fields resume and
		// not for where they first stop.
		{name: "hardware-backed key that asks nothing of its holder", data: hardwareKey("sk-ssh-ed25519@openssh.com", 1, 0x00, deviceHandle), want: model.CredentialProtectionProtected, material: true},

		// Every one of these announces key material and cannot deliver it. A
		// header-deep reading would have counted the first three as findings.
		{name: "marker only", data: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----\n"), malformed: true},
		{name: "truncated armour", data: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA"), malformed: true},
		{name: "container with the wrong magic", data: pemArmour(opensshType, []byte("not-a-key-v1\x00padding")), malformed: true},
		{name: "container declaring no keys", data: pemArmour(opensshType, opensshBlob("none", "none", "ssh-ed25519", 0, opensshPrivateBody("ssh-ed25519"))), malformed: true},
		{name: "container with no private section", data: pemArmour(opensshType, opensshBlob("none", "none", "ssh-ed25519", 1, nil)), malformed: true},
		{name: "container with an empty derivation field", data: pemArmour(opensshType, opensshBlob("none", "", "ssh-ed25519", 1, opensshPrivateBody("ssh-ed25519"))), malformed: true},
		// A count that disagrees with the bodies behind it is how a truncated
		// container would otherwise read as whole: the second key's public blob
		// stands in for the private section that is no longer there. A count of
		// anything but one is refused whether or not the bodies are there, which
		// is what the format's own reader does.
		{name: "container declaring more keys than it carries", data: pemArmour(opensshType, declaringKeyCount(opensshBlob("none", "none", "ssh-ed25519", 1, opensshPrivateBody("ssh-ed25519")), 2)), malformed: true},
		{name: "container carrying more than one key", data: pemArmour(opensshType, opensshBlob("none", "none", "ssh-ed25519", 2, opensshPrivateBody("ssh-ed25519"))), malformed: true},
		{name: "container with bytes after its private section", data: pemArmour(opensshType, append(opensshBlob("none", "none", "ssh-ed25519", 1, opensshPrivateBody("ssh-ed25519")), 'x')), malformed: true},
		// The private half of an unencrypted key states its own consistency and
		// names the algorithm the public half named, so arbitrary bytes of an
		// acceptable length are not a section this build can confirm.
		{name: "container whose private section is arbitrary bytes", data: pemArmour(opensshType, opensshBlob("none", "none", "ssh-ed25519", 1, bytes.Repeat([]byte{'k'}, 160))), malformed: true},
		{name: "container whose private section names another algorithm", data: pemArmour(opensshType, opensshBlob("none", "none", "ssh-ed25519", 1, opensshPrivateBody("ssh-rsa"))), malformed: true},
		// Past the algorithm the record is the key's own fields, written as this
		// format writes every field and running to the padding that squares them
		// with the block size. Bytes behind a correct opening are not a record,
		// and the walk that establishes that never reads a field.
		{name: "container whose private section stops after its algorithm", data: pemArmour(opensshType, opensshBlob("none", "none", "ssh-ed25519", 1, opensshRecord("ssh-ed25519", bytes.Repeat([]byte{'k'}, 25)))), malformed: true},
		{name: "container whose private section is padded with what padding never holds", data: pemArmour(opensshType, opensshBlob("none", "none", "ssh-ed25519", 1, misPadded(opensshPrivateBody("ssh-ed25519")))), malformed: true},
		// A record squared straight to the block size walks as cleanly as a key does
		// and states none of one, and so does a run of fields that all state
		// nothing. Neither is material, and counting either would be a finding
		// invented out of a container's opening.
		// A device-backed key is protected by what holds the handle, but the handle
		// still has to be there. Deciding on the algorithm name alone would report a
		// file cut off before it as a key sitting on a device that never held one.
		{name: "hardware-backed key stating no handle at all", data: hardwareKey("sk-ssh-ed25519@openssh.com", 1, 0x01, nil), malformed: true},
		{name: "hardware-backed key cut off before its handle", data: pemArmour(opensshType, opensshBlob("none", "none", "sk-ssh-ed25519@openssh.com", 1, opensshPadded("sk-ssh-ed25519@openssh.com", hardwareOpening(1, 0x01)))), malformed: true},
		{name: "container whose private section holds only its padding", data: pemArmour(opensshType, opensshBlob("none", "none", "ssh-ed25519", 1, opensshPadded("ssh-ed25519", nil))), malformed: true},
		{name: "container whose private section states only empty fields", data: pemArmour(opensshType, opensshBlob("none", "none", "ssh-ed25519", 1, opensshPadded("ssh-ed25519", append(sshString(nil), sshString(nil)...)))), malformed: true},
		// The cipher and the derivation state the same fact. Believing either half
		// of a container that contradicts itself would report the wrong protection.
		{name: "container naming a cipher with no derivation", data: pemArmour(opensshType, opensshBlob("aes256-ctr", "none", "ssh-ed25519", 1, opensshPrivateBody("ssh-ed25519"))), malformed: true},
		{name: "container naming a derivation with no cipher", data: pemArmour(opensshType, opensshBlob("none", "bcrypt", "ssh-ed25519", 1, bytes.Repeat([]byte{'k'}, 160))), malformed: true},
		// An authenticating cipher writes its tag past the length the private
		// section declares, so where the container ends is decided by which cipher
		// it named. Both are keys a developer can make with one flag.
		{name: "container encrypted by an authenticating cipher", data: pemArmour(opensshType, authenticationTag(opensshBlob("chacha20-poly1305@openssh.com", "bcrypt", "ssh-ed25519", 1, bytes.Repeat([]byte{'k'}, 160)))), want: model.CredentialProtectionProtected, material: true},
		{name: "container encrypted by the other authenticating cipher", data: pemArmour(opensshType, authenticationTag(opensshBlob("aes256-gcm@openssh.com", "bcrypt", "ssh-ed25519", 1, bytes.Repeat([]byte{'k'}, 160)))), want: model.CredentialProtectionProtected, material: true},
		{name: "container whose authenticating cipher left no tag", data: pemArmour(opensshType, opensshBlob("aes256-gcm@openssh.com", "bcrypt", "ssh-ed25519", 1, bytes.Repeat([]byte{'k'}, 160))), malformed: true},
		{name: "container carrying a tag its cipher does not write", data: pemArmour(opensshType, authenticationTag(opensshBlob("aes256-ctr", "bcrypt", "ssh-ed25519", 1, bytes.Repeat([]byte{'k'}, 160)))), malformed: true},
		// The derivation options are the derivation. A container stating a
		// derivation it gave nothing to work from describes a key nothing could
		// open, which is not a protected key.
		{name: "container whose derivation was given nothing", data: pemArmour(opensshType, opensshContainer("aes256-ctr", "bcrypt", nil, "ssh-ed25519", 1, bytes.Repeat([]byte{'k'}, 160))), malformed: true},
		{name: "container whose derivation states no rounds", data: pemArmour(opensshType, opensshContainer("aes256-ctr", "bcrypt", append(sshString([]byte("saltsaltsaltsalt")), 0, 0, 0, 0), "ssh-ed25519", 1, bytes.Repeat([]byte{'k'}, 160))), malformed: true},
		{name: "container with options and nothing to derive", data: pemArmour(opensshType, opensshContainer("none", "none", []byte("options"), "ssh-ed25519", 1, opensshPrivateBody("ssh-ed25519"))), malformed: true},

		{name: "pkcs8", data: testPKCS8PrivateKeyPEM(), want: model.CredentialProtectionPlaintext, material: true},
		{name: "pkcs1", data: testRSAPrivateKeyPEM(), want: model.CredentialProtectionPlaintext, material: true},
		{name: "elliptic curve", data: testECPrivateKeyPEM(), want: model.CredentialProtectionPlaintext, material: true},
		{name: "raw der with no armour", data: testECPrivateKeyDER(), want: model.CredentialProtectionPlaintext, material: true},
		{name: "encrypted pkcs8", data: testEncryptedPKCS8PEM(), want: model.CredentialProtectionProtected, material: true},
		// Which cipher the key was encrypted with is stated by name, and the names a
		// writer offers grow with every release. A container is protected by the
		// passphrase over it whichever of them it names.
		{name: "encrypted pkcs8 encrypted by a cipher this build has never seen", data: encryptedPKCS8Parameters(pkcs8PBES2, pbes2Named(pkcs8Derivations[0], asn1.ObjectIdentifier{1, 2, 392, 200011, 61, 1, 1, 1, 4}, asn1.RawValue{FullBytes: pkcs8DerivationParameters([]byte("salt"), 2048)}, asn1.RawValue{FullBytes: pkcs8DerivationParameters([]byte("iv"), 1)})), want: model.CredentialProtectionProtected, material: true},
		{name: "legacy format with a passphrase", data: legacyEncryptedPEM(map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,0123456789ABCDEF0123456789ABCDEF"}), want: model.CredentialProtectionProtected, material: true},

		// A private-key block that does not parse is a damaged key, not an
		// unrelated object: reporting it clean would be a claim about a file the
		// agent could not read.
		{name: "pkcs8 marker with no key in it", data: []byte("-----BEGIN PRIVATE KEY-----\ndmFsdWU=\n-----END PRIVATE KEY-----\n"), malformed: true},
		{name: "encrypted pkcs8 with no container in it", data: []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\ndmFsdWU=\n-----END ENCRYPTED PRIVATE KEY-----\n"), malformed: true},
		// A scheme nothing here knows leaves a container that cannot be confirmed,
		// which is not the same as a file holding no key.
		{name: "encrypted pkcs8 naming an unfamiliar scheme", data: encryptedPKCS8PEM(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}), malformed: true},
		// The scheme decides what its parameters look like, so an identifier
		// standing over parameters of another shape describes nothing that could
		// have produced the ciphertext behind it.
		{name: "encrypted pkcs8 whose parameters are the wrong shape", data: encryptedPKCS8Parameters(pkcs8PBES2, pkcs8SchemeParameters(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3})), malformed: true},
		{name: "encrypted pkcs8 with no parameters at all", data: encryptedPKCS8Parameters(pkcs8PBES2, nil), malformed: true},
		// The derivation inside the current scheme states what it started from and
		// how hard it worked. Neither can be missing: a derivation with no salt or
		// no work derives nothing, so nothing could have encrypted this.
		// The current scheme's own identifier says only that a passphrase was
		// involved; the function it names inside is where it says what it derived
		// the key with. Reading that as freely as the scheme itself would let a
		// container name anything at all and still be counted.
		{name: "encrypted pkcs8 derived by a function it cannot name", data: encryptedPKCS8Parameters(pkcs8PBES2, pbes2Named(asn1.ObjectIdentifier{1, 2, 3, 4}, aes256CBC, asn1.RawValue{FullBytes: pkcs8DerivationParameters([]byte("salt"), 2048)}, asn1.RawValue{FullBytes: pkcs8DerivationParameters([]byte("iv"), 1)})), malformed: true},
		{name: "encrypted pkcs8 whose derivation states nothing", data: encryptedPKCS8Parameters(pkcs8PBES2, pbes2Parameters(asn1.RawValue{}, asn1.RawValue{FullBytes: pkcs8DerivationParameters([]byte("salt"), 2048)})), malformed: true},
		{name: "encrypted pkcs8 whose cipher states no nonce", data: encryptedPKCS8Parameters(pkcs8PBES2, pbes2Parameters(asn1.RawValue{FullBytes: pkcs8DerivationParameters([]byte("salt"), 2048)}, asn1.RawValue{})), malformed: true},
		{name: "encrypted pkcs8 derived from no salt", data: encryptedPKCS8Parameters(pkcs8PBES2, pbes2Parameters(asn1.RawValue{FullBytes: pkcs8DerivationParameters(nil, 2048)}, asn1.RawValue{FullBytes: pkcs8DerivationParameters([]byte("iv"), 1)})), malformed: true},
		// A curve spelled out rather than named is what one export flag writes, and
		// the standard library declines to read it. The container still holds a key.
		{name: "pkcs8 written with its curve spelled out", data: pkcs8EnvelopePEM(ellipticCurveOID, explicitCurveParameters(), ecPrivateKey()), want: model.CredentialProtectionPlaintext, material: true},
		{name: "pkcs8 envelope naming an unfamiliar algorithm", data: pkcs8EnvelopePEM(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}, explicitCurveParameters(), ecPrivateKey()), malformed: true},
		{name: "pkcs8 envelope carrying no key", data: pkcs8EnvelopePEM(ellipticCurveOID, explicitCurveParameters(), nil), malformed: true},
		// The envelope is only ever a second reading for the one algorithm the
		// standard library declines over its curve. Naming that algorithm over
		// something that is not a key states a credential the file does not hold,
		// and naming an algorithm that parser already handles means it read the
		// key itself and refused it.
		{name: "pkcs8 envelope wrapping something that is not a key", data: pkcs8EnvelopePEM(ellipticCurveOID, explicitCurveParameters(), []byte("not an elliptic curve key")), malformed: true},
		{name: "pkcs8 envelope wrapping a key of no version", data: pkcs8EnvelopePEM(ellipticCurveOID, explicitCurveParameters(), pkcs8DerivationParameters([]byte("scalar"), 0)), malformed: true},
		{name: "pkcs8 envelope naming an algorithm the library reads", data: pkcs8EnvelopePEM(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, explicitCurveParameters(), ecPrivateKey()), malformed: true},
		{name: "legacy encryption header with no key derivation", data: legacyEncryptedPEM(map[string]string{"Proc-Type": "4,ENCRYPTED"}), malformed: true},
		// The header states a cipher and the vector that cipher takes, so the two
		// have to agree before the body behind them is called encrypted material.
		{name: "legacy encryption naming an unfamiliar cipher", data: legacyEncryptedPEM(map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "SOME-FUTURE-CIPHER,0123456789ABCDEF"}), malformed: true},
		{name: "legacy encryption whose vector is the wrong length", data: legacyEncryptedPEM(map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,0123456789ABCDEF"}), malformed: true},
		// The unencrypted legacy DSA encoding has no standard-library parser, so
		// it fails visibly rather than being counted on its begin line.
		{name: "legacy dsa", data: pemArmour(pemDSAPrivate, bytes.Repeat([]byte{0x03}, 64)), malformed: true},

		// Published material is neither a credential nor a failure.
		{name: "certificate", data: testCertificatePEM(), material: false},
		{name: "public key", data: testPublicKeyPEM(), material: false},
		{name: "public key line", data: []byte(sshPublicKeyLine() + "\n"), material: false},
		{name: "host key list", data: []byte("example.invalid " + sshPublicKeyLine() + "\n"), material: false},
		{name: "empty file", data: nil, material: false},

		// A key beside its certificate is an ordinary layout, and the pair has to
		// classify from the key.
		{name: "key and certificate bundle", data: append(append([]byte{}, testECPrivateKeyPEM()...), testCertificatePEM()...), want: model.CredentialProtectionPlaintext, material: true},
		// A damaged sibling block costs the file its completeness without
		// discarding the key that was confirmed.
		{name: "key beside a damaged key block", data: append(append([]byte{}, testECPrivateKeyPEM()...), []byte("-----BEGIN PRIVATE KEY-----\ndmFsdWU=\n-----END PRIVATE KEY-----\n")...), want: model.CredentialProtectionPlaintext, material: true, malformed: true},
		// The worst protection in a bundle describes it.
		{name: "protected key beside a plaintext one", data: append(append([]byte{}, testEncryptedPKCS8PEM()...), testECPrivateKeyPEM()...), want: model.CredentialProtectionPlaintext, material: true},
		// A generator writes the curve it used ahead of the key it made, so the
		// pair has to classify from the key and cost the file nothing.
		{name: "curve parameters ahead of the key", data: append(append([]byte{}, ecParametersPEM()...), testECPrivateKeyPEM()...), want: model.CredentialProtectionPlaintext, material: true},
		// Armour this build cannot account for is reported rather than passed
		// over: a key in an encoding never learned would otherwise read as a file
		// holding nothing.
		{name: "armour of an unknown type", data: pemArmour("PGP PRIVATE KEY BLOCK", bytes.Repeat([]byte{0x04}, 64)), malformed: true},
		// The second block never decoded, so nothing is left to classify it from —
		// the confirmed key beside it must not present the file as whole.
		{name: "key followed by armour that does not close", data: append(append([]byte{}, testECPrivateKeyPEM()...), []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n")...), want: model.CredentialProtectionPlaintext, material: true, malformed: true},
		// A file opening with the current format is walked block by block like any
		// other, so a damaged sibling behind it still costs the file its
		// completeness rather than being left unread behind the first block.
		{name: "current format followed by a damaged key block", data: append(append([]byte{}, opensshKey("none", "none", "ssh-ed25519")...), []byte("-----BEGIN PRIVATE KEY-----\ndmFsdWU=\n-----END PRIVATE KEY-----\n")...), want: model.CredentialProtectionPlaintext, material: true, malformed: true},

		{name: "putty without a passphrase", data: puttyKey(3, "none"), want: model.CredentialProtectionPlaintext, material: true},
		{name: "putty with a passphrase", data: puttyKey(3, "aes256-cbc"), want: model.CredentialProtectionProtected, material: true},
		{name: "putty of the older version", data: puttyKey(2, "none"), want: model.CredentialProtectionPlaintext, material: true},
		{name: "putty missing its private material", data: []byte("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nPrivate-Lines: 1\n"), malformed: true},
		{name: "putty of the newer version missing its private material", data: []byte("PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nPrivate-Lines: 1\n"), malformed: true},
		{name: "putty missing its mandatory encryption field", data: []byte("PuTTY-User-Key-File-3: ssh-ed25519\nComment: a-key\n"), malformed: true},
		{name: "putty missing its authentication code", data: puttyFile("3", "ssh-ed25519", "none", "ssh-ed25519", ""), malformed: true},
		{name: "putty whose authentication code is not hexadecimal", data: puttyFile("3", "ssh-ed25519", "none", "ssh-ed25519", "not-hexadecimal"), malformed: true},
		// A version with no published layout is not read on the assumption its
		// fields still mean what this build takes them to mean.
		{name: "putty of an unpublished version", data: puttyKey(99, "none"), malformed: true},
		// Naming an encryption this build cannot account for leaves the protection
		// unresolved, and guessing it would report the wrong one.
		{name: "putty naming an unfamiliar encryption", data: puttyKey(3, "some-future-cipher"), malformed: true},
		// The public half has to name the algorithm the header declared, or the
		// file is not the key it says it is.
		{name: "putty whose public half names another algorithm", data: puttyFile("3", "ssh-ed25519", "none", "ssh-rsa", "00"), malformed: true},
		// The comment is mandatory in every published version, and its absence is
		// what a container edited down past one of its fields looks like. The value
		// is never read.
		{name: "putty missing its comment", data: without(puttyKey(3, "none"), "Comment"), malformed: true},
		// The later version derives its key rather than using the passphrase, and
		// states how. A file of that version claiming encryption without those
		// fields describes a key nothing could open.
		{name: "putty of the newer version encrypted with no derivation stated", data: without(puttyKey(3, "aes256-cbc"), "Key-Derivation", "Argon2"), malformed: true},
		{name: "putty naming a derivation nothing knows", data: bytes.Replace(puttyKey(3, "aes256-cbc"), []byte("Argon2id"), []byte("some-future-derivation"), 1), malformed: true},
		{name: "putty whose derivation cost is not a number", data: bytes.Replace(puttyKey(3, "aes256-cbc"), []byte("Argon2-Passes: 13"), []byte("Argon2-Passes: many"), 1), malformed: true},
		{name: "putty whose derivation salt is not hexadecimal", data: bytes.Replace(puttyKey(3, "aes256-cbc"), []byte("Argon2-Salt: 0011"), []byte("Argon2-Salt: not-hexadecimal"), 1), malformed: true},
		// A field stated twice leaves the file saying two things with no rule for
		// which one holds. Where the repeated field is the one naming the
		// protection, believing either statement is a guess.
		{name: "putty stating its encryption twice", data: bytes.Replace(puttyKey(3, "none"), []byte("Encryption: none\n"), []byte("Encryption: none\nEncryption: aes256-cbc\n"), 1), malformed: true},
		{name: "putty stating its private material twice", data: bytes.Replace(puttyKey(3, "none"), []byte("Private-Lines: 1\n"), []byte("Private-Lines: 1\nPrivate-Lines: 1\n"), 1), malformed: true},
		// With nothing encrypting it the private half is the key's own fields,
		// written the way this format writes every field and running to the end of
		// the body. Bytes of an acceptable length are not those fields, and no
		// field's contents are read to establish it.
		{name: "putty whose unencrypted private half is arbitrary bytes", data: puttyPrivate(puttyKey(3, "none"), bytes.Repeat([]byte{'k'}, 32)), malformed: true},
		{name: "putty whose unencrypted private half states nothing", data: puttyPrivate(puttyKey(3, "none"), sshString(nil)), malformed: true},
		{name: "putty whose unencrypted private half stops mid-field", data: puttyPrivate(puttyKey(3, "none"), append(sshString(bytes.Repeat([]byte{'k'}, 32)), 0, 0, 0, 8)), malformed: true},

		{name: "prose in place of a key", data: []byte("this file is a note someone left in the key directory\n"), malformed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, material, malformed := classifySSHKey(tt.data)
			if material != tt.material || malformed != tt.malformed {
				t.Fatalf("material/malformed = %v/%v, want %v/%v", material, malformed, tt.material, tt.malformed)
			}
			if got != tt.want {
				t.Errorf("protection = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClassifySSHKey_MarkerIsNeverEvidence states the rule the whole rewrite
// exists for, separately from the table: no format is classified from the line
// that announces it, because the file most in need of a correct answer is the one
// carrying the marker and nothing behind it.
func TestClassifySSHKey_MarkerIsNeverEvidence(t *testing.T) {
	markers := []string{
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		puttyHeader + "3: ssh-ed25519",
	}
	for _, marker := range markers {
		if _, material, _ := classifySSHKey([]byte(marker + "\n")); material {
			t.Errorf("%q alone was classified as key material", marker)
		}
	}
}

func TestLooksLikeKeyFile(t *testing.T) {
	tests := map[string]bool{
		"id_ed25519":             true,
		"id_rsa":                 true,
		"work_key":               true,
		"id_ecdsa_sk":            true,
		"id_rsa.pub":             false,
		"id_ed25519.pub":         false,
		"id_ed25519-cert.pub":    false,
		"server.crt":             false,
		"client.cer":             false,
		"request.csr":            false,
		"config":                 false,
		"known_hosts":            false,
		"known_hosts2":           false,
		"authorized_keys":        false,
		"authorized_keys2":       false,
		"allowed_signers":        false,
		"environment":            false,
		"rc":                     false,
		".DS_Store":              false,
		".ssh-agent-environment": false,
	}
	for name, want := range tests {
		if got := looksLikeKeyFile(name); got != want {
			t.Errorf("looksLikeKeyFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestReadSSHString_BoundedByWhatRemains(t *testing.T) {
	value, rest, ok := readSSHString(append(sshString([]byte("abc")), 'x'))
	if !ok || string(value) != "abc" || string(rest) != "x" {
		t.Errorf("read = %q/%q/%v, want %q/%q/true", value, rest, ok, "abc", "x")
	}
	// A length longer than the buffer must fail rather than drive an allocation.
	oversized := []byte{0xff, 0xff, 0xff, 0xff, 'a'}
	if _, _, ok := readSSHString(oversized); ok {
		t.Error("a length past the end of the buffer must not be read")
	}
	if _, _, ok := readSSHString([]byte{0, 0}); ok {
		t.Error("a buffer too short for the length prefix must not be read")
	}
}

func TestDecodeBase64Lines(t *testing.T) {
	lines := []string{"Private-Lines: 2", "AAAA", "BBBB", "Private-MAC: 00"}
	decoded, count, ok := decodeBase64Lines(lines, 1, "2")
	if !ok || count != 2 || len(decoded) != 6 {
		t.Errorf("decoded = %d bytes over %d lines (ok=%v), want 6 over 2", len(decoded), count, ok)
	}
	// A count naming more lines than the file has is how a truncated container
	// would otherwise pass for a whole one.
	if _, _, ok := decodeBase64Lines(lines, 1, "9"); ok {
		t.Error("a count past the end of the file must not be accepted")
	}
	if _, _, ok := decodeBase64Lines(lines, 1, "not a number"); ok {
		t.Error("a count that is not a number must not be accepted")
	}
	if _, _, ok := decodeBase64Lines([]string{"", "not base64 !!"}, 1, "1"); ok {
		t.Error("a body line that is not base64 must not be accepted")
	}
}

func TestIsSSHPublicKeyText(t *testing.T) {
	tests := map[string]bool{
		sshPublicKeyLine():                             true,
		"example.invalid " + sshPublicKeyLine():        true,
		sshPublicKeyLine() + "\n" + sshPublicKeyLine(): true,
		"ssh-ed25519 not-base64!!":                     false,
		// The blob has to name the algorithm the line claims, so arbitrary base64
		// behind a key-shaped word is not a public key.
		"ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte("nonsense")): false,
		"this is prose": false,
		"":              false,
	}
	for text, want := range tests {
		if got := isSSHPublicKeyText([]byte(text)); got != want {
			t.Errorf("isSSHPublicKeyText(%q) = %v, want %v", text, got, want)
		}
	}
}
