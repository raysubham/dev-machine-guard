package credentials

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"slices"
	"strconv"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// Private-key container markers. Each one only selects which validator runs: a
// marker is never evidence on its own, because the file that most needs to be
// classified correctly — a truncated or hand-edited key — carries the marker and
// nothing behind it.
const (
	opensshType  = "OPENSSH PRIVATE KEY"
	opensshMagic = "openssh-key-v1\x00"
	puttyHeader  = "PuTTY-User-Key-File-"
)

// PEM block types that declare private-key material. A block of one of these
// types that does not parse is a malformed key rather than an unrelated object,
// which is the difference between an incomplete scan and a silent pass.
const (
	pemRSAPrivate       = "RSA PRIVATE KEY"
	pemECPrivate        = "EC PRIVATE KEY"
	pemDSAPrivate       = "DSA PRIVATE KEY"
	pemPKCS8Private     = "PRIVATE KEY"
	pemPKCS8Encrypted   = "ENCRYPTED PRIVATE KEY"
	pemLegacyEncryption = "Proc-Type"
)

// pemNonSecretTypes carry no secret and are the shapes that routinely sit in the
// same file as a key: the published half, the certificate it was issued, and the
// curve parameters a generator emits ahead of the key it made. Listed rather than
// inferred, so that a bundle classifies from its key alone and a block type this
// build has never seen is still reported rather than passed over.
var pemNonSecretTypes = map[string]bool{
	"CERTIFICATE":         true,
	"PUBLIC KEY":          true,
	"RSA PUBLIC KEY":      true,
	"CERTIFICATE REQUEST": true,
	"X509 CRL":            true,
	"EC PARAMETERS":       true,
	"DH PARAMETERS":       true,
}

// sshSkipSuffixes are the files that live beside private keys and are not
// private keys. Reporting a public half or a certificate as a credential would
// tell a developer their published key is exposed.
var sshSkipSuffixes = []string{".pub", ".cer", ".crt", ".csr"}

// sshSkipNames are the configuration and bookkeeping files kept in the same
// directory.
var sshSkipNames = map[string]bool{
	"config":           true,
	"known_hosts":      true,
	"known_hosts2":     true,
	"authorized_keys":  true,
	"authorized_keys2": true,
	"allowed_signers":  true,
	"environment":      true,
	"rc":               true,
}

// looksLikeKeyFile keeps the directory listing from opening files that are
// obviously not keys. A file it admits is still classified from its contents,
// and a file it rejects is never read.
func looksLikeKeyFile(name string) bool {
	if sshSkipNames[name] {
		return false
	}
	lower := strings.ToLower(name)
	for _, suffix := range sshSkipSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return !strings.HasPrefix(name, ".")
}

// classifySSHKey decides whether a file holds private-key material and, if so,
// what guards it. The third return says the file announced key material this
// build could not confirm — a truncated container, a private-key block that does
// not parse, a mandatory field that is missing.
//
// Every accepted format is validated over its complete bytes rather than from its
// header, because the two failure directions are not equal. Calling a marker a key
// invents a credential out of a file someone left behind; calling a real key
// nothing at all hides one. The third result exists so neither has to be chosen: a
// container that announces material and cannot be confirmed is reported as
// uninterpreted, which is neither.
func classifySSHKey(data []byte) (protection string, material, malformed bool) {
	trimmed := bytes.TrimSpace(data)
	switch {
	case len(trimmed) == 0:
		return "", false, false
	case bytes.HasPrefix(trimmed, []byte(puttyHeader)):
		return classifyPuTTYContainer(data)
	default:
		// The current OpenSSH format is armoured like every other key here, so it
		// goes through the same block walk: a file that opens with one and carries
		// something damaged behind it must not classify from its first block alone.
		return classifyPEMOrDERKey(data)
	}
}

// opensshBlockSize is the granularity the private section is padded to. Every
// cipher this format defines agrees on it: the unencrypted case pads to eight
// bytes, and each cipher it can name pads to a multiple of that.
const opensshBlockSize = 8

// opensshTrailingBytes is how much each cipher leaves after the private section,
// keyed by the name the container states. The authenticating ciphers append a
// tag that the section's own length does not cover, so a container encrypted
// with one ends sixteen bytes past where every other cipher ends. A cipher this
// build has never seen reads zero here and is held to the common case.
var opensshTrailingBytes = map[string]int{
	"chacha20-poly1305@openssh.com": 16,
	"aes128-gcm@openssh.com":        16,
	"aes256-gcm@openssh.com":        16,
}

// validOpenSSHKDFOptions checks the derivation options against the derivation
// they belong to. Only two names have a defined layout — the one that derives a
// key and the one that states there is nothing to derive — and each is checked
// against its own. A name this build has never seen is left alone rather than
// held to a layout it never claimed.
func validOpenSSHKDFOptions(kdf string, options []byte) bool {
	switch kdf {
	case "none":
		return len(options) == 0
	case "bcrypt":
		salt, rest, ok := readSSHString(options)
		if !ok || len(salt) == 0 || len(rest) != 4 {
			return false
		}
		// A derivation of no rounds derives nothing, so a container stating it
		// could not have been written by anything that encrypts.
		return binary.BigEndian.Uint32(rest) > 0
	}
	return true
}

// classifyOpenSSHBlob validates the binary container. Every field is walked
// because a length prefix that overruns the buffer is how a truncated file
// otherwise passes for a whole one; the values are read only where the answer
// lives.
func classifyOpenSSHBlob(blob []byte) (string, bool, bool) {
	rest, ok := bytes.CutPrefix(blob, []byte(opensshMagic))
	if !ok {
		return "", false, true
	}
	cipher, rest, ok := readSSHString(rest)
	if !ok {
		return "", false, true
	}
	kdf, rest, ok := readSSHString(rest)
	if !ok {
		return "", false, true
	}
	options, rest, ok := readSSHString(rest)
	if !ok || len(rest) < 4 {
		return "", false, true
	}
	// One key per file is the whole of this format: the count field exists, and
	// the reference implementation refuses any value but one. A container stating
	// more is either truncated or something other than a key file.
	if binary.BigEndian.Uint32(rest[:4]) != 1 {
		return "", false, true
	}
	public, rest, ok := readSSHString(rest[4:])
	if !ok {
		return "", false, true
	}
	algorithm, _, ok := readSSHString(public)
	if !ok {
		return "", false, true
	}
	// The private section is the material itself, and it is the last field of the
	// container: its absence is what separates a key from a public blob wrapped in
	// a private-key container.
	private, rest, ok := readSSHString(rest)
	if !ok || len(private) == 0 || len(private)%opensshBlockSize != 0 {
		return "", false, true
	}
	// What may follow the private section is decided entirely by the cipher: the
	// authenticating ciphers write their tag outside the declared length, and
	// every other cipher ends the container there. Anything else is not this
	// format, whichever cipher was named.
	if len(rest) != opensshTrailingBytes[string(cipher)] {
		return "", false, true
	}
	// The two fields state the same fact and have to agree. A named cipher with no
	// derivation, or a derivation with no cipher, describes a container neither
	// reading of which could be acted on — and guessing which half to believe is
	// how an encrypted key gets reported as an exposed one.
	encrypted := string(cipher) != "none"
	if encrypted != (string(kdf) != "none") {
		return "", false, true
	}
	if !validOpenSSHKDFOptions(string(kdf), options) {
		return "", false, true
	}
	if encrypted {
		return model.CredentialProtectionProtected, true, false
	}
	// A hardware-backed key holds a handle rather than the secret, and has no
	// passphrase to derive from, so the algorithm the public half names is what
	// decides its protection: the safest key a developer can own would otherwise
	// read as an unprotected one. Its record is still read, and against its own
	// structure — the name alone would report a truncated file as a key on a
	// device that never held one.
	if bytes.HasPrefix(algorithm, []byte("sk-")) {
		if !opensshHardwarePrivate(private, algorithm) {
			return "", false, true
		}
		return model.CredentialProtectionProtected, true, false
	}
	if !opensshPlaintextPrivate(private, algorithm) {
		return "", false, true
	}
	return model.CredentialProtectionPlaintext, true, false
}

// opensshRecordOpening reads what every unencrypted private section opens with —
// one number stated twice so a wrong passphrase is detectable, then the algorithm
// the public half already named — and returns the key's own fields behind it.
func opensshRecordOpening(private, algorithm []byte) ([]byte, bool) {
	if len(private) < 8 || !bytes.Equal(private[:4], private[4:8]) {
		return nil, false
	}
	name, rest, ok := readSSHString(private[8:])
	if !ok || !bytes.Equal(name, algorithm) {
		return nil, false
	}
	return rest, true
}

// opensshPlaintextPrivate checks the unencrypted private section against its own
// structure: its opening, and then the fields of the key itself running to the
// end of the section but for the padding that squares it with the block size.
// Nothing here reads a field's contents — walking them is what separates a key
// record from arbitrary bytes of an acceptable length.
func opensshPlaintextPrivate(private, algorithm []byte) bool {
	rest, ok := opensshRecordOpening(private, algorithm)
	if !ok {
		return false
	}
	rest, fields, filled := walkSSHStrings(rest)
	// Every algorithm writes the key's own fields and then the comment naming it,
	// so two is the fewest fields any record can be written from, and the secret
	// among them is never the empty one. A well-formed run of nothing is a record
	// holding no key, which is the shape a container padded straight to its block
	// size takes.
	if fields < 2 || filled == 0 {
		return false
	}
	return opensshPadding(rest)
}

// opensshHardwarePrivate checks the record a device-backed key is written from.
// It is fields like any other record but for one thing: between what the key was
// registered for and the handle standing in for the secret, the writer states a
// byte of flags with no length in front of it — the only bare byte this format
// writes, and the reason such a record cannot simply be walked. Where that byte
// falls is decided by how the public half was written, so it is searched for
// rather than assumed: each field boundary is tried as the place it stands, and
// the record is one when the fields resume there and run to the padding. A key
// type this build has never seen is read the same way, so long as it is written
// the way the ones before it were.
func opensshHardwarePrivate(private, algorithm []byte) bool {
	body, ok := opensshRecordOpening(private, algorithm)
	if !ok {
		return false
	}
	for fields := 0; len(body) > 0; fields++ {
		// What the key was registered for stands behind the public half, so the
		// flags are never where the record's first field would be.
		if fields >= 2 {
			// The handle is the material: it is what the device is asked with, and a
			// record stating none of it holds no more of a key than an empty file
			// does. What follows it — the field held in reserve and the comment — is
			// counted and not read, either of them being empty in keys written today.
			if handle, tail, ok := readSSHString(body[1:]); ok && len(handle) > 0 {
				if rest, after, _ := walkSSHStrings(tail); after >= 2 && opensshPadding(rest) {
					return true
				}
			}
		}
		_, next, ok := readSSHString(body)
		if !ok {
			return false
		}
		body = next
	}
	return false
}

// walkSSHStrings consumes consecutive length-prefixed fields, returning what is
// left where the next one would begin along with how many fields were read and how
// many of them held anything. The fields a private key is written from differ
// between algorithms in number and in meaning but never in shape, so a record can
// be walked to its end without knowing which kind of key it holds — and a key type
// this build has never seen walks the same as any other. What the counts add is
// the one thing shape alone cannot say: whether the walk crossed any material.
func walkSSHStrings(body []byte) (rest []byte, fields, filled int) {
	for {
		value, next, ok := readSSHString(body)
		if !ok {
			return body, fields, filled
		}
		fields++
		if len(value) > 0 {
			filled++
		}
		body = next
	}
}

// opensshPadding checks the bytes squaring the private section with the block
// size. They count up from one, so they are also what proves the walk above
// ended where the record ended rather than in the middle of a field: any run
// starting with a one is too long to be read as a field of its own.
func opensshPadding(rest []byte) bool {
	if len(rest) >= opensshBlockSize {
		return false
	}
	for i, b := range rest {
		if int(b) != i+1 {
			return false
		}
	}
	return true
}

// readSSHString reads one length-prefixed field. The length is bounded by what
// remains, so a corrupt or truncated container cannot drive an allocation or read
// past the buffer.
func readSSHString(b []byte) (value, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	// Compared as int64, which both a uint32 length and a slice length widen into
	// without wrapping, so the bound holds for any container the file can carry.
	n := binary.BigEndian.Uint32(b[:4])
	if int64(n) > int64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// puttyVersions are the container versions with a published layout. A file
// announcing another one is not read on the assumption its fields still mean what
// this build takes them to mean.
var puttyVersions = map[string]bool{"2": true, "3": true}

// puttyEncryptions are the values the field that decides protection is defined to
// take. Anything else leaves protection unresolved, and guessing it is how an
// encrypted key would be reported as an exposed one.
var puttyEncryptions = map[string]bool{"none": true, "aes256-cbc": true}

// classifyPuTTYContainer validates the PuTTY formats, which state their fields in
// the clear as text. The declared line counts, the encoded bodies behind them and
// the agreement between the header and the public half are all checked: this
// format's header is trivially forgeable by a truncation, and the encryption
// field alone would classify a file holding no key at all.
func classifyPuTTYContainer(data []byte) (string, bool, bool) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	fields := map[string]string{}
	var version, algorithm string
	var public, private []byte

	for i := 0; i < len(lines); i++ {
		key, value, ok := strings.Cut(lines[i], ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		// A field stated twice states two things, and the file gives no rule for
		// which of them holds. Where the field is the one naming the protection,
		// believing either is a guess — so a file that repeats any of them is a
		// file whose fields cannot be taken at their word.
		if _, repeated := fields[key]; repeated {
			return "", false, true
		}
		fields[key] = value
		switch {
		case strings.HasPrefix(key, puttyHeader):
			version, algorithm = strings.TrimPrefix(key, puttyHeader), value
		case key == "Public-Lines", key == "Private-Lines":
			body, count, ok := decodeBase64Lines(lines, i+1, value)
			if !ok {
				return "", false, true
			}
			if key == "Private-Lines" {
				private = body
			} else {
				public = body
			}
			i += count
		}
	}

	encryption := fields["Encryption"]
	// Every one of these is mandatory in both published versions of the format.
	if !puttyVersions[version] || algorithm == "" || len(private) == 0 {
		return "", false, true
	}
	if _, ok := fields["Comment"]; !ok || !isHexString(fields["Private-MAC"]) {
		return "", false, true
	}
	// The public half names the algorithm the header declared. A body naming
	// something else, or naming nothing, is not the key this file says it holds.
	if name, _, ok := readSSHString(public); !ok || string(name) != algorithm {
		return "", false, true
	}
	if !puttyEncryptions[strings.ToLower(encryption)] {
		return "", false, true
	}
	if strings.EqualFold(encryption, "none") {
		// With no passphrase over it the private half is the key's own fields,
		// written the way every field in this format is and running to the end of
		// the body. Encrypted, it is ciphertext padded to the cipher's block, and
		// there is nothing there to walk. One field stating nothing walks as
		// cleanly as a key does and is not one.
		if rest, _, filled := walkSSHStrings(private); len(rest) != 0 || filled == 0 {
			return "", false, true
		}
		return model.CredentialProtectionPlaintext, true, false
	}
	// The later version derives its key rather than using the passphrase
	// directly, and states how in fields of its own. A file of that version
	// claiming encryption without them describes a key nothing could open, which
	// is not a protected key — it is a container this build cannot confirm.
	if version == "3" && !validPuTTYDerivation(fields) {
		return "", false, true
	}
	return model.CredentialProtectionProtected, true, false
}

// puttyDerivations are the derivations the later version can name.
var puttyDerivations = map[string]bool{"argon2i": true, "argon2d": true, "argon2id": true}

// validPuTTYDerivation checks the fields stating how the key was derived. The
// cost parameters are read only to confirm they are the numbers they are
// declared to be, and the salt only to confirm it is the hexadecimal it is
// declared to be; neither value is compared against anything.
func validPuTTYDerivation(fields map[string]string) bool {
	if !puttyDerivations[strings.ToLower(fields["Key-Derivation"])] {
		return false
	}
	for _, cost := range []string{"Argon2-Memory", "Argon2-Passes", "Argon2-Parallelism"} {
		if n, err := strconv.Atoi(fields[cost]); err != nil || n <= 0 {
			return false
		}
	}
	return isHexString(fields["Argon2-Salt"])
}

// isHexString reports whether a field is the hexadecimal it is declared to be.
// The value itself is never compared against anything.
func isHexString(value string) bool {
	if value == "" {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// decodeBase64Lines consumes the body a line-count field declares, returning the
// bytes it decoded to. A count naming more lines than the file has, or a body line
// that is not base64, means the container was truncated or edited.
func decodeBase64Lines(lines []string, from int, countField string) (decoded []byte, count int, ok bool) {
	count, err := strconv.Atoi(countField)
	if err != nil || count <= 0 || from+count > len(lines) {
		return nil, 0, false
	}
	for _, line := range lines[from : from+count] {
		body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil || len(body) == 0 {
			return nil, 0, false
		}
		decoded = append(decoded, body...)
	}
	return decoded, count, true
}

// classifyPEMOrDERKey handles everything else: one or more PEM blocks, or a bare
// DER encoding with no armour at all. Every block is walked rather than only the
// first, because a key and its certificate in one file is an ordinary layout and
// stopping at the first block would classify the pair by whichever came first.
func classifyPEMOrDERKey(data []byte) (protection string, material, malformed bool) {
	blocks := 0
	for rest := data; ; {
		block, next := pem.Decode(rest)
		if block == nil {
			// Armour that stopped decoding partway leaves its remainder here. A
			// truncated key after a whole one is the case this catches: without
			// it the file classifies from the block that did decode and the
			// damaged one leaves no trace at all.
			if blocks > 0 && len(bytes.TrimSpace(rest)) > 0 {
				malformed = true
			}
			break
		}
		blocks++
		rest = next

		blockProtection, blockMaterial, blockMalformed := classifyPEMBlock(block)
		malformed = malformed || blockMalformed
		if !blockMaterial {
			continue
		}
		material = true
		// The worst protection in the bundle describes it, the same way the fold
		// over a whole source does.
		if protection == "" || blockProtection == model.CredentialProtectionPlaintext {
			protection = blockProtection
		}
	}
	if blocks > 0 {
		return protection, material, malformed
	}

	switch {
	case parsesRawDERPrivateKey(data):
		// Unarmoured DER carries no encryption header, so what parses is in the
		// clear by construction.
		return model.CredentialProtectionPlaintext, true, false
	case parsesRawDERPublicKeyOrCertificate(data), isSSHPublicKeyText(data):
		// Published material, which is not a credential and not a failure either.
		return "", false, false
	default:
		return "", false, true
	}
}

// classifyPEMBlock resolves one block. A type this build cannot account for is
// reported rather than passed over: armour it does not recognise is exactly how a
// key in an encoding this build never learned would read as a clean file.
func classifyPEMBlock(block *pem.Block) (string, bool, bool) {
	switch block.Type {
	case opensshType:
		return classifyOpenSSHBlob(block.Bytes)

	case pemPKCS8Encrypted:
		if !parsesEncryptedPKCS8(block.Bytes) {
			return "", false, true
		}
		return model.CredentialProtectionProtected, true, false

	case pemRSAPrivate, pemECPrivate, pemDSAPrivate:
		// The legacy format marks encryption with a header rather than a
		// different begin line, so this has to be read before attempting a
		// plaintext parse — the body of an encrypted key is ciphertext and would
		// fail every parser as though it were malformed.
		if strings.EqualFold(strings.TrimSpace(block.Headers[pemLegacyEncryption]), "4,ENCRYPTED") {
			if !validLegacyEncryptionHeader(block) {
				return "", false, true
			}
			return model.CredentialProtectionProtected, true, false
		}
		if parsesLegacyPEMPrivateKey(block) {
			return model.CredentialProtectionPlaintext, true, false
		}
		// Includes the unencrypted legacy DSA encoding, which has no
		// standard-library parser: it fails visibly here rather than being
		// counted on the strength of its begin line.
		return "", false, true

	case pemPKCS8Private:
		if !parsesPKCS8PrivateKey(block.Bytes) {
			return "", false, true
		}
		return model.CredentialProtectionPlaintext, true, false
	}

	if pemNonSecretTypes[block.Type] {
		return "", false, false
	}
	return "", false, true
}

// parsesLegacyPEMPrivateKey parses the two legacy encodings with their own
// standard-library parsers, matched to the block type so an RSA body in an
// elliptic-curve block cannot pass.
func parsesLegacyPEMPrivateKey(block *pem.Block) bool {
	switch block.Type {
	case pemRSAPrivate:
		_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		return err == nil
	case pemECPrivate:
		_, err := x509.ParseECPrivateKey(block.Bytes)
		return err == nil
	}
	return false
}

// pemLegacyCiphers are the ciphers the legacy header can name, each with the
// length in bytes of the initialisation vector stated beside it. Holding the pair
// is what makes the header checkable without decrypting anything: a vector of the
// wrong length for the cipher it accompanies is not a header any writer produced.
var pemLegacyCiphers = map[string]int{
	"DES-CBC":          8,
	"DES-EDE-CBC":      8,
	"DES-EDE3-CBC":     8,
	"RC2-CBC":          8,
	"AES-128-CBC":      16,
	"AES-192-CBC":      16,
	"AES-256-CBC":      16,
	"CAMELLIA-128-CBC": 16,
	"CAMELLIA-192-CBC": 16,
	"CAMELLIA-256-CBC": 16,
}

// validLegacyEncryptionHeader checks that the header naming how a legacy block
// was encrypted agrees with itself and with the body behind it. Nothing is
// decrypted: the vector is measured and discarded, and the ciphertext is only
// ever counted.
func validLegacyEncryptionHeader(block *pem.Block) bool {
	name, vector, ok := strings.Cut(strings.TrimSpace(block.Headers["DEK-Info"]), ",")
	if !ok {
		return false
	}
	size, known := pemLegacyCiphers[strings.ToUpper(strings.TrimSpace(name))]
	if !known {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimSpace(vector))
	if err != nil || len(raw) != size {
		return false
	}
	// Every cipher here runs in a chaining mode, so a body that is not a whole
	// number of blocks was never its output.
	return len(block.Bytes) > 0 && len(block.Bytes)%size == 0
}

// pkcs8EllipticCurve is the identifier a container states for an elliptic-curve
// key. It is the one algorithm the standard library's parser declines over how
// the curve was written rather than over whether a key is there.
var pkcs8EllipticCurve = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// parsesPKCS8PrivateKey reports whether a container holds a private key. The
// standard library's parser answers for every algorithm it supports, and it
// answers completely: it reads the key. Only one shape gets a second look — an
// elliptic curve written out by its parameters rather than by its name, which a
// widely used export flag produces and which that parser refuses on the curve
// alone. The key is read there for its structure, never for its value.
func parsesPKCS8PrivateKey(der []byte) bool {
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return true
	}
	var info struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		Key        []byte
		Attributes asn1.RawValue `asn1:"optional,tag:0"`
	}
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 || info.Version != 0 {
		return false
	}
	if !info.Algorithm.Algorithm.Equal(pkcs8EllipticCurve) {
		return false
	}
	return holdsECPrivateKey(info.Key)
}

// holdsECPrivateKey checks the wrapped key against the structure an elliptic
// curve key is written in: the one version this structure has ever had, and a
// scalar. The scalar is measured and discarded — its length is what separates a
// key from an empty field, and its bytes are the secret.
func holdsECPrivateKey(der []byte) bool {
	// The curve and the public half may follow, and are not read: whether this
	// is a key is settled by the two fields that are always there.
	var key struct {
		Version    int
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &key); err != nil {
		return false
	}
	return key.Version == 1 && len(key.PrivateKey) > 0
}

// pkcs8PBES2 is the current password-based scheme, which states its derivation
// and its cipher as two structures of their own rather than as a salt and a
// count.
var pkcs8PBES2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}

// pkcs8EncryptionAlgorithms are the identifiers the encrypted container states
// for how it was protected. The identifier is read to confirm the container is
// one this build can account for, never to decrypt: a container naming a scheme
// nothing here knows is a shape that cannot be confirmed, which is not the same
// as a file holding no key.
var pkcs8EncryptionAlgorithms = []asn1.ObjectIdentifier{
	pkcs8PBES2,
	{1, 2, 840, 113549, 1, 5, 3},     // the two single-cipher schemes before it
	{1, 2, 840, 113549, 1, 5, 10},    //
	{1, 2, 840, 113549, 1, 12, 1, 3}, // the personal-exchange variants
	{1, 2, 840, 113549, 1, 12, 1, 6}, //
}

// pkcs8Derivations are the functions turning a passphrase into a key. The
// current scheme's own identifier says only that a passphrase was involved, and
// this is where it states what it derived the key with, so it is held to the
// same rule as the scheme itself: the two named here are the whole of what these
// containers are written with, and a third would be news. The cipher run with
// that key is not held to a list — which ciphers a writer offers grows with
// every release, and refusing a container over a name would take a key that is
// protected and report it as no key at all.
var pkcs8Derivations = []asn1.ObjectIdentifier{
	{1, 2, 840, 113549, 1, 5, 12},    // the iterated hash
	{1, 3, 6, 1, 4, 1, 11591, 4, 11}, // the memory-hard function
}

// parsesEncryptedPKCS8 validates the encrypted container's structure without
// decrypting it: a scheme this build knows, the parameters that scheme takes, and
// a non-empty ciphertext. The ciphertext is never touched beyond its length.
func parsesEncryptedPKCS8(der []byte) bool {
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		Data      []byte
	}
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 || len(info.Data) == 0 {
		return false
	}
	if !slices.ContainsFunc(pkcs8EncryptionAlgorithms, info.Algorithm.Algorithm.Equal) {
		return false
	}
	return validPKCS8EncryptionParameters(info.Algorithm)
}

// validPKCS8EncryptionParameters reads the parameters against the shape the
// named scheme defines for them. An identifier standing over parameters of some
// other shape describes nothing that could have produced the ciphertext behind
// it, which is the difference between a protected key and a container that only
// claims to be one.
func validPKCS8EncryptionParameters(algorithm pkix.AlgorithmIdentifier) bool {
	params := algorithm.Parameters.FullBytes
	if len(params) == 0 {
		return false
	}
	if algorithm.Algorithm.Equal(pkcs8PBES2) {
		var scheme struct {
			Derivation pkix.AlgorithmIdentifier
			Cipher     pkix.AlgorithmIdentifier
		}
		if rest, err := asn1.Unmarshal(params, &scheme); err != nil || len(rest) != 0 {
			return false
		}
		// The cipher states the nonce it ran from. Which shape that takes is the
		// cipher's own business and is not read here, but a cipher standing over
		// no parameters at all could not have produced the ciphertext behind it.
		if len(scheme.Cipher.Parameters.FullBytes) == 0 {
			return false
		}
		if !slices.ContainsFunc(pkcs8Derivations, scheme.Derivation.Algorithm.Equal) {
			return false
		}
		return validPKCS8Derivation(scheme.Derivation)
	}
	return validPKCS8Derivation(algorithm)
}

// validPKCS8Derivation reads the parameters of the function that turned the
// passphrase into a key. Every derivation these containers name — the iterated
// hash and the memory-hard one alike — opens with the salt it started from and
// the work factor it applied, and whatever else follows is the derivation's own.
// Both are read for their presence: a derivation with nothing to start from, or
// no work to do, derives nothing, and a container naming one describes a key
// that no passphrase could ever open.
func validPKCS8Derivation(algorithm pkix.AlgorithmIdentifier) bool {
	var derivation struct {
		Salt []byte
		Work int
	}
	rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &derivation)
	return err == nil && len(rest) == 0 && len(derivation.Salt) > 0 && derivation.Work > 0
}

// parsesRawDERPrivateKey reports whether unarmoured bytes are a private key in
// any of the encodings the standard library parses.
func parsesRawDERPrivateKey(der []byte) bool {
	if parsesPKCS8PrivateKey(der) {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return true
	}
	_, err := x509.ParseECPrivateKey(der)
	return err == nil
}

// parsesRawDERPublicKeyOrCertificate keeps unarmoured published material a clean
// result rather than an uninterpreted one.
func parsesRawDERPublicKeyOrCertificate(der []byte) bool {
	if _, err := x509.ParsePKIXPublicKey(der); err == nil {
		return true
	}
	_, err := x509.ParseCertificate(der)
	return err == nil
}

// sshPublicKeyPrefixes begin the algorithm name of every published SSH key and
// certificate shape.
var sshPublicKeyPrefixes = []string{"ssh-", "ecdsa-", "sk-"}

// isSSHPublicKeyText reports whether a file is the single-line SSH public-key
// text format. Recognising it positively is what keeps a public half, a
// certificate or a host-key list from being reported as material this build could
// not interpret — the same outcome a genuinely damaged private key gets.
func isSSHPublicKeyText(data []byte) bool {
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// The algorithm is the first field in a key file and the second in a
		// host-key list, which prefixes each line with the host it belongs to.
		if !sshPublicKeyAt(fields, 0) && !sshPublicKeyAt(fields, 1) {
			return false
		}
		seen = true
	}
	return seen
}

// sshPublicKeyAt reports whether an algorithm name and its encoded blob sit at
// the given position, the blob being confirmed by the algorithm it repeats
// inside itself rather than by being base64 at all.
func sshPublicKeyAt(fields []string, i int) bool {
	if i+1 >= len(fields) {
		return false
	}
	name := fields[i]
	if !slicesContainsPrefix(sshPublicKeyPrefixes, name) {
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[i+1])
	if err != nil {
		return false
	}
	algorithm, _, ok := readSSHString(blob)
	return ok && string(algorithm) == name
}

func slicesContainsPrefix(prefixes []string, value string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(value, p) {
			return true
		}
	}
	return false
}
