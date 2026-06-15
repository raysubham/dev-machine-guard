package state

import "encoding/base64"

// ScanRecordFromBase64 builds a ScanRecord from a PM scan result whose raw
// stdout is base64-encoded (NodeScanResult.RawStdoutBase64). When the base64
// decode fails the raw string is hashed instead so the record is never empty.
func ScanRecordFromBase64(path, pm, pmVersion, rawStdoutBase64 string, exitCode int) ScanRecord {
	decoded, err := base64.StdEncoding.DecodeString(rawStdoutBase64)
	if err != nil {
		decoded = []byte(rawStdoutBase64)
	}
	hash, _ := CanonicalHashJSON(decoded)
	return ScanRecord{
		Path:           path,
		Hash:           hash,
		PackageManager: pm,
		PMVersion:      pmVersion,
		ExitCode:       exitCode,
	}
}
