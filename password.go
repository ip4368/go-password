package password

import (
    "math/rand"
    "time"
    "encoding/base64"
    "crypto/sha256"
    "strings"
    //"fmt"
)

func isDigit(ch rune) bool {
    return '0' <= ch && ch <= '9'
}
func isLower(ch rune) bool {
    return 'a' <= ch && ch <= 'z'
}
func isUpper(ch rune) bool {
    return 'A' <= ch && ch <= 'Z'
}
func checkAll(s string) bool {
    // length
    length := len(s)
    if (length < 8 && length > 20) { return false }

    // check contain at least 1 from each families
    containDigit := false
    containLower := false
    containUpper := false
    for _, ch := range s {
        containDigit = containDigit || isDigit(ch)
        containLower = containLower || isLower(ch)
        containUpper = containUpper || isUpper(ch)
        if containDigit && containLower && containUpper { return true }
    }
    return false
}

func ValidatePassword(s string) bool {
    return checkAll(s)
}

const letterBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const (
    letterIdxBits = 6                    // 6 bits to represent a letter index
    letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
    letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)
var src = rand.NewSource(time.Now().UnixNano())
func MakeSalt(n int) string {
    salt := make([]byte, n)
    // A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
    for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
        if remain == 0 {
            cache, remain = src.Int63(), letterIdxMax
        }
        if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
            salt[i] = letterBytes[idx]
            i--
        }
        cache >>= letterIdxBits
        remain--
    }

    return string(salt)
}

func AutoAddSalt(s string) (string, string, bool) {
    if !ValidatePassword(s) { return "", "", false }
    minLen := 8
    passB := []byte(s)
    salted := make([]byte, len(passB)+minLen)
    salt := MakeSalt(minLen)
    for i := 0; i<minLen; i++ {
        salted[2*i] = passB[i]
        salted[2*i+1] = salt[i]
    }
    for i := minLen; i<len(passB); i++ {
        salted[minLen+i] = passB[i]
    }
    return string(salted), salt, true
}

func HashAutoSalt(s string) (string, string, bool) {
    salted, salt, valid := AutoAddSalt(s)
    if !valid { return "", "", false }
    h := sha256.New()
    hash := string(base64.StdEncoding.EncodeToString(h.Sum([]byte(salted))))
    return hash, salt, true
}


func HashWithSalt(s string, salt string) (string, string, bool) {
    if !ValidatePassword(s) { return "", "", false }
    h := sha256.New()
    hash := string(base64.StdEncoding.EncodeToString(h.Sum([]byte(salt))))
    return hash, salt, true
}

func Compare(pass string, salt string, hash string) (bool, bool) {
    hashed, _, valid := HashWithSalt(pass, salt)
    return strings.Compare(hashed, hash) == 0, valid
}
