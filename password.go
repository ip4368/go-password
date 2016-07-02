package password

import (
    "regexp"
    "math/rand"
    "time"
    "encoding/base64"
    "crypto/sha256"
)

func checkPassword(s string) bool {
    pattern := "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{8,20}$"
    matched, _ := regexp.MatchString(pattern, s)
    return matched
}

const letterBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const (
    letterIdxBits = 6                    // 6 bits to represent a letter index
    letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
    letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)
var src = rand.NewSource(time.Now().UnixNano())
func makeSalt(n int) string {
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

type passAndSalt struct {
    pass string
    salt string
}
func autoAddSalt(s string) passAndSalt {
    minLen := 8
    passB := []byte(s)
    salted := make([]byte, len(passB)+minLen)
    salt := makeSalt(minLen)
    for i := 0; i<minLen; i++ {
        salted[2*i] = passB[i]
        salted[2*i+1] = salt[i]
    }
    for i := minLen; i<len(passB)-minLen; i++ {
        salted[2*minLen+i] = passB[minLen+i]
    }
    return passAndSalt{string(salted), salt}
}

type hashedAndSalt struct {
    hash string
    salt string
}
func saltedHashed(s string) hashedAndSalt {
    salted := autoAddSalt(s)
    h := sha256.New()
    hash := string(base64.StdEncoding.EncodeToString(h.Sum([]byte(salted.pass))))
    return hashedAndSalt{hash, salted.salt}
}
