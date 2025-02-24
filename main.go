package main

import (
	"fmt"
	"flag"
	"log"
	"os"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var algorithms map[string]otp.Algorithm = map[string]otp.Algorithm {
	"sha1": otp.AlgorithmSHA1,
	"sha256": otp.AlgorithmSHA256,
	"sha512": otp.AlgorithmSHA512,
	"md5": otp.AlgorithmMD5,
}

func main() {
	secr := flag.String("s", "", "user's secret for validation")
	toke := flag.String("t", "", "user's token to validate")
	size := flag.Uint("n", 20, "size of secret in bytes")
	expt := flag.Uint("v", 30, "validity period in seconds")
	halg := flag.String("h", "sha1", "algorithm (sha1, sha256, sha512, md5)")
	user := flag.String("u", "user@example.com", "user email or id")
	issu := flag.String("i", "Example.com", "issuer name")
	flag.Parse()

	algo, ok := algorithms[*halg]
	if !ok {
		log.Fatal("illegal algorithm: ", *halg)
	}

	if *size != 20 {
		log.Println("warning: secret size other than 20 may not work")
	}

	// Verification -- if secret is not empty, token must also be provided
	if *secr != "" {
		if *toke == "" {
			log.Fatal("missing token")
		}
		vopt := totp.ValidateOpts{Period: *expt, Skew: 1, Digits: otp.DigitsSix, Algorithm: algo}
		if validateTOTP(*secr, *toke, vopt) {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// Generation -- generate a new TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      *issu,
		AccountName: *user,
		SecretSize:  *size,
		Period:      *expt,
		Algorithm:   algo,
		Digits: otp.DigitsSix,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Send the secret to STDERR so that a shell script
	// can generate the QR and store the secret without having
	// to parse things
	fmt.Fprintln(os.Stderr, "Secret:", key.Secret())
	fmt.Print(key)
}

// prompt for TOTP and validate it
func validateTOTP(secret, tok string, vopt totp.ValidateOpts) bool {
	ok, err := totp.ValidateCustom(tok, secret, time.Now().UTC(), vopt)
	if err != nil {
		log.Fatal(err)
	}
	if ok {
		fmt.Println("👍")
	} else {
		fmt.Println("👎")
	}
	return ok
}

