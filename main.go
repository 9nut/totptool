package main

import (
	"bufio"
	"fmt"
	"flag"
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
	secr := flag.String("s", "", "secret; user is prompted for code to validate")
	size := flag.Uint("n", 20, "size of secret in bytes")
	expt := flag.Uint("t", 30, "validity period in seconds")
	halg := flag.String("h", "sha1", "algorithm (sha1, sha256, sha512, md5)")
	user := flag.String("u", "user@example.com", "user email or id")
	issu := flag.String("i", "Example.com", "issuer name")
	flag.Parse()

	algo, ok := algorithms[*halg]
	if !ok {
		fmt.Println("illegal algorithm: ", *halg)
		os.Exit(1)
	}

	if *size != 20 {
		fmt.Println("warning: secret size other than 20 may not work")
	}

	if *secr != "" {
		vopt := totp.ValidateOpts{Period: *expt, Skew: 1, Digits: otp.DigitsSix, Algorithm: algo}
		validateTOTP(*secr, vopt)
		os.Exit(0)
	}

	// Generate a TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      *issu,
		AccountName: *user,
		SecretSize:  *size,
		Period:      *expt,
		Algorithm:   algo,
		Digits: otp.DigitsSix,
	})
	if err != nil {
		fmt.Println("Error generating TOTP key:", err)
		os.Exit(2)
	}

	// Display the key's secret and QR code for the user
	fmt.Fprintln(os.Stderr, "Secret:", key.Secret())
	fmt.Print(key)
}

// prompt for TOTP and validate it
func validateTOTP(secret string, vopt totp.ValidateOpts) {
	fmt.Print("Enter the OTP from your authenticator app: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	tok := scanner.Text()

	ok, err := totp.ValidateCustom(tok, secret, time.Now().UTC(), vopt)
	if err != nil {
		fmt.Println("Validation error: ", err)
		return
	}
	if ok {
		fmt.Println("👍")
	} else {
		fmt.Println("👎")
	}
}

