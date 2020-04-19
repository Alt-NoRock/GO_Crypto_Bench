package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"
)

func main() {
	loop := 10
	count := 10000
	fn := "result_ECDSA.csv"
	file, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal("Error:", err)
	}
	defer file.Close()
	err = file.Truncate(0) // ファイルを空っぽにする(実行2回目以降用)
	if err != nil {
		log.Fatal("Error:", err)
	}
	writer := csv.NewWriter(file)

	resultSign, resultVrfy, err := ECDSASignVerify(count, loop)
	if err != nil {
		log.Fatal("error")
	}
	writer.Write(resultSign)
	writer.Write(resultVrfy)
	writer.Flush()
}

// ECDSASignVerify method is Sign & Verification method
func ECDSASignVerify(count int, loop int) ([]string, []string, error) {
	curve := elliptic.P256()
	privkey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	message := "Hello World"
	var r, s *big.Int
	resultSign := []string{"GO_ECDSA", "P256", "Sign"}
	var SignTime []float64

	for l := 0; l < loop; l++ {
		start := time.Now()
		for i := 0; i < count; i++ {
			r, s, err = ECDSAGenerateSign(privkey, message)
			if err != nil {
				log.Fatal(err)
			}
		}
		end := time.Now()
		SignTime = append(SignTime, (end.Sub(start)).Seconds())
	}
	avg := Average(SignTime)
	strAvg := strconv.FormatFloat(avg, 'f', 4, 64)
	resultSign = append(resultSign, strAvg)
	strTimeList := ConvStr(SignTime)
	resultSign = append(resultSign, strTimeList...)

	pubkey := privkey.Public().(*ecdsa.PublicKey)
	resultVrfy := []string{"GO_ECDSA", "P256", "Verify"}
	var VrfyTime []float64

	for l := 0; l < loop; l++ {
		start := time.Now()
		for i := 0; i < count; i++ {
			ret := ECDSAVerifySign(pubkey, message, r, s)
			if ret != true {
				fmt.Println("verification FAILED")
			}
		}
		end := time.Now()
		VrfyTime = append(VrfyTime, (end.Sub(start)).Seconds())
	}
	avg = Average(VrfyTime)
	strAvg = strconv.FormatFloat(avg, 'f', 4, 64)
	resultVrfy = append(resultVrfy, strAvg)
	strTimeList = ConvStr(VrfyTime)
	resultVrfy = append(resultVrfy, strTimeList...)
	// fmt.Println("verification SUCCESS")
	return resultSign, resultVrfy, err
}

// Average calc Average in Float Data List
func Average(data []float64) float64 {
	var sum float64
	sum = 0
	for i := 0; i < len(data); i++ {
		sum += data[i]
	}
	ave := sum / float64(len(data))
	return ave
}

// ConvStr return float64_list -> String_list
func ConvStr(data []float64) []string {
	var StrDat []string
	for i := 0; i < len(data); i++ {
		StrDat = append(StrDat, strconv.FormatFloat(data[i], 'f', 4, 64))
	}
	return StrDat
}

// ECDSAGenerateSign make signature with argument(ECDSA pubkey & message & signature)
func ECDSAGenerateSign(privkey *ecdsa.PrivateKey, message string) (*big.Int, *big.Int, error) {
	hash := sha256.New()
	hash.Write([]byte(message))
	hashVal := hash.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, privkey, hashVal)
	return r, s, err
}

// ECDSAVerifySign make signature with argument(ECDSA pubkey & message & signature)
func ECDSAVerifySign(pubkey *ecdsa.PublicKey, message string, r *big.Int, s *big.Int) bool {
	hash := sha256.New()
	hash.Write([]byte(message))
	hashVal := hash.Sum(nil)
	ret := ecdsa.Verify(pubkey, hashVal, r, s)
	if ret == false {
		log.Fatal("verification error")
		return false
	}
	return true
}
