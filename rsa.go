package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/csv"
	"log"
	"os"
	"strconv"
	"time"
)

func main() {
	loop := 10
	count := 10000
	fn := "result_RSA.csv"

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

	resultSign, resultVrfy, err := RSASignVerify(count, loop, 2048)
	if err != nil {
		log.Fatal(err)
	}
	writer.Write(resultSign)
	writer.Write(resultVrfy)

	resultSign, resultVrfy, err = RSASignVerify(count, loop, 3072)
	if err != nil {
		log.Fatal(err)
	}
	writer.Write(resultSign)
	writer.Write(resultVrfy)
	writer.Flush()

	// fmt.Printf("%d\n", i)
}

// RSASignVerify method is Sign & Verification method
func RSASignVerify(count int, loop int, size int) ([]string, []string, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		log.Fatal(err)
	}

	// 秘密鍵の読込み、ここには上記で発行した秘密鍵のファイルパスを指定する
	// sign
	message := "Hello World"
	var signature []byte
	resultSign := []string{"GO_RSA", strconv.Itoa(size), "Sign"}
	var SignTime []float64
	for l := 0; l < loop; l++ {
		start := time.Now()
		for i := 0; i < count; i++ {
			signature, err = RSAGenerateSign(privkey, message)
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

	rsaPubKey := privkey.Public().(*rsa.PublicKey)
	resultVrfy := []string{"GO_RSA", strconv.Itoa(size), "Verify"}
	var VrfyTime []float64
	for l := 0; l < loop; l++ {
		start := time.Now()
		for i := 0; i < 10000; i++ {
			err = RSAVerifySign(rsaPubKey, message, signature)
			//verify
			if err != nil {
				log.Fatal(err)
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

// RSAGenerateSign make signature with argument(RSA pubkey & message & signature)
func RSAGenerateSign(privkey *rsa.PrivateKey, message string) ([]byte, error) {
	hash := sha256.New()
	hash.Write([]byte(message))
	hashVal := hash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA256, hashVal)
	return signature, err
}

// RSAVerifySign make signature with argument(RSA pubkey & message & signature)
func RSAVerifySign(pubkey *rsa.PublicKey, message string, signature []byte) error {
	hash := sha256.New()
	hash.Write([]byte(message))
	hashVal := hash.Sum(nil)
	err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA256, hashVal, signature)
	return err
}
