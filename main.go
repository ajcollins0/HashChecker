package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// VERSION string to output.
const VERSION = "1.0"

type params struct {
	ApiKey string
	IFile  string
	OFile  string
}

// respOutput descibes the output from Virus Total.
type respOutput struct {
	Scans        map[string]repEntry `json:"Scans"`
	ScanID       string              `json:"scan_id"`
	Sha1         string              `json:"sha1"`
	Resource     string              `json:"resource"`
	ResponseCode int                 `json:"response_code"`
	ScanDate     string              `json:"scan_date"`
	Permalink    string              `json:"permalink"`
	VerboseMsg   string              `json:"verbose_msg"`
	Total        int                 `json:"total"`
	Positives    int                 `json:"positives"`
	Sha256       string              `json:"sha256"`
	Md5          string              `json:"md5"`
}

// repEntry describes  each reputation provider from Virus Total.
type repEntry struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version"`
	Result   string `json:"result"`
	Update   string `json:"update"`
}

func getInfoFromUser(outputMsg string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(outputMsg)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func parseArgs() *params {
	Param := new(params)

	a := flag.String("a", "", "API key to use for virus total")
	i := flag.String("i", "./input.txt", "File of list of hashes to check")
	o := flag.String("o", "./output.csv", "File of list of hashes to check")
	v := flag.Bool("v", false, "Prints the version number and exit")

	flag.Parse()
	if *v {
		fmt.Println(VERSION)
		os.Exit(0)
	}
	if *a == "" {
		Param.ApiKey = getInfoFromUser("Input Virus Total API Key")
	} else {
		Param.ApiKey = *a
	}

	Param.IFile = *i
	Param.OFile = *o

	return Param
}

func chkEr(e error) {
	if e != nil {
		panic(e)
	}
}

func readFile(f string) []string {
	file, err := os.Open(f)
	chkEr(err)
	scanner := bufio.NewScanner(file)
	result := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}
	return result
}

func readFileTemp(f string) string {
	dat, err := ioutil.ReadFile(f)
	chkEr(err)
	return string(dat)
}

// func makeVTRequest(k string, h string) {
func makeVTRequest(k string, h string) []byte {
	SLEEPTIME := 30

	base := "https://www.virustotal.com/vtapi/v2/file/report"

	req, err := http.NewRequest("GET", base, nil)
	chkEr(err)

	p := req.URL.Query()
	p.Add("apikey", k)
	p.Add("resource", h)

	req.URL.RawQuery = p.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	chkEr(err)
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		log.Println("Hit Virus Total API Limit. Sleeping for 30 seconds")
		time.Sleep(time.Duration(SLEEPTIME) * time.Second)
		// recurse to get the data after sleeping
		return makeVTRequest(k, h)
	}

	body, err := ioutil.ReadAll(resp.Body)
	chkEr(err)
	return body
}

func unMarsh(b []byte) respOutput {
	f := respOutput{}
	chkEr(json.Unmarshal(b, &f))
	return f
}

func main() {
	params := parseArgs()
	hashes := readFile(params.IFile)

	// hate putting this in main, but need to stream output to file
	file, err := os.Create(params.OFile)
	chkEr(err)
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Output headers to file
	t := []string{"Hash", "Bad Reputation Count", "Total Reputations Reported"}
	err = writer.Write(t)
	chkEr(err)

	for _, h := range hashes {
		b := makeVTRequest(params.ApiKey, h)
		d := unMarsh(b)

		t := []string{}
		// check if VT didn't have any data for this hash
		if d.ResponseCode == 0 {
			log.Println("Unable to find data for hash:", h)
			t = []string{h, "Hash Not Found", "Hash Not Found"}
		} else {
			t = []string{h, strconv.Itoa(d.Positives), strconv.Itoa(d.Total)}
		}
		err := writer.Write(t)
		chkEr(err)
	}
}
