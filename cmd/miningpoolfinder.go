package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	output string       = "pools.json"
	client *http.Client = &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			DisableCompression:  true,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			MaxConnsPerHost:     100,
			MaxIdleConnsPerHost: 100,
		},
		Timeout: time.Second * 10,
	}
	source = map[string][]string{
		"txt": {
			"https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/crypto_mining.txt",
		},
		"sigma": {
			"https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml",
			"https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/network_connection/net_connection_win_crypto_mining.yml",
			"https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/network/zeek/zeek_dns_mining_pools.yml",
		},
	}
)

func main() {
	fmt.Println("miningpoolfinder")

	finder := NewFinder()
	if err := finder.Run(); err != nil {
		log.Fatal(err)
	}
	total, err := finder.OutputJSON(output)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("mining pool address total '%d' \n", total)
}

type Finder struct {
	values map[string]struct{}
}

func NewFinder() *Finder {
	return &Finder{
		values: make(map[string]struct{}),
	}
}

func (f *Finder) Run() error {
	for k, v := range source {
		for _, vv := range v {
			fmt.Printf("request '%s'...\n", vv)
			data, err := f.request(vv)
			if err != nil {
				fmt.Printf("request '%s' error: %s", vv, err.Error())
				continue
			}
			if k == "txt" {
				err = f.findFromTxt(data)
			} else if k == "sigma" {
				err = f.findFromSigma(data)
			}
			if err != nil {
				fmt.Printf("find '%s' type '%s' error: %s", vv, k, err.Error())
			}
		}
	}
	return nil
}

func (f *Finder) OutputJSON(filename string) (int, error) {
	total := len(f.values)
	if total <= 0 {
		return 0, nil
	}

	pools := make([]string, 0, total)
	for addr := range f.values {
		pools = append(pools, addr)
	}

	data, err := json.Marshal(pools)
	if err != nil {
		return 0, err
	}
	of, err := os.Create(filename)
	if err != nil {
		return 0, err
	}
	defer of.Close()
	_, err = of.Write(data)

	return total, err
}

func (f *Finder) request(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func (f *Finder) findFromTxt(content []byte) error {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		f.values[line] = struct{}{}
	}
	return nil
}

type SigmaHQRule struct {
	Detection struct {
		Selection struct {
			DestinationHostname []string `yaml:"DestinationHostname"`
			QueryContains       []string `yaml:"query|contains"`
			QueryEndswith       []string `yaml:"query|endswith"`
		} `yaml:"selection"`
	} `yaml:"detection"`
}

func (f *Finder) findFromSigma(data []byte) error {
	v := SigmaHQRule{}
	err := yaml.Unmarshal([]byte(data), &v)
	if err != nil {
		return err
	}
	for _, d := range v.Detection.Selection.DestinationHostname {
		f.values[d] = struct{}{}
	}
	for _, d := range v.Detection.Selection.QueryContains {
		f.values[d] = struct{}{}
	}
	for _, d := range v.Detection.Selection.QueryEndswith {
		f.values[d] = struct{}{}
	}
	return nil
}
