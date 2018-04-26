// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// create wait group to track http check progress
var wg sync.WaitGroup

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check URL",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			log.Fatalln("Need a least one URL to check")
		}

		// test web proxy connectivity
		proxy, err := checkProxy(viper.GetString("proxy-url"))
		if err != nil {
			log.Fatalln(err)
		}

		// scrub invalid urls
		targetURLs := parseURLs(args)

		// provide a timeout for http client requests
		d, _ := time.ParseDuration(viper.GetString("timeout"))
		timeout := time.Second * d

		// perform url accessiblity checks
		processURLs(proxy, targetURLs, timeout)
	},
}

func parseURLs(args []string) []url.URL {
	c := make([]url.URL, 0)
	for i := 0; i < len(args); i++ {
		// validate uri
		if _, err := url.ParseRequestURI(args[i]); err != nil {
			log.Warnf("Invalid URI: %s", args[i])
		} else {
			// parse raw URL string
			if u, err := url.Parse(args[i]); err != nil {
				log.Warnf("Could not parse URI: %s", args[i])
			} else {
				c = append(c, *u)
			}
		}
	}
	return c
}

func checkProxy(proxyURL string) (*url.URL, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		log.Fatalln(err)
	}
	conn, err := net.Dial("tcp", u.Hostname()+":"+u.Port())
	if err != nil {
		return &url.URL{}, err
	}
	defer conn.Close()
	log.Infoln("Proxy connection successful")
	return u, nil
}

func processURLs(proxy *url.URL, targetURLs []url.URL, timeout time.Duration) {
	log.Infof("URLs to check: %d", len(targetURLs))

	// create http client
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxy),
		},
	}

	// create channel to hold results
	results := make(chan *http.Response)
	done := make(chan bool)

	// establish waitgroup size
	wg.Add(len(targetURLs))

	// begin http checks
	for _, u := range targetURLs {
		log.Debugln("Firing URL check")
		go checkURL(client, u, 5*time.Second, results)
	}

	// signal completion
	go func() {
		defer close(done)
		log.Debugln("Waiting for all URL checks to complete")
		wg.Wait()
	}()

resultsloop:
	for {
		select {
		case res := <-results:
			log.Infoln("url: ", res.Request.URL.String())
			log.Infoln("status: ", res.Status)
			log.Infoln("location: ", res.Header.Get("Location"))
		case <-done:
			break resultsloop
		}
	}
}

func checkURL(client *http.Client, u url.URL, t time.Duration, ch chan *http.Response) {
	defer wg.Done()

	// build a http request
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		log.Fatalln(err)
	}

	// set a context
	ctx, cancel := context.WithTimeout(req.Context(), t)
	defer cancel()

	// prepare and execute getk:w
	req = req.WithContext(ctx)
	res, err := client.Do(req)
	if err != nil {
		log.Warnln(err)
		return
	}

	// add results to channel
	ch <- res

	// follow redirects recursively
	if location := res.Header.Get("Location"); location != "" {
		log.Debugln("Following redirect")
		wg.Add(1)
		go checkURL(client, u, t, ch)
	}
}

func init() {
	log.SetOutput(os.Stderr)
	rootCmd.AddCommand(checkCmd)
}
