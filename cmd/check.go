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
	"encoding/json"
	"fmt"
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
	Short: "Perform a GET request for a given URL through a proxy",
	Long: `Perform a GET request to determine connectivity through a web proxy.
URLs must be properly formatted with preceeding protocol.
Provide multiple URLs as additional arguments.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Set desired logging level
		level, err := log.ParseLevel(viper.GetString("log-level"))
		if err != nil {
			log.Panicln(err)
		}
		log.SetLevel(level)
		if len(args) == 0 {
			log.Fatalln("Need a least one URL to check")
		}

		// Test TCP connectivity to web proxy
		proxy, err := checkProxy(viper.GetString("proxy-url"))
		if err != nil {
			log.Fatalln(err)
		}

		// Scrub invalid URLs
		validURLs := parseURLs(args)
		log.Infof("URLs to check: %d", len(validURLs))

		// Create HTTP client
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxy),
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// Create channel to receive check results
		results := make(chan *http.Response)
		done := make(chan bool)

		// Establish waitgroup size
		wg.Add(len(validURLs))

		// Begin HTTP checks
		for _, u := range validURLs {
			log.Debugln("Firing URL check")
			c := HttpCheckEntry{
				HttpClient: client,
				URL:        u,
				WaitGroup:  &wg,
				Timeout:    3 * time.Second,
				Results:    results,
			}
			go c.Check()
		}

		// Watch for goruntine completion
		go func() {
			defer close(done)
			log.Debugln("Waiting for all URL checks to complete")
			wg.Wait()
		}()

	resultloop:
		for {
			select {
			case res := <-results:
				log.Infof("Request: %s, Status: %s, Redirect: %s",
					res.Request.URL.String(),
					res.Status,
					res.Header.Get("Location"))
				j, err := json.Marshal(HttpCheckResults{
					Request:  res.Request.URL.String(),
					Status:   res.Status,
					Redirect: res.Header.Get("Location"),
				})
				if err != nil {
					log.Fatalln(err)
				}
				// Output JSON to stdout
				fmt.Println(string(j))
			case <-done:
				break resultloop
			}
		}

	},
}

// Display format struct
type HttpCheckResults struct {
	Request  string `json:"request"`
	Status   string `json:"status"`
	Redirect string `json:"redirect,omitempty"`
}

type HttpCheckEntry struct {
	HttpClient *http.Client
	URL        url.URL
	WaitGroup  *sync.WaitGroup
	Timeout    time.Duration
	Results    chan *http.Response
}

func (c *HttpCheckEntry) Check() {
	defer c.WaitGroup.Done()

	// build a http request
	req, err := http.NewRequest("GET", c.URL.String(), nil)
	if err != nil {
		log.Fatalln(err)
	}

	// set a context
	ctx, cancel := context.WithTimeout(req.Context(), c.Timeout)
	defer cancel()

	// prepare and execute getk:w
	req = req.WithContext(ctx)
	res, err := c.HttpClient.Do(req)
	if err != nil {
		log.Warnln(err)
		return
	}

	// add results to channel
	c.Results <- res

	// follow redirects recursively
	if location := res.Header.Get("Location"); location != "" {
		log.Debugf("Following redirect %s", location)
		wg.Add(1)
		// stinky
		r, err := url.Parse(location)
		if err != nil {
			log.Warnln(err)
		}
		cc := HttpCheckEntry{
			HttpClient: c.HttpClient,
			URL:        *r,
			WaitGroup:  c.WaitGroup,
			Timeout:    c.Timeout,
			Results:    c.Results,
		}
		go cc.Check()
	}
}

func parseURLs(args []string) []url.URL {
	c := make([]url.URL, 0)
	for _, a := range args {
		if _, err := url.ParseRequestURI(a); err != nil {
			log.Warnf("Invalid URI: %s", a)
		} else {
			if u, err := url.Parse(a); err != nil {
				log.Warnf("Could not parse URI: %s", a)
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
	conn, err := net.DialTimeout("tcp", u.Hostname()+":"+u.Port(), 3*time.Second)
	if err != nil {
		return &url.URL{}, err
	}
	defer conn.Close()
	log.Infof("%s proxy connection successful", proxyURL)
	return u, nil
}

func init() {
	log.SetOutput(os.Stderr)
	rootCmd.AddCommand(checkCmd)
}
