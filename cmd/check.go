// Copyright © 2018 Michael Da Silva madasilva@gmail.com
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
	"bufio"
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

// Create a wait group to track asynchronous HTTP checks
var wg sync.WaitGroup

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check URL",
	Short: "Perform a GET request for a given URL through a proxy",
	Long: `Perform a GET request to determine connectivity through a web proxy.
URLs must be properly formatted with preceeding protocol.
Provide multiple URLs as additional arguments.`,
	Run: cmdMain,
}

// HttpCheckResultsDisplay is the format for result output
type HttpCheckResultsDisplay struct {
	HttpRequest    string `json:"http_request"`
	Status         string `json:"status"`
	Message        string `json:"message,omitempty"`
	HttpStatusCode int    `json:"http_status_code,omitempty"`
	HttpStatus     string `json:"http_status,omitempty"`
	HttpRedirect   string `json:"http_redirect,omitempty"`
}

// HttpCheckError is an error
type HttpCheckError struct {
	URL     url.URL
	Message string
}

// Error is the standard method to satisfy the Error interface
func (e *HttpCheckError) Error() string {
	return fmt.Sprintf("%s: %s", e.URL.String(), e.Message)
}

// HttpCheckEntry is a HTTP check item
type HttpCheckEntry struct {
	HttpClient *http.Client
	URL        url.URL
	WaitGroup  *sync.WaitGroup
	Timeout    time.Duration
	Results    chan *http.Response
	Errors     chan error
}

// Check performs a HTTP GET request through the HttpClient
// The HttpClient should be configure using a transport with a proxy server defined
func (c *HttpCheckEntry) Check() {
	defer c.WaitGroup.Done()

	// Build the  HTTP request
	req, err := http.NewRequest("GET", c.URL.String(), nil)
	if err != nil {
		log.Fatalln(err)
	}

	// Set a context timeout
	ctx, cancel := context.WithTimeout(req.Context(), c.Timeout)
	defer cancel()

	// Prepare and execute HTTP request
	req = req.WithContext(ctx)
	res, err := c.HttpClient.Do(req)
	if err != nil {
		c.Errors <- &HttpCheckError{URL: c.URL, Message: err.Error()}
		return
	}

	// Add HTTP GET results to channel
	c.Results <- res

	// Follow HTTP redirects recursively
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
			Errors:     c.Errors,
		}
		go cc.Check()
	}
}

// getStdinURLs reads stdin and returns a slice of strings
func getStdinURLs() ([]string, error) {
	urls := make([]string, 0)
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		urls = append(urls, cleanSuffix(line))
	}
	log.Infof("Found %d URLS from Stdin", len(urls))
	return urls, nil
}

// cmdMain is the primary procedure for the check command execution
func cmdMain(cmd *cobra.Command, args []string) {
	// Set desired logging level
	level, err := log.ParseLevel(viper.GetString("log-level"))
	if err != nil {
		log.Panicln(err)
	}
	log.SetLevel(level)

	// Gather URLs to check from argument list or stdin
	var rawURLs []string = args
	if len(rawURLs) == 0 {
		log.Debugln("Found not URL arguments")
		rawURLs, _ = getStdinURLs()
		if err != nil {
			log.Fatalln("Need a least one URL to check")
		}
	}

	// Scrub invalid URLs
	validURLs := parseURLs(rawURLs)
	log.Infof("URLs to check: %d", len(validURLs))

	// Test TCP connectivity to web proxy
	proxy, err := checkProxy(viper.GetString("proxy-url"))
	if err != nil {
		log.Fatalln(err)
	}

	// Create a shared HTTP client
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
	errors := make(chan error)
	done := make(chan bool)

	// Establish waitgroup size
	wg.Add(len(validURLs))

	// Initiate asynchronous HTTP checks
	for _, u := range validURLs {
		log.Debugf("Firing URL check for %s", u.String())
		c := HttpCheckEntry{
			HttpClient: client,
			URL:        u,
			WaitGroup:  &wg,
			Timeout:    3 * time.Second,
			Results:    results,
			Errors:     errors,
		}
		go c.Check()
	}

	// Watch for asynchronous HTTP check completion
	go func() {
		defer close(done)
		log.Debugln("Waiting for all URL checks to complete")
		wg.Wait()
	}()

resultloop: // Handle asynchronous HTTP check results as they are returned
	for {
		select {

		case r := <-results:
			log.Infof("Request: %s, Status Code: %d, Status: %s, Redirect: %s",
				r.Request.URL.String(),
				r.StatusCode,
				r.Status,
				r.Header.Get("Location"))

			j, err := json.Marshal(HttpCheckResultsDisplay{
				HttpRequest:    r.Request.URL.String(),
				Status:         "Successful",
				HttpStatusCode: r.StatusCode,
				HttpStatus:     r.Status,
				HttpRedirect:   r.Header.Get("Location"),
			})
			if err != nil {
				log.Fatalln(err)
			}
			// Output JSON to stdout
			fmt.Println(string(j))

		case r := <-errors:
			if r, ok := r.(*HttpCheckError); ok {
				log.Warnf("Request: %s, Error: %s",
					r.URL.String(),
					r.Message)
				j, err := json.Marshal(HttpCheckResultsDisplay{
					HttpRequest: r.URL.String(),
					Status:      "Failed",
					Message:     r.Message,
				})
				if err != nil {
					log.Fatalln(err)
				}
				fmt.Println(string(j))
			}

		case <-done:
			break resultloop
		}
	}

}

// parseURLs converts a slice of URL strings into a slice of url.URL objects
// Invalid URLs are dropped. A slice of url.URLs are retruned.
func parseURLs(args []string) []url.URL {
	c := make([]url.URL, 0)
	for _, a := range args {
		if _, err := url.ParseRequestURI(a); err != nil {
			log.Warnf("Invalid URI: %s", a)
			log.Warnln(err)
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

// checkProxy takes a URL string and tests for basic TCP connectivy
// It returns a pointer to a url.URL object and error
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
