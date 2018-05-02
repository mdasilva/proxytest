# Overview

A simple cross platform utility to test HTTP GET requests through a web proxy.

Features

- Multiple OS & architectures supported
- HTTP_PROXY environment variable support
- Concurrent HTTP checks
- Redirect support
- Short timeouts
- Stdin support
- JSON output


# Usage

Explicitly provided web proxy URL

    $ proxytest --proxy-url http://mywebproxy:3128 check http://www.google.ca
    {"http_request":"http://www.google.ca","status":"Successful","http_status_code":200,"http_status":"200 OK"}



Implicitly provided web proxy URL (HTTP_PROXY env variable)

    $ HTTP_PROXY=http://mywebproxy:3128
    $ proxytest check http://google.ca
    {"http_request":"http://www.google.ca","status":"Successful","http_status_code":200,"http_status":"200 OK"}


URL list provided as arguments

    $ proxytest check http://www.google.ca http://www.bing.com http://www.youtube.com
    {"http_request":"http://www.youtube.com","status":"Successful","http_status_code":301,"http_status":"301 Moved Permanently","http_redirect":"https://www.youtube.com/"}
    {"http_request":"http://www.bing.com","status":"Successful","http_status_code":200,"http_status":"200 OK"}
    {"http_request":"http://www.google.ca","status":"Successful","http_status_code":200,"http_status":"200 OK"}
    {"http_request":"https://www.youtube.com/","status":"Successful","http_status_code":200,"http_status":"200 OK"}


URL list provided from stdin

    $ cat > url_list.txt
    http://www.google.ca
    http://www.youtube.com
    ^C

    $ cat url_list.txt | proxytest check
    {"http_request":"http://www.youtube.com","status":"Successful","http_status_code":301,"http_status":"301 Moved Permanently","http_redirect":"https://www.youtube.com/"}
    {"http_request":"http://www.google.ca","status":"Successful","http_status_code":200,"http_status":"200 OK"}
    {"http_request":"https://www.youtube.com/","status":"Successful","http_status_code":200,"http_status":"200 OK"}


Increase logging verbosity

    $ proxytest --log-level debug check http://www.google.ca
    INFO[0000] URLs to check: 1                             
    INFO[0000] http://localhost:3128 proxy connection successful 
    DEBU[0000] Firing URL check for http://www.google.ca    
    DEBU[0000] Waiting for all URL checks to complete       
    INFO[0000] Request: http://www.google.ca, Status Code: 200, Status: 200 OK, Redirect:  
    {"http_request":"http://www.google.ca","status":"Successful","http_status_code":200,"http_status":"200 OK"}


Redirected logging 

    $ proxytest --log-level info check http://www.google.ca 2> info.log
    {"http_request":"http://www.google.ca","status":"Successful","http_status_code":200,"http_status":"200 OK"}

    $ cat info.log
    time="2018-05-02T11:42:12-04:00" level=info msg="URLs to check: 1"
    time="2018-05-02T11:42:12-04:00" level=info msg="http://localhost:3128 proxy connection successful"
    time="2018-05-02T11:42:12-04:00" level=info msg="Request: http://www.google.ca, Status Code: 200, Status: 200 OK, Redirect: "
    

Get version

    $ proxytest version
    version 0.1.2


# Building

Building `proxytest` requires having Go installed and follows the typical Go build process.  You can download Go [here](https://golang.org/dl/).

Visit the [releases](https://github.com/mdasilva/proxytest/releases) section if you are looking for available pre-compiled binaries.

---

Checkout code into your GOPATH

    $ git clone git@github.com:mdasilva/proxytest.git $GOPATH/src/github.com/mdasilva/proxytest


Fetch dependencies

    $ cd $GOPATH/src/github.com/mdasilva/proxytest
    $ go get


Set OS and architecture for cross compilation (optional)

    $ export GOOS=windows
    $ export GOARCH=amd64


Build binary

    $ cd $GOPATH/src/github.com/mdasilva/proxytest
    $ go build 
