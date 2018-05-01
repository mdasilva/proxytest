# Overview

A simple cross platform utility to test HTTP GET requests through a web proxy.

Features

- Multiple OS & architectures supported
- HTTP_PROXY environment variable support
- Concurrent HTTP checks
- Short timeouts
- Redirect support
- Stdin support
- JSON output


# Usage

Explicitly provided web proxy URL

    $ proxytest --proxy-url http://mywebproxy:3128 check http://www.google.ca
    {"request":"http://www.google.ca","status":"200 OK"}


Implicitly provided web proxy URL (HTTP_PROXY env variable)

    $ HTTP_PROXY=http://mywebproxy:3128
    $ proxytest check http://google.ca
    {"request":"http://www.google.ca","status":"200 OK"}


URL list provided as arguments

    $ proxytest check http://www.google.ca http://www.bing.com http://www.youtube.com
    {"request":"http://www.google.ca","status":"200 OK"}
    {"request":"http://www.youtube.com","status":"301 Moved Permanently","redirect":"https://www.youtube.com/"}
    {"request":"http://www.bing.com","status":"200 OK"}
    {"request":"https://www.youtube.com/","status":"200 OK"}


URL list provided from stdin

    $ cat > url_list.txt
    http://www.google.ca
    http://www.youtube.com
    ^C

    $ cat url_list.txt | proxytest check


Increase logging verbosity

    $ proxytest --log-level debug check http://www.google.ca
    INFO[0000] http://localhost:3128 proxy connection successful 
    INFO[0000] URLs to check: 1                             
    DEBU[0000] Firing URL check                             
    DEBU[0000] Waiting for all URL checks to complete       
    INFO[0000] Request: http://www.google.ca, Status: 200 OK, Redirect:  
    {"request":"http://www.google.ca","status":"200 OK"}


Redirected logging 

    $ proxytest --log-level info check http://www.google.ca 2> info.log
    {"request":"http://www.google.ca","status":"200 OK"}

    $ cat info.log
    time="2018-05-01T18:34:10-04:00" level=info msg="http://localhost:3128 proxy connection successful"
    time="2018-05-01T18:34:10-04:00" level=info msg="URLs to check: 1"
    time="2018-05-01T18:34:10-04:00" level=info msg="Request: http://www.google.ca, Status: 200 OK, Redirect: "


Get version

    $ proxytest version
    version 0.1.0


# Building

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
