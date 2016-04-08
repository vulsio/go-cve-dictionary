# go-cve-dictionary

HTTP API server to get CVE information stored in SQLite3 on localhost.  
Current data sources are NVD(English) and JVN(Japanese).

## Install requirements

Vuls requires the following packages.

- sqlite
- git
- gcc
- go v1.6
    - https://golang.org/doc/install

```bash
$ ssh ec2-user@52.100.100.100  -i ~/.ssh/private.pem
$ sudo yum -y install sqlite git gcc
$ wget https://storage.googleapis.com/golang/go1.6.linux-amd64.tar.gz
$ sudo tar -C /usr/local -xzf go1.6.linux-amd64.tar.gz
$ mkdir $HOME/go
```
Put these lines into /etc/profile.d/goenv.sh

```bash
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

Set the OS environment variable to current shell
```bash
$ source /etc/profile.d/goenv.sh
```

## Deploy go-cve-dictionary

To install, use `go get`:

go get

```bash
$ sudo mkdir /var/log/vuls
$ sudo chown ec2-user /var/log/vuls
$ sudo chmod 700 /var/log/vuls
$ go get github.com/kotakanbe/go-cve-dictionary
```

Start go-cve-dictionary as server mode.  
For the first time, go-cve-dictionary fetches vulnerability data from NVD.  
It takes about 10 minutes (on AWS).  

```bash
$ go-cve-dictionary server
... Fetching ...
$ ls -alh cve.sqlite3
-rw-r--r-- 1 ec2-user ec2-user 7.0M Mar 24 13:20 cve.sqlite3
```

Now we has vulnerbility data, So start as server mode again.
```bash
$ go-cve-dictionary server
[Mar 24 15:21:55]  INFO Opening DB. datafile: /home/ec2-user/cve.sqlite3
[Mar 24 15:21:55]  INFO Migrating DB
[Mar 24 15:21:56]  INFO Starting HTTP Sever...
[Mar 24 15:21:56]  INFO Listening on 127.0.0.1:1323
```

# Hello HeartBleed

```
$ curl http://127.0.0.1:1323/cves/CVE-2014-0160 | jq "." 
{
  "ID": 63949,
  "CreatedAt": "2016-03-23T20:50:52.712279635+09:00",
  "UpdatedAt": "2016-03-23T20:50:52.712279635+09:00",
  "DeletedAt": null,
  "CveInfoID": 0,
  "CveID": "CVE-2014-0160",
  "Nvd": {
    "ID": 63949,
    "CreatedAt": "2016-03-23T20:50:52.712384527+09:00",
    "UpdatedAt": "2016-03-23T20:50:52.712384527+09:00",
    "DeletedAt": null,
    "CveDetailID": 63949,
    "Summary": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.",
    "Score": 5,
    "AccessVector": "NETWORK",
    "AccessComplexity": "LOW",
    "Authentication": "NONE",
    "ConfidentialityImpact": "PARTIAL",
    "IntegrityImpact": "NONE",
    "AvailabilityImpact": "NONE",
    "Cpes": null,
    "References": [
      {
        "ID": 316262,
        "CreatedAt": "2016-03-23T20:50:52.715120529+09:00",
        "UpdatedAt": "2016-03-23T20:50:52.715120529+09:00",
        "DeletedAt": null,
        "JvnID": 0,
        "NvdID": 63949,
        "Source": "CERT",
        "Link": "http://www.us-cert.gov/ncas/alerts/TA14-098A"
      },
      ...snip...
    ],
    "PublishedDate": "2014-04-07T18:55:03.893-04:00",
    "LastModifiedDate": "2015-10-22T10:19:38.453-04:00"
  },
  "Jvn": {
    "ID": 651,
    "CreatedAt": "2016-03-23T20:53:47.711776398+09:00",
    "UpdatedAt": "2016-03-23T20:53:47.711776398+09:00",
    "DeletedAt": null,
    "CveDetailID": 63949,
    "Title": "OpenSSL の heartbeat 拡張に情報漏えいの脆弱性",
    "Summary": "OpenSSL の heartbeat 拡張の実装には、情報漏えいの脆弱性が存在します。TLS や DTLS 通信において OpenSSL のコードを実行しているプロセスのメモリ内容が通信相手に漏えいする可能性があります。",
    "JvnLink": "http://jvndb.jvn.jp/ja/contents/2014/JVNDB-2014-001920.html",
    "JvnID": "JVNDB-2014-001920",
    "Score": 5,
    "Severity": "Medium",
    "Vector": "(AV:N/AC:L/Au:N/C:P/I:N/A:N)",
    "References": [
      {
        "ID": 369475,
        "CreatedAt": "2016-03-23T20:53:47.711885901+09:00",
        "UpdatedAt": "2016-03-23T20:53:47.711885901+09:00",
        "DeletedAt": null,
        "JvnID": 651,
        "NvdID": 0,
        "Source": "AT-POLICE",
        "Link": "http://www.npa.go.jp/cyberpolice/detect/pdf/20140410.pdf"
      },
      ...snip...
    ],
    "Cpes": null,
    "PublishedDate": "2014-04-08T16:13:59+09:00",
    "LastModifiedDate": "2014-04-08T16:13:59+09:00"
  }
}

```

# Usage:

```
./go-cve-dictionary -help
Usage: go-cve-dictionary <flags> <subcommand> <subcommand args>

Subcommands:
        commands         list all command names
        flags            describe all known top-level flags
        help             describe subcommands and their syntax

Subcommands for fetchjvn:
        fetchjvn         Fetch Vulnerability dictionary from JVN

Subcommands for fetchnvd:
        fetchnvd         Fetch Vulnerability dictionary from NVD

Subcommands for loadjvn:
        loadjvn          Start CVE dictionary HTTP server

Subcommands for server:
        server           Start CVE dictionary HTTP server


Use "go-cve-dictionary flags" for a list of top-level flags
```

go-cve-dictionary has four subcommands
- fetchnvd  
  Fetch vulnerbility data from NVD(English)

- fetchjvn
  Fetch vulnerbility data from JVN(Japanese)

- loadjvn
  Load vulnerbility data from local json file(Japanese)

- server
  Start HTTP server

# Usage: Update NVD Data.

```
$ go-cve-dictionary fetchnvd -h
fetchnvd:
        fetchnvd
                [-last2y]
                [-dbpath=/path/to/cve.sqlite3]
                [-debug]
                [-debug-sql]

  -dbpath string
        /path/to/sqlite3 (default "$PWD/cve.sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -last2y
        Refresh NVD data in the last two years.
```

- Fetch data of the entire period

```
$ go-cve-dictionary fetchnvd -entire
```

- Fetch data last 2 years

```
$ go-cve-dictionary fetchnvd -last2y
```
----

# Usage: Update JVN Data.

```
./go-cve-dictionary fetchjvn -h
fetchjvn:
        fetchjvn
                [-dump-path=/path/to/cve.json]
                [-dpath=$PWD/cve.sqlite3]
                [-week]
                [-month]
                [-entire]
                [-debug]
                [-debug-sql]

  -dbpath string
        /path/to/sqlite3 (default "/Users/kotakanbe/go/src/github.com/kotakanbe/go-cve-dictionary/cve.sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -dump-path string
        /path/to/cve.json (default: empty(nodump))
  -entire
        Fetch data for entire period.(This operation is time-consuming) (default: false)
  -month
        Fetch data in the last month
  -week
        Fetch data in the last week

```

- Fetch data of the entire period

```
$ go-cve-dictionary fetchjvn --entire
```

- Fetch data last month

```
$ go-cve-dictionary fetchnvd -month
```

- Fetch data last week

```
$ go-cve-dictionary fetchnvd -week
```

----

# Usage: Run HTTP Server.

```
./go-cve-dictionary server -h
server:
        server
                [-bind=127.0.0.1]
                [-port=8000]
                [-dpath=$PWD/cve.sqlite3]
                [-debug]
                [-debug-sql]

  -bind string
        HTTP server bind to IP address (default: loop back interface) (default "127.0.0.1")
  -dbpath string
        /path/to/sqlite3 (default : /Users/kotakanbe/go/src/github.com/kotakanbe/go-cve-dictionary/cve.sqlite3) (default "/Users/kotakanbe/go/src/github.com/kotakanbe/go-cve-dictionary/cve.sqlite3")
  -debug
        debug mode (default: false)
  -debug-sql
        SQL debug mode (default: false)
  -port string
        HTTP server port number (default: 1323) (default "1323")

```

----

# Misc

- HTTP Proxy Support  
If your system is behind HTTP proxy, you have to specify --http-proxy option.

- How to Daemonize go-cve-dictionary  
Use Systemd, Upstart or supervisord, daemontools...

- How to update vulnerbility data automatically.  
Use job scheduler like Cron (with -last2y option).

- How to cross compile
    ```bash
    $ cd /path/to/your/local-git-reporsitory/vuls
    $ GOOS=linux GOARCH=amd64 go build -o vuls.amd64
    ```

- Logging  
Log wrote to under /var/log/vuls/

- Debug  
Run with --debug, --sql-debug option.

----

# Data Source

- [NVD](https://nvd.nist.gov/)
- [JVN(Japanese)](http://jvndb.jvn.jp/apis/myjvn/)



----

# Authors

kotakanbe ([@kotakanbe](https://twitter.com/kotakanbe)) created vuls and [these fine people](https://github.com/future-architect/vuls/graphs/contributors) have contributed.

----

# Contribute

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

----

# Change Log

Please see [CHANGELOG](https://github.com/kotakanbe/go-cve-dictionary/blob/master/CHANGELOG.md).

----

# Licence

Please see [LICENSE](https://github.com/kotakanbe/go-cve-dictionary/blob/master/LICENSE).

----

# Additional License

- [NVD](https://nvd.nist.gov/faq)
>How can my organization use the NVD data within our own products and services?  
> All NVD data is freely available from our XML Data Feeds. There are no fees, licensing restrictions, or even a requirement to register. All NIST publications are available in the public domain according to Title 17 of the United States Code. Acknowledgment of the NVD  when using our information is appreciated. In addition, please email nvd@nist.gov to let us know how the information is being used.  
 

- [JVN](http://jvndb.jvn.jp/apis/termsofuse.html)

