# dnstrace

This tool performs a DNS resolution by tracing the delegation path from the root name servers and by following CNAMES. Each additional query is reported.

![](screenshot.png)

## Install

Using [homebrew](http://brew.sh/):

```
brew install rs/tap/dnstrace
```

From source:

```
go get github.com/rs/dnstrace
```

Or download a [binary package](https://github.com/rs/dnstrace/releases/latest).

# License

All source code is licensed under the [MIT License](https://raw.github.com/rs/dnstrace/master/LICENSE).
