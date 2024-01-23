# jwker CLI

A CLI for generating and manipulating JWKs and JWKSes (is that even how you spell it?).

## Installation

Make sure you have Go installed.

```
go install github.com/palkerecsenyi/jwker@v0.1.0
```

## Usage
To generate a simple private JWK with 2048 bit RSA and send it to stdout in JSON form, simply run the command:

```
jwker generate --use <encryption / signing>
```

For more information, see:
```
jwker help
```

## License
MIT license; see license.md.
