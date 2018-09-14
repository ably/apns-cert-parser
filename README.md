# APNS Certificate Parser

A simple parser to extract details of the Apple custom extension used to encode bundle/topic ids in Apple developer certificates.

# Usage

```
	const buf = fs.readFileSync(__dirname + '/path/to/certificate.pem'),
		cert = Certificate.fromPEM(buf),
		{ name, detail } = cert.getFirstTopicIdentifier();
```

# Test

```
	npm test
```
