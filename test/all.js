const { Certificate, APPLE_UNIVERSAL_CERTIFICATE_EXTENSION } = require('../lib/certificate');

const fs = require('fs');

/* read a certificate with the universal extension, DER format */
exports.read_der = function(test) {
	const buf = fs.readFileSync(__dirname + '/fixtures/universal.der'),
		cert = Certificate.fromDER(buf),
		topicIdentifier = cert.getTopicIdentifier();

	test.equal(topicIdentifier.name, 'io.ably.push-demo', 'Verify expected topic id');
	test.done();
};

/* read a certificate with the universal extension, PEM format */
exports.read_pem = function(test) {
	const buf = fs.readFileSync(__dirname + '/fixtures/universal.pem'),
		cert = Certificate.fromPEM(buf),
		topicIdentifier = cert.getTopicIdentifier();

	test.equal(topicIdentifier.name, 'io.ably.push-demo', 'Verify expected topic id');
	test.done();
};

/* read a certificate with the universal extension, PEM format, with preamble text */
exports.read_preamble_pem = function(test) {
	const buf = fs.readFileSync(__dirname + '/fixtures/preamble.pem'),
		cert = Certificate.fromPEM(buf),
		topicIdentifier = cert.getTopicIdentifier();

	test.equal(topicIdentifier.name, 'io.ably.push-demo', 'Verify expected topic id');
	test.done();
};

/* read a certificate with the universal extension, PEM format with escaped whitespace */
exports.read_pem_escaped = function(test) {
	const buf = fs.readFileSync(__dirname + '/fixtures/universal-escaped.pem'),
		cert = Certificate.fromPEM(buf),
		topicIdentifier = cert.getTopicIdentifier();

	test.equal(topicIdentifier.name, 'io.ably.push-demo', 'Verify expected topic id');
	test.done();
};

/* read a certificate with the universal extension, PEM format, with preamble text */
exports.read_preamble_escaped_pem = function(test) {
	const buf = fs.readFileSync(__dirname + '/fixtures/preamble-escaped.pem'),
		cert = Certificate.fromPEM(buf),
		topicIdentifier = cert.getTopicIdentifier();

	test.equal(topicIdentifier.name, 'io.ably.push-demo', 'Verify expected topic id');
	test.done();
};

/* read a certificate with the development extension and UID, PEM format */
exports.read_development_pem = function(test) {
	const buf = fs.readFileSync(__dirname + '/fixtures/development.pem'),
		cert = Certificate.fromPEM(buf, {ignoreExtensionOID: APPLE_UNIVERSAL_CERTIFICATE_EXTENSION}),
		topicIdentifier = cert.getTopicIdentifier();

	test.equal(topicIdentifier.name, 'io.ably.push-demo', 'Verify expected topic id');
	test.done();
};
