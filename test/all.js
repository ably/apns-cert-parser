const { Certificate } = require('../lib/certificate');

const fs = require('fs');

exports.read_der = function(test) {
	const buf = fs.readFileSync(__dirname + '/fixtures/io.ably.push-demo.production-cert.der'),
		cert = Certificate.fromDER(buf),
		topicIdentifier = cert.getFirstTopicIdentifier();

	test.equal(topicIdentifier.name, 'io.ably.push-demo', 'Verify expected topic id');
	test.done();
};

exports.read_pem = function(test) {
	const buf = fs.readFileSync(__dirname + '/fixtures/io.ably.push-demo.production-cert.pem'),
		cert = Certificate.fromPEM(buf),
		topicIdentifier = cert.getFirstTopicIdentifier();

	test.equal(topicIdentifier.name, 'io.ably.push-demo', 'Verify expected topic id');
	test.done();
};
