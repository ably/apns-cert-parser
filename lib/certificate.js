'use strict';

const APPLE_TOPIC_EXTENSION_OID = exports.APPLE_TOPIC_EXTENSION_OID = '1.2.840.113635.100.6.3.6';

const asn1js = require('asn1js');
const pem = require('pem-file');
const pkijs = require('pkijs');
const util = require('util');

function toArrayBuffer(b) {
	return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

function Certificate(asn1) {
	this.asn1 = asn1;
	this.cert = new pkijs.Certificate({ schema: asn1.result });
}

Certificate.prototype.getExtensionById = function(extnID) {
	extnID = extnID || APPLE_TOPIC_EXTENSION_OID;
	const cert = this.cert;
	for(let i = 0; i < cert.extensions.length; i++) {
		const ext = cert.extensions[i];
		if(ext.extnID == extnID) {
			return ext;
		}
	}
	return null;
};

Certificate.prototype.inspect = function() {
	return util.inspect(this.cert, {depth: 6});
};

Certificate.prototype.getTopicIdentifiers = function() {
	const topicsExt = this.getExtensionById(APPLE_TOPIC_EXTENSION_OID);
	const topicsExtValue = topicsExt.extnValue.valueBlock.valueHex;
	const extAsn1 = asn1js.fromBER(topicsExtValue);
	const topics = extAsn1.result.valueBlock.value;

	const topicCount = topics.length / 2;
	const identifiers = new Array(topicCount);
	for(let topicIdx = 0; topicIdx < topicCount; topicIdx++) {
		const topicNameEntry = topics[topicIdx*2];
		const name = topicNameEntry.valueBlock.value;
		const topicDetailsEntry = topics[topicIdx*2 + 1];
		const detail = topicDetailsEntry.valueBlock.value[0].valueBlock.value;
		identifiers[topicIdx] = { name, detail };

	}
	return identifiers;
};

Certificate.prototype.getFirstTopicIdentifier = function() {
	const topicIdentifiers = this.getTopicIdentifiers();
	if(!topicIdentifiers || !topicIdentifiers.length) { return null; }
	return topicIdentifiers[0];
};

Certificate.fromPEM = function(buf) {
	return Certificate.fromDER(pem.decode(buf));
};

Certificate.fromDER = function(buf) {
	const arrayBuffer = toArrayBuffer(buf);
	const asn1 = asn1js.fromBER(arrayBuffer);
	return new Certificate(asn1);
};

exports.Certificate = Certificate;
