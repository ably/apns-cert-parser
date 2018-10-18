'use strict';

const APPLE_DEVELOPMENT_ENV_EXTENSION       = exports.APPLE_DEVELOPMENT_ENV_EXTENSION       = '1.2.840.113635.100.6.3.1';
const APPLE_PRODUCTION_ENV_EXTENSION        = exports.APPLE_PRODUCTION_ENV_EXTENSION        = '1.2.840.113635.100.6.3.2';
const APPLE_UNIVERSAL_CERTIFICATE_EXTENSION = exports.APPLE_UNIVERSAL_CERTIFICATE_EXTENSION = '1.2.840.113635.100.6.3.6';
const USERID_OID                            = exports.USERID_OID                            = '0.9.2342.19200300.100.1.1';

const asn1js = require('asn1js');
const pem = require('pem-file');
const pkijs = require('pkijs');
const util = require('util');

function toArrayBuffer(b) {
	return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

function Certificate(asn1, options) {
	this.asn1 = asn1;
	this.options = options;
	this.cert = new pkijs.Certificate({ schema: asn1.result });
}

Certificate.prototype.getExtensionById = function(extnID) {
	if(this.options && this.options.ignoreExtensionOID === extnID) {
		return null;
	}

	const cert = this.cert;
	for(let i = 0; i < cert.extensions.length; i++) {
		const ext = cert.extensions[i];
		if(ext.extnID == extnID) {
			return ext;
		}
	}
	return null;
};

Certificate.prototype.getSubjectNameEntryByType = function(typeID) {
	const cert = this.cert, subjectNames = cert.subject.typesAndValues;
	for(let i = 0; i < subjectNames.length; i++) {
		const nameAttributeTypeAndValue = subjectNames[i];
		if(nameAttributeTypeAndValue.type == typeID) {
			return nameAttributeTypeAndValue;
		}
	}
	return null;
};

Certificate.prototype.inspect = function() {
	return util.inspect(this.cert, {depth: 6});
};

Certificate.prototype.getUniversalTopicIdentifiers = function() {
	const topicsExt = this.getExtensionById(APPLE_UNIVERSAL_CERTIFICATE_EXTENSION);
	if(!topicsExt) { return null; }
	const topicsExtValue = topicsExt.extnValue.valueBlock.valueHex;
	const extAsn1 = asn1js.fromBER(topicsExtValue);
	if(!extAsn1) { return null; }
	const topics = extAsn1.result.valueBlock.value;

	const topicCount = topics.length / 2;
	if(topicCount === 0) { return null; }

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

Certificate.prototype.getUID = function() {
	const uidAttribute = this.getSubjectNameEntryByType(USERID_OID);
	if(!uidAttribute) { return null; }
	const name = uidAttribute.value.valueBlock.value;
	return name;
};

Certificate.prototype.getFirstTopicIdentifier = function() {
	const topicIdentifiers = this.getTopicIdentifiers();
	if(!topicIdentifiers || !topicIdentifiers.length) { return null; }
	return topicIdentifiers[0];
};

Certificate.prototype.getTopicIdentifier = function() {
	const topicIdentifiers = this.getUniversalTopicIdentifiers();
	if(topicIdentifiers && topicIdentifiers.length > 0) {
		// console.log('Found universal extension');
		const topicIdentifier = topicIdentifiers[0];
		return topicIdentifier;
	}
	/* no universal extension, so look for dev or production extensions */
	if(this.getExtensionById(APPLE_PRODUCTION_ENV_EXTENSION) || this.getExtensionById(APPLE_DEVELOPMENT_ENV_EXTENSION)) {
		// console.log('Found environment extension and UID');
		const name = this.getUID();
		return name && { name };
	}
	/* no relevant information found */
	return null;
};

Certificate.fromPEM = function(pemText, options) {
	if (Buffer.isBuffer(pemText)) {
		pemText = pemText.toString('utf-8')
	}
	/* if the text contains encoded whitespace, replace */
	pemText = pemText.replace(/\\n/g, '\n');
	/* if the text contains a preamble before the certificate text, remove it */
	const startIdx = pemText.indexOf('-----BEGIN CERTIFICATE-----');
	if(startIdx === -1) {
		throw new Error('Invalid PEM text - no BEGIN');
	}
	if(startIdx > 0) {
		pemText = pemText.slice(startIdx);
	}

	return Certificate.fromDER(pem.decode(pemText), options);
};

Certificate.fromDER = function(buf, options) {
	const arrayBuffer = toArrayBuffer(buf);
	const asn1 = asn1js.fromBER(arrayBuffer);
	return new Certificate(asn1, options);
};

exports.Certificate = Certificate;
