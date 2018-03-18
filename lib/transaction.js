'use strict';

var bs58check = require('bs58check');

var elliptic = require('elliptic');
var secp256k1 = new elliptic.ec('secp256k1'); /* eslint new-cap: ["error", { "newIsCap": false }] */
var varuint = require('varuint-bitcoin');
var zconfig = require('./config');
var zbufferutils = require('./bufferutils');
var zcrypto = require('./crypto');
var zconstants = require('./constants');
var zaddress = require('./address');
var zopcodes = require('./opcodes');

/* 
 * Given an address, generates a pubkeyhash replay type script needed for the transaction
 * @param {String} address
 * return {String} pubKeyScript
 */
function mkPubkeyHashReplayScript(address) {
  // Prefix
  var pubKeyHash = zconfig.mainnet.pubKeyHash;

  var addrHex = bs58check.decode(address).toString('hex');

  // Cut out pubKeyHash
  // '14' is the length of the subAddrHex (in bytes)
  var subAddrHex = addrHex.substring(pubKeyHash.length, addrHex.length);

  // '14' is the length of the subAddrHex (in bytes)
  return zopcodes.OP_DUP + zopcodes.OP_HASH160 + subAddrHex + zopcodes.OP_EQUALVERIFY + zopcodes.OP_CHECKSIG;
}

/*
 * Given an address, generates a script hash replay type script needed for the transaction
 * @param {String} address
 * return {String} scriptHash script
 */
function mkScriptHashReplayScript(address) {

  var addrHex = bs58check.decode(address).toString('hex');

  // Cut out the '00' (we also only want 14 bytes instead of 16)
  var subAddrHex = addrHex.substring(4, addrHex.length);

  return zopcodes.OP_HASH160 + zbufferutils.getPushDataLength(subAddrHex) + subAddrHex + zopcodes.OP_EQUAL;
}

/*
 * Given an address, generates an output script
 * @param {String} address
 * return {String} output script
 */
function addressToScript(address) {
  // P2SH (with replay protection) 
  if (address[1] === 'x') {
    return mkScriptHashReplayScript(address);
  }

  // P2PKH (with replay protection)
  return mkPubkeyHashReplayScript(address);
}

/*
 * Signature hashing for TXOBJ
 * @param {String} address
 * @param {Number} i, which transaction input to sign
 * @param {String} hex string of script
 * @param {String} hash code (SIGHASH_ALL, SIGHASH_NONE...)
 * return {String} output script
 */
function signatureForm(txObj, i, script, hashcode) {
  // Copy object so we don't rewrite it
  var newTx = JSON.parse(JSON.stringify(txObj));

  // Only sign the specified index
  for (var j = 0; j < newTx.ins.length; j++) {
    newTx.ins[j].script = '';
  }

  newTx.ins[i].script = script;

  /*
  if (hashcode === zconstants.SIGHASH_NONE) {
    newTx.outs = [];
  } else if (hashcode === zconstants.SIGHASH_SINGLE) {
    newTx.outs = newTx.outs.slice(0, newTx.ins.length);
    for (var _j = 0; _j < newTx.ins.length - 1; ++_j) {
      newTx.outs[_j].satoshis = Math.pow(2, 64) - 1;
      newTx.outs[_j].script = '';
    }
  } else if (hashcode === zconstants.SIGHASH_ANYONECANPAY) {
    newTx.ins = [newTx.ins[i]];
  }
  TODO these | SIGHASH_FORKID 
  */

  newTx.ins = [newTx.ins[i]];

  return newTx;
}

/*
 * Deserializes a hex string into a TXOBJ
 * @param {String} hex string
 * @return {Object} txOBJ
 */
function deserializeTx(hexStr) {
  var buf = Buffer.from(hexStr, 'hex');
  var offset = 0;

  // Out txobj
  var txObj = { version: 0, locktime: 0, ins: [], outs: []

    // Version
  };txObj.version = buf.readUInt32LE(offset);
  offset += 4;

  // Vins
  var vinLen = varuint.decode(buf, offset);
  offset += varuint.decode.bytes;
  for (var i = 0; i < vinLen; i++) {
    // Else its
    var hash = buf.slice(offset, offset + 32);
    offset += 32;

    var vout = buf.readUInt32LE(offset);
    offset += 4;

    var scriptLen = varuint.decode(buf, offset);
    offset += varuint.decode.bytes;

    var script = buf.slice(offset, offset + scriptLen);
    offset += scriptLen;

    var sequence = buf.slice(offset, offset + 4).toString('hex');
    offset += 4;

    txObj.ins.push({
      output: { hash: hash.reverse().toString('hex'), vout: vout },
      script: script.toString('hex'),
      sequence: sequence,
      prevScriptPubKey: ''
    });
  }

  // Vouts
  var voutLen = varuint.decode(buf, offset);
  offset += varuint.decode.bytes;
  for (var _i = 0; _i < voutLen; _i++) {
    var satoshis = zbufferutils.readUInt64LE(buf, offset);
    offset += 8;

    var _scriptLen = varuint.decode(buf, offset);
    offset += varuint.decode.bytes;

    var _script = buf.slice(offset, offset + _scriptLen);
    offset += _scriptLen;

    txObj.outs.push({
      satoshis: satoshis,
      script: _script.toString('hex')
    });
  }

  // Locktime
  txObj.locktime = buf.readInt32LE(offset);
  offset += 4;

  return txObj;
}

/*
 * Serializes a TXOBJ into hex string
 * @param {Object} txObj
 * return {String} hex string of txObj
 */
function serializeTx(txObj) {
  var serializedTx = '';
  var _buf16 = Buffer.alloc(4);

  // Version
  _buf16.writeUInt16LE(txObj.version, 0);
  serializedTx += _buf16.toString('hex');

  // History
  serializedTx += zbufferutils.numToVarInt(txObj.ins.length);
  txObj.ins.map(function (i) {
    // Txids and vouts
    _buf16.writeUInt16LE(i.output.vout, 0);
    serializedTx += Buffer.from(i.output.hash, 'hex').reverse().toString('hex');
    serializedTx += _buf16.toString('hex');

    // Script Signature
    // Doesn't work for length > 253 ....
    serializedTx += zbufferutils.getPushDataLength(i.script);
    serializedTx += i.script;

    // Sequence
    serializedTx += i.sequence;
  });

  // Outputs
  serializedTx += zbufferutils.numToVarInt(txObj.outs.length);
  txObj.outs.map(function (o) {
    // Write 64bit buffers
    // JS only supports 56 bit
    // https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/bufferutils.js#L25
    var _buf32 = Buffer.alloc(8);

    // Satoshis
    _buf32.writeInt32LE(o.satoshis & -1, 0);
    _buf32.writeUInt32LE(Math.floor(o.satoshis / 0x100000000), 4);

    // ScriptPubKey
    serializedTx += _buf32.toString('hex');
    serializedTx += zbufferutils.getPushDataLength(o.script);
    serializedTx += o.script;
  });

  // Locktime
  _buf16.writeUInt16LE(txObj.locktime, 0);
  serializedTx += _buf16.toString('hex');

  return serializedTx;
}

/*
 * Creates a raw transaction
 * @param {[HISTORY]} history type, array of transaction history
 * @param {[RECIPIENTS]} recipient type, array of address on where to send coins to
 * @return {TXOBJ} Transaction Object (see TXOBJ type for info about structure)
 */
function createRawTx(history, recipients) {
  var txObj = { locktime: 0, version: 1, ins: [], outs: [] };

  txObj.ins = history.map(function (h) {
    return {
      output: { hash: h.txid, vout: h.vout },
      script: '',
      prevScriptPubKey: h.scriptPubKey,
      sequence: 'ffffffff'
    };
  });
  txObj.outs = recipients.map(function (o) {
    return {
      script: addressToScript(o.address),
      satoshis: o.satoshis
    };
  });

  return txObj;
}

/*
 * Gets signature for the vin script
 * @params {string} privKey private key
 * @params {TXOBJ} signingTx a txobj whereby all the vin script's field are empty except for the one that needs to be signed
 * @params {number} hashcode
*/
function getScriptSignature(privKey, signingTx, hashcode) {

  var BTCP_FORKID = 42;

  // Buffers
  var _buf16H = Buffer.alloc(4);
  _buf16H.writeUInt16LE(hashcode, 0);
  var _buf16FH = Buffer.alloc(4);
  _buf16FH.writeUInt16BE(hashcode | (BTCP_FORKID << 8), 0);

  var signingTxHex = serializeTx(signingTx);
  var signingTxWithHashcode = signingTxHex + _buf16H.toString('hex');
  var signingTxFinal = signingTxWithHashcode + _buf16FH.toString('hex');
  

  // Sha256 it twice, according to spec
  var msg = zcrypto.sha256x2(Buffer.from(signingTxWithHashcode, 'hex'));

  // Signing it
  var rawsig = secp256k1.sign(Buffer.from(msg, 'hex'), Buffer.from(privKey, 'hex'), { canonical: true });

  // Convert it to DER format
  // Appending 01 to it cause
  // ScriptSig = <varint of total sig length> <SIG from code, including appended 01 SIGNHASH> <length of pubkey (0x21 or 0x41)> <pubkey>
  // https://bitcoin.stackexchange.com/a/36481
  var signatureDER = Buffer.from(rawsig.toDER()).toString('hex') + '01';

  return signatureDER;
}

/*
 * Signs the raw transaction
 * @param {String} rawTx raw transaction
 * @param {Int} i
 * @param {privKey} privKey (not WIF format)
 * @param {compressPubKey} compress public key before appending to scriptSig? (default false)
 * @param {hashcode} hashtype (default SIGHASH_ALL|SIGHASH_FORKID)
 * return {String} signed transaction
 */
function signTx(_txObj, i, privKey) {
  var compressPubKey = arguments.length > 3 && arguments[3] !== undefined ? arguments[3] : false;
  var hashcode = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : (zconstants.SIGHASH_ALL | zconstants.SIGHASH_FORKID);

  // Make a copy
  var txObj = JSON.parse(JSON.stringify(_txObj));

  // Prepare our signature
  // Get script from the current tx input
  var script = txObj.ins[i].prevScriptPubKey;

  // Populate current tx in with the prevScriptPubKey
  var signingTx = signatureForm(txObj, i, script, hashcode);

  // Get script signature
  var scriptSig = getScriptSignature(privKey, signingTx, hashcode);


  // Chuck it back into txObj and add pubkey
  // Protocol:
  // PUSHDATA
  // signature data and SIGHASH_ALL|SIGHASH_FORKID
  // PUSHDATA
  // public key data
  var compress = false; //TODO does this need to be true?
  var pubKey = zaddress.privKeyToPubKey(privKey, compress);

  txObj.ins[i].script = zbufferutils.getPushDataLength(scriptSig) + scriptSig + zbufferutils.getPushDataLength(pubKey) + pubKey;

  return txObj;
}

/*
 * Gets signatures needed for multi-sign tx
 * @param {String} _txObj transaction object you wanna sign
 * @param {Int} index fof tx.in to sign
 * @param {privKey} An M private key (NOT WIF format!!!)
 * @param {string} redeemScript (redeemScript of the multi-sig)
 * @param {string} hashcode (SIGHASH_ALL, SIGHASH_NONE, etc | SIGHASH_FORKID)
 * return {String} signature
 */
function multiSign(_txObj, i, privKey, redeemScript) {
  var hashcode = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : zconstants.SIGHASH_ALL | zconstants.SIGHASH_FORKID;

  // Make a copy
  var txObj = JSON.parse(JSON.stringify(_txObj));

  // Populate current tx.ins[i] with the redeemScript
  var signingTx = signatureForm(txObj, i, redeemScript, hashcode);

  return getScriptSignature(privKey, signingTx, hashcode);
}

/*
 * Applies the signatures to the transaction object
 * NOTE: You NEED to supply the signatures in order.
 *       E.g. You made sigAddr1 with priv1, priv3, priv2
 *            You can provide signatures of (priv1, priv2) (priv3, priv2) ...
 *            But not (priv2, priv1)
 * @param {String} _txObj transaction object you wanna sign
 * @param {Int} index fof tx.in to sign
 * @param {[string]} signatures obtained from multiSign
 * @param {string} redeemScript (redeemScript of the multi-sig)
 * @param {string} hashcode (SIGHASH_ALL, SIGHASH_NONE, etc)
 * return {String} signature
 */
function applyMultiSignatures(_txObj, i, signatures, redeemScript) {
  // Make a copy
  var txObj = JSON.parse(JSON.stringify(_txObj));

  var redeemScriptPushDataLength = zbufferutils.getPushDataLength(redeemScript);

  // Lmao no idea, just following the source code
  if (redeemScriptPushDataLength.length > 2) {
    if (redeemScriptPushDataLength.length === 6) {
      redeemScriptPushDataLength = redeemScriptPushDataLength.slice(2, 4);
    }
  }

  // http://www.soroushjp.com/2014/12/20/bitcoin-multisig-the-hard-way-understanding-raw-multisignature-bitcoin-transactions/
  txObj.ins[i].script = zopcodes.OP_0 + signatures.map(function (x) {
    return zbufferutils.getPushDataLength(x) + x;
  }).join('') + zopcodes.OP_PUSHDATA1 + redeemScriptPushDataLength + redeemScript;

  return txObj;
}

module.exports = {
  addressToScript: addressToScript,
  createRawTx: createRawTx,
  mkPubkeyHashReplayScript: mkPubkeyHashReplayScript,
  mkScriptHashReplayScript: mkScriptHashReplayScript,
  signatureForm: signatureForm,
  serializeTx: serializeTx,
  deserializeTx: deserializeTx,
  signTx: signTx,
  multiSign: multiSign,
  applyMultiSignatures: applyMultiSignatures,
  getScriptSignature: getScriptSignature
};
