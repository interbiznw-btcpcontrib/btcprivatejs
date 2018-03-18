'use strict';

/* Opcodes for the scripting language */
module.exports = {
  OP_0: '00', // OP_FALSE
  OP_1: '51', // OP_TRUE
  OP_2: '52',
  OP_3: '53',
  OP_4: '54',
  OP_5: '55',
  OP_NOP: '61',
  OP_VER: '62',
  OP_IF: '63',
  OP_NOTIF: '64',
  OP_VERIF: '65',
  OP_VERNOTIF: '66',
  OP_ELSE: '67',
  OP_ENDIF: '68',
  OP_VERIFY: '69',
  OP_RETURN: '6a',
  OP_DUP: '76',
  OP_NIP: '77',
  OP_OVER: '78',
  OP_HASH160: 'a9',
  OP_EQUAL: '87',
  OP_EQUALVERIFY: '88',
  OP_RESERVED: '89', //There are actually 2
  OP_CHECKSIG: 'ac',
  OP_CHECKSIGVERIFY: 'ad',
  OP_CHECKMULTISIG: 'ae',
  OP_CHECKMULTISIGVERIFY: 'af',
  OP_PUSHDATA1: '4c',
  OP_PUSHDATA2: '4d',
  OP_PUSHDATA4: '4e'
};
