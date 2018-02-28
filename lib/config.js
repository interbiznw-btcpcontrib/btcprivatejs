'use strict';

/*
config.js - Configuration for Bitcoin Private 
*/

module.exports = {
  mainnet: {
    messagePrefix: 'BitcoinPrivate Signed Message:\n',
    bip32: {
      public: '0488b21e',
      private: '0488ade4'
    },
    pubKeyHash: '1325', // P2PKH Prefix
    scriptHash: '13af', // P2SH Prefix
    zcPaymentAddressHash: '16a8', // Private z-address (ZK)
    zcSpendingKeyHash: 'ab36', // Spending key (SK)
    wif: '80'
  },
  testnet: {
    messagePrefix: 'BitcoinPrivate Signed Message:\n',
    bip32: {
      public: '043587cf',
      private: '04358394'
    },
    pubKeyHash: '1958',
    scriptHash: '19e0',
    zcPaymentAddressHash: '16c0', // Private z-address (ZK)
    zcSpendingKeyHash: 'ac08', // Spending key (SK)
    wif: 'ef'
  }
};
