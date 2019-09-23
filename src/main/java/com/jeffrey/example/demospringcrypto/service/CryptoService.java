package com.jeffrey.example.demospringcrypto.service;

import com.jeffrey.example.demospringcrypto.crypto.CryptoClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class CryptoService {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoService.class);

    @Autowired
    @Qualifier("cryptoClient")
    CryptoClient cryptoClient;

    public String generateAesKey() {
        return cryptoClient.generateNewAesKey();
    }

    public String encryptMessageWithAes(String aesKeyBase64, String decipheredText) {
        return cryptoClient.encryptWithAesKey(aesKeyBase64, decipheredText);
    }

    public String decryptMessageWithAes(String aesKeyBase64, String cipheredTextBase64) {
        return cryptoClient.decryptWithAesKey(aesKeyBase64, cipheredTextBase64);
    }

    public String generateEcdsaKeyPair() {
        return cryptoClient.generateNewEcdsaKeyPair();
    }

    public String signMessageWithEcdsa(String ecdsaPrivateKeyBase64, String messageToSign) {
        return cryptoClient.signWithEcdsaPrivateKey(ecdsaPrivateKeyBase64, messageToSign);
    }

    public void verifyMessageWithEcdsa(String ecdsaPrivateKeyBase64, String messageToSign, String signatureBase64) {
        cryptoClient.verifySignatureWithEcdsaPublicKey(ecdsaPrivateKeyBase64, messageToSign, signatureBase64);

    }

}
