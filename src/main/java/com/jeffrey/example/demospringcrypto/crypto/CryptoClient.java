package com.jeffrey.example.demospringcrypto.crypto;

public interface CryptoClient {

    String generateNewAesKey() throws RuntimeException;

    String encryptWithAesKey(final String aesKeyBase64, final String decipheredText) throws RuntimeException;

    String decryptWithAesKey(final String aesKeyBase64, final String cipheredTextBase64) throws RuntimeException;

    String generateNewEcdsaKeyPair() throws RuntimeException;

    String signWithEcdsaPrivateKey(final String ecdsaPrivateKeyBase64, final String messageToSign) throws RuntimeException;

    void verifySignatureWithEcdsaPublicKey(final String ecdsaPrivateKeyBase64, final String messageToSign, final String signatureBase64);
}
