package com.jeffrey.example.demospringcrypto.crypto;

public interface CryptoClient {

    String generateNewAesKey() throws RuntimeException;

    String encryptWithAesKey(final String aesKeyBase64, final String decipheredText) throws RuntimeException;

    String decryptWithAesKey(final String aesKeyBase64, final String cipheredTextBase64) throws RuntimeException;

    String generateNewEcdsaKeyPair() throws RuntimeException;

    String signWithEcdsaPrivateKey(final String ecdsaPrivateKeyBase64, final String message) throws RuntimeException;

    void verifySignatureWithEcdsaPublicKey(final String ecdsaPrivateKeyBase64, final String message, final String signatureBase64) throws RuntimeException;

    String generateNewHmacSha2Key() throws RuntimeException;

    String computeAuthTagWithHmacKey(final String hmacKeyBase64,final String message) throws RuntimeException;

    void verifyAuthTagWithHmacKey(final String hmacKeyBase64, final String message, final String authTagBase64);

}
