package com.jeffrey.example.demospringcrypto.crypto;

import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;
import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.signature.SignatureKeyTemplates;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;

public class TinkCryptoClient implements CryptoClient {
    private static final Logger LOGGER = LoggerFactory.getLogger(TinkCryptoClient.class);

    public TinkCryptoClient() throws Exception {
        try {
            TinkConfig.register();
            AeadConfig.register();
        } catch (Exception e) {
            throw e;
        }
    }

    @Override
    public String generateNewAesKey() {
        try {
            /**
             * Default JDK supports encryption only through 128 bit keys because of American restrictions.
             *
             * For running locally:
             * Starting with Java 8 Update 161, Java 8 defaults to the Unlimited Strength Policy.
             * Install or upgrade Java 8 SDK to any version >= 1.8.0.161
             *
             * For running on cloud foundry:
             * Prior to the Java buildpack version 3.7.1, the Java Cryptography Extension(JCE) Unlimited Strength
             * policy was not enabled and had to be enabled manually. Starting with the version 3.7.1, the JCE
             * Unlimited Strength policy is enabled by default.
             *
             * See also:
             * https://community.pivotal.io/s/article/How-to-use-the-JCE-Unlimited-Strength-policy-with-Java-applications
             *
             */
            KeysetHandle keysetHandle = KeysetHandle.generateNew(
                    AeadKeyTemplates.AES256_GCM
            );
            ByteArrayOutputStream keyOutputStream = new ByteArrayOutputStream();
            CleartextKeysetHandle.write(keysetHandle, JsonKeysetWriter.withOutputStream(keyOutputStream));
            byte[] keyByteArray = ByteStreams.newDataOutput(keyOutputStream).toByteArray();

            String aesKeyJsonString = new String(keyByteArray);
            LOGGER.debug("aes key json: {}", aesKeyJsonString);

            String aesKeyBase64String = BaseEncoding.base64().encode(keyByteArray);
            LOGGER.debug("aes key base64: {}", aesKeyBase64String);

            return aesKeyBase64String;

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String encryptWithAesKey(final String aesKeyBase64, final String decipheredText) {
        try {
            byte[] keyByteArray = BaseEncoding.base64().decode(aesKeyBase64);
            KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyByteArray));
            Aead aeadPrimitive = keysetHandle.getPrimitive(Aead.class);

            String cipheredTextBase64String = BaseEncoding.base64().encode(aeadPrimitive.encrypt(decipheredText.getBytes(), keyByteArray));
            LOGGER.debug("ciphered text base64: {}", cipheredTextBase64String);

            return cipheredTextBase64String;

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String decryptWithAesKey(final String aesKeyBase64, final String cipheredTextBase64String) {
        try {
            byte[] keyByteArray = BaseEncoding.base64().decode(aesKeyBase64);
            KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyByteArray));
            Aead aeadPrimitive = keysetHandle.getPrimitive(Aead.class);

            String decipheredText = new String(aeadPrimitive.decrypt(BaseEncoding.base64().decode(cipheredTextBase64String), keyByteArray));
            LOGGER.debug("deciphered text: {}", decipheredText);

            return decipheredText;

        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String generateNewEcdsaKeyPair() {
        try {
            KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(SignatureKeyTemplates.ECDSA_P256);
            ByteArrayOutputStream privateKeyOutputStream = new ByteArrayOutputStream();
            CleartextKeysetHandle.write(privateKeysetHandle, JsonKeysetWriter.withOutputStream(privateKeyOutputStream));

            byte[] privateKeyByteArray = ByteStreams.newDataOutput(privateKeyOutputStream).toByteArray();
            String privateKeyJsonString = new String(privateKeyByteArray);
            LOGGER.debug("private key json: {}", privateKeyJsonString);

            KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();
            ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
            CleartextKeysetHandle.write(publicKeysetHandle, JsonKeysetWriter.withOutputStream(publicKeyOutputStream));

            byte[] publicKeyByteArray = ByteStreams.newDataOutput(publicKeyOutputStream).toByteArray();
            String publicKeyJsonString = new String(publicKeyByteArray);
            LOGGER.debug("public key json: {}", publicKeyJsonString);

            String privatekeyJsonBase64 = BaseEncoding.base64().encode(privateKeyByteArray);
            LOGGER.debug("private key json base64: {}", privatekeyJsonBase64);

            return privateKeyJsonString;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public String signWithEcdsaPrivateKey(final String ecdsaPrivateKeyJBase64, final String messageToSign) {
        try {
            byte [] privateKeyByteArray = BaseEncoding.base64().decode(ecdsaPrivateKeyJBase64);
            KeysetHandle privateKeysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(privateKeyByteArray));

            PublicKeySign signer = privateKeysetHandle.getPrimitive(PublicKeySign.class);
            byte[] signature = signer.sign(messageToSign.getBytes());

            String signatureBase64String = BaseEncoding.base64().encode(signature);
            LOGGER.debug("signature in base64: {}", signatureBase64String);

            return signatureBase64String;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void verifySignatureWithEcdsaPublicKey(final String ecdsaPrivateKeyJBase64, final String messageToSign, final String signatureBase64) {
        try {
            byte [] privateKeyByteArray = BaseEncoding.base64().decode(ecdsaPrivateKeyJBase64);
            KeysetHandle privateKeysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(privateKeyByteArray));
            KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();

            PublicKeyVerify verifier = publicKeysetHandle.getPrimitive(PublicKeyVerify.class);
            verifier.verify(BaseEncoding.base64().decode(signatureBase64), messageToSign.getBytes());

            LOGGER.debug("message's signature verified successfully");

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
