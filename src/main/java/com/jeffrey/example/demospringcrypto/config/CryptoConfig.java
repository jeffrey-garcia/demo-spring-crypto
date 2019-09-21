package com.jeffrey.example.demospringcrypto.config;

import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;
import com.google.crypto.tink.*;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;
import com.jeffrey.example.demospringcrypto.crypto.CryptoClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.ByteArrayOutputStream;

@Configuration
public class CryptoConfig {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoConfig.class);

    @Bean
    @Qualifier("cryptoClient")
    CryptoClient buildCryptoClient() {
        return new CryptoClient() {
            {
                try {
                    TinkConfig.register();
                    AeadConfig.register();
                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }
            }

            @Override
            public String generateNewAesKey() throws RuntimeException {
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
                    String aesKeyJsonBase64String = new String(keyByteArray);
                    LOGGER.debug("aes key json base64: {}", aesKeyJsonBase64String);
                    return aesKeyJsonBase64String;

                } catch (Exception e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            }

            @Override
            public String encryptWithAesKey(final String aesKeyJsonBase64String, final String decipheredText) throws RuntimeException {
                try {
                    byte[] keyByteArray = aesKeyJsonBase64String.getBytes();
                    KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyByteArray));
                    Aead aeadPrimitive = keysetHandle.getPrimitive(Aead.class);
                    String cipheredText = BaseEncoding.base64().encode(aeadPrimitive.encrypt(decipheredText.getBytes(), keyByteArray));
                    LOGGER.debug("ciphered text: {}", cipheredText);
                    return cipheredText;

                } catch (Exception e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            }

            @Override
            public String decryptWithAesKey(final String aesKeyJsonBase64String, final String cipheredText) throws RuntimeException {
                try {
                    byte[] keyByteArray = aesKeyJsonBase64String.getBytes();
                    KeysetHandle keysetHandle = CleartextKeysetHandle.read(JsonKeysetReader.withBytes(keyByteArray));
                    Aead aeadPrimitive = keysetHandle.getPrimitive(Aead.class);
                    String decipheredText = new String(aeadPrimitive.decrypt(BaseEncoding.base64().decode(cipheredText), keyByteArray));
                    LOGGER.debug("deciphered text: {}", decipheredText);
                    return decipheredText;

                } catch (Exception e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            }
        };
    }

}
