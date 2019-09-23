package com.jeffrey.example.demospringcrypto.controller;

import com.jeffrey.example.demospringcrypto.service.CryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class MainController {

    private static final Logger LOGGER = LoggerFactory.getLogger(MainController.class);

    @Autowired
    private CryptoService cryptoService;

    /**
     * curl "http://localhost:8080/aesKey" -i -X GET
     */
    @GetMapping(path="/aesKey")
    public @ResponseBody String getAesKey() {
        LOGGER.debug("getAesKey");
        return cryptoService.generateAesKey();
    }

    /**
     * curl 'http://localhost:8080/aesEncrypt' -i -X POST -H "Content-Type: application/json" -d '{"aesKeyBase64":"ewogICAgInByaW1hcnlLZXlJZCI6IDI3NDE0NTE5NSwKICAgICJrZXkiOiBbewogICAgICAgICJrZXlEYXRhIjogewogICAgICAgICAgICAidHlwZVVybCI6ICJ0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkiLAogICAgICAgICAgICAia2V5TWF0ZXJpYWxUeXBlIjogIlNZTU1FVFJJQyIsCiAgICAgICAgICAgICJ2YWx1ZSI6ICJHaUNzRUs0K3BsWEVQYjJpajRaUWZXZGZrQzcxZ2ozRFAwRGZ4TGhUTUk2T1l3PT0iCiAgICAgICAgfSwKICAgICAgICAib3V0cHV0UHJlZml4VHlwZSI6ICJUSU5LIiwKICAgICAgICAia2V5SWQiOiAyNzQxNDUxOTUsCiAgICAgICAgInN0YXR1cyI6ICJFTkFCTEVEIgogICAgfV0KfQ==","decipheredText":"123"}'
     * curl 'http://localhost:8080/aesEncrypt' -i -X POST -H "Content-Type: application/json" -d '{"aesKeyBase64":"YTkyMDcyNmQtYWE4YS00Njk1LTkzZjktZjIxMWM4OWMwOTMxYmE0ZTJkMTktMGEyMi00ZDU0LWJhYmQtZWFlODk4OTFiNDY5","decipheredText":"123"}'
     */
    @PostMapping(path="/aesEncrypt")
    public @ResponseBody String aesEncrypt(@RequestBody Map<String,String> requestBodyMap) {
        LOGGER.debug("aesEncrypt");

        String aesKeyBase64 = requestBodyMap.get("aesKeyBase64");
        String decipheredText = requestBodyMap.get("decipheredText");

        Assert.notNull(aesKeyBase64, "aesKeyBase64 should not be null");
        Assert.notNull(decipheredText, "decipheredText should not be null");

        return cryptoService.encryptMessageWithAes(aesKeyBase64, decipheredText);
    }

    /**
     * curl 'http://localhost:8080/aesDecrypt' -i -X POST -H "Content-Type: application/json" -d '{"aesKeyBase64":"ewogICAgInByaW1hcnlLZXlJZCI6IDI3NDE0NTE5NSwKICAgICJrZXkiOiBbewogICAgICAgICJrZXlEYXRhIjogewogICAgICAgICAgICAidHlwZVVybCI6ICJ0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNHY21LZXkiLAogICAgICAgICAgICAia2V5TWF0ZXJpYWxUeXBlIjogIlNZTU1FVFJJQyIsCiAgICAgICAgICAgICJ2YWx1ZSI6ICJHaUNzRUs0K3BsWEVQYjJpajRaUWZXZGZrQzcxZ2ozRFAwRGZ4TGhUTUk2T1l3PT0iCiAgICAgICAgfSwKICAgICAgICAib3V0cHV0UHJlZml4VHlwZSI6ICJUSU5LIiwKICAgICAgICAia2V5SWQiOiAyNzQxNDUxOTUsCiAgICAgICAgInN0YXR1cyI6ICJFTkFCTEVEIgogICAgfV0KfQ==","cipheredTextBase64":"ARBXH6t5GVkWhDGSPBF2dkvJU1u+zQ8OfQsD6wJ9w+otYP9T"}'
     * curl 'http://localhost:8080/aesDecrypt' -i -X POST -H "Content-Type: application/json" -d '{"aesKeyBase64":"YTkyMDcyNmQtYWE4YS00Njk1LTkzZjktZjIxMWM4OWMwOTMxYmE0ZTJkMTktMGEyMi00ZDU0LWJhYmQtZWFlODk4OTFiNDY5","cipheredTextBase64":"dDiIuniFpsqK7aKVUKGwgRml6sRoZ02BuzlX8l4o8w9yG7w="}'
     */
    @PostMapping(path="/aesDecrypt")
    public @ResponseBody String aesDecrypt(@RequestBody Map<String,String> requestBodyMap) {
        LOGGER.debug("aesDecrypt");

        String aesKeyBase64 = requestBodyMap.get("aesKeyBase64");
        String cipheredTextBase64 = requestBodyMap.get("cipheredTextBase64");

        Assert.notNull(aesKeyBase64, "aesKeyBase64 should not be null");
        Assert.notNull(cipheredTextBase64, "cipheredTextBase64 should not be null");

        return cryptoService.decryptMessageWithAes(aesKeyBase64, cipheredTextBase64);
    }

    /**
     * curl "http://localhost:8080/ecdsaKeyPair" -i -X GET
     */
    @GetMapping(path="/ecdsaKeyPair")
    public @ResponseBody String getEcdsaKeyPair() {
        LOGGER.debug("getEcdsaKeyPair");
        return cryptoService.generateEcdsaKeyPair();
    }

    /**
     * curl 'http://localhost:8080/ecdsaSign' -i -X POST -H "Content-Type: application/json" -d '{"ecdsaPrivateKeyBase64":"ewogICAgInByaW1hcnlLZXlJZCI6IDE4MjExMjExMTAsCiAgICAia2V5IjogW3sKICAgICAgICAia2V5RGF0YSI6IHsKICAgICAgICAgICAgInR5cGVVcmwiOiAidHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuRWNkc2FQcml2YXRlS2V5IiwKICAgICAgICAgICAgImtleU1hdGVyaWFsVHlwZSI6ICJBU1lNTUVUUklDX1BSSVZBVEUiLAogICAgICAgICAgICAidmFsdWUiOiAiRWswU0JnZ0RFQUlZQWhvZ2N2bkpHb205YldiVzdDbzZPY3Bna21jei8rT2p3TVp1VFg4Vm9qVXRHWEFpSVFDZkk4N0hQT0tDZDQ0MFdsdnJPZU9oT3RJVDZZblVEWU9wUG8xWUhvRTlEaG9nS1FIVGJ0VUVsRnMzMlRCMWFpaHFCcU5LaHRMZ3hUeEF4T0NudFNhU2dZVT0iCiAgICAgICAgfSwKICAgICAgICAib3V0cHV0UHJlZml4VHlwZSI6ICJUSU5LIiwKICAgICAgICAia2V5SWQiOiAxODIxMTIxMTEwLAogICAgICAgICJzdGF0dXMiOiAiRU5BQkxFRCIKICAgIH1dCn0=","message":"123"}'
     */
    @PostMapping(path="/ecdsaSign")
    public @ResponseBody String ecdsaSign(@RequestBody Map<String,String> requestBodyMap) {
        LOGGER.debug("ecdsaSign");

        String ecdsaPrivateKeyBase64 = requestBodyMap.get("ecdsaPrivateKeyBase64");
        String message = requestBodyMap.get("message");

        Assert.notNull(ecdsaPrivateKeyBase64, "ecdsaPrivateKeyBase64 should not be null");
        Assert.notNull(message, "message should not be null");

        return cryptoService.signMessageWithEcdsa(ecdsaPrivateKeyBase64, message);
    }

    /**
     * curl 'http://localhost:8080/ecdsaVerify' -i -X POST -H "Content-Type: application/json" -d '{"ecdsaPrivateKeyBase64":"ewogICAgInByaW1hcnlLZXlJZCI6IDE4MjExMjExMTAsCiAgICAia2V5IjogW3sKICAgICAgICAia2V5RGF0YSI6IHsKICAgICAgICAgICAgInR5cGVVcmwiOiAidHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuRWNkc2FQcml2YXRlS2V5IiwKICAgICAgICAgICAgImtleU1hdGVyaWFsVHlwZSI6ICJBU1lNTUVUUklDX1BSSVZBVEUiLAogICAgICAgICAgICAidmFsdWUiOiAiRWswU0JnZ0RFQUlZQWhvZ2N2bkpHb205YldiVzdDbzZPY3Bna21jei8rT2p3TVp1VFg4Vm9qVXRHWEFpSVFDZkk4N0hQT0tDZDQ0MFdsdnJPZU9oT3RJVDZZblVEWU9wUG8xWUhvRTlEaG9nS1FIVGJ0VUVsRnMzMlRCMWFpaHFCcU5LaHRMZ3hUeEF4T0NudFNhU2dZVT0iCiAgICAgICAgfSwKICAgICAgICAib3V0cHV0UHJlZml4VHlwZSI6ICJUSU5LIiwKICAgICAgICAia2V5SWQiOiAxODIxMTIxMTEwLAogICAgICAgICJzdGF0dXMiOiAiRU5BQkxFRCIKICAgIH1dCn0=","message":"123","signatureBase64":"AWyMGlYwRQIhANg4aNMdARECRSwz3NNI8ia9O1mEL0+9fisjEW48CI4HAiBLmmncaoEIvsiHuG53QAIrKyEYKLhs9j6F32INUVXuPw=="}'
     */
    @PostMapping(path="/ecdsaVerify")
    public @ResponseBody ResponseEntity ecdsaVerify(@RequestBody Map<String,String> requestBodyMap) {
        LOGGER.debug("ecdsaVerify");

        String ecdsaPrivateKeyBase64 = requestBodyMap.get("ecdsaPrivateKeyBase64");
        String message = requestBodyMap.get("message");
        String signatureBase64 = requestBodyMap.get("signatureBase64");

        Assert.notNull(ecdsaPrivateKeyBase64, "ecdsaPrivateKeyBase64 should not be null");
        Assert.notNull(message, "message should not be null");
        Assert.notNull(signatureBase64, "signatureBase64 should not be null");

        cryptoService.verifyMessageWithEcdsa(ecdsaPrivateKeyBase64, message, signatureBase64);
        return ResponseEntity.ok().build();
    }
}
