package com.example.enc.controller

import com.example.enc.model.entity.KeyStore
import com.example.enc.model.request.PostDecVerifyRequest
import com.example.enc.model.request.PostKeyExchangeRequest
import com.example.enc.model.request.PostSignEncRequest
import com.example.enc.model.response.PostDecVerifyResponse
import com.example.enc.model.response.PostKeyExchangeResponse
import com.example.enc.model.response.PostSignEncResponse
import com.example.enc.repository.KeyStoreRepository
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController
import java.security.SecureRandom
import java.util.*

@RestController
class Controller {

    private val logger: Logger = LoggerFactory.getLogger(Controller::class.java)

    @Autowired
    private lateinit var keyStoreRepository: KeyStoreRepository

    val ByteArray.hex: String
        get() = HexFormat.of().formatHex(this)

    val String.byteArray: ByteArray
        get() = HexFormat.of().parseHex(this)

    val ByteArray.string: String
        get() = String(this)

    @PostMapping("/key-exchange", produces = ["application/json"])
    fun postKeyExchange(
        @RequestHeader("X-Device-ID") deviceId: String,
        @RequestBody request: PostKeyExchangeRequest): PostKeyExchangeResponse {

        // Generate encryption key

        val encKeyPairGenerator = X25519KeyPairGenerator()

        encKeyPairGenerator.init(X25519KeyGenerationParameters(SecureRandom()))

        val encKeyPair = encKeyPairGenerator.generateKeyPair()

        val encServerPrivKey = (encKeyPair.private as X25519PrivateKeyParameters).encoded.hex
        val encServerPubKey = (encKeyPair.public as X25519PublicKeyParameters).encoded.hex

        // Generate sign key

        val signKeyPairGenerator = Ed25519KeyPairGenerator()

        signKeyPairGenerator.init(Ed25519KeyGenerationParameters(SecureRandom()))

        val signKeyPair = signKeyPairGenerator.generateKeyPair()

        val signServerPrivKey = (signKeyPair.private as Ed25519PrivateKeyParameters).encoded.hex
        val signServerPubKey = (signKeyPair.public as Ed25519PublicKeyParameters).encoded.hex

        val keyStore = KeyStore(
            deviceId = deviceId,
            signClientPubKey = request.signClientPubKey,
            signClientPrivKey = request.signClientPrivKey,
            encClientPubKey = request.encClientPubKey,
            encClientPrivKey = request.encClientPrivKey,
            encServerPubKey = encServerPubKey,
            encServerPrivKey = encServerPrivKey,
            signServerPubKey = signServerPubKey,
            signServerPrivKey = signServerPrivKey
        )

        keyStoreRepository.save(keyStore)

        return PostKeyExchangeResponse(
            signClientPubKey = request.signClientPubKey,
            signClientPrivKey = request.signClientPrivKey,
            encClientPubKey = request.encClientPubKey,
            encClientPrivKey = request.encClientPrivKey,
            encServerPubKey = encServerPubKey,
            encServerPrivKey = encServerPrivKey,
            signServerPubKey = signServerPubKey,
            signServerPrivKey = signServerPrivKey
        )

    }

    @PostMapping("/sign-enc", produces = ["application/json"])
    fun postSignEnc(
        @RequestHeader("X-Device-ID") deviceId: String,
        @RequestBody request: PostSignEncRequest): PostSignEncResponse {

        val keyStore = keyStoreRepository.findById(deviceId)
            .orElseThrow { throw Exception("Key not found") }

        val signature = signMessage(keyStore.signServerPrivKey.byteArray, request.plaintext.toByteArray())

        val (nonce, ciphertext) = encrypt(keyStore.encServerPrivKey.byteArray, keyStore.encClientPubKey.byteArray, signature)

        return PostSignEncResponse(nonce.hex, ciphertext.hex)

    }

    @PostMapping("/dec-verify", produces = ["application/json"])
    fun postDecVerify(
        @RequestHeader("X-Device-ID") deviceId: String,
        @RequestBody request: PostDecVerifyRequest): PostDecVerifyResponse {

        val keyStore = keyStoreRepository.findById(deviceId)
            .orElseThrow { throw Exception("Key not found") }

        val signature = decrypt(keyStore.encServerPrivKey.byteArray, keyStore.encClientPubKey.byteArray, request.nonce.byteArray, request.ciphertext.byteArray)

        val plaintext = verifySignature(keyStore.signClientPubKey.byteArray, signature)

        return PostDecVerifyResponse(plaintext.string)

    }

    @PostMapping("/mobile-sign-enc", produces = ["application/json"])
    fun postMobileSignEnc(
        @RequestHeader("X-Device-ID") deviceId: String,
        @RequestBody request: PostSignEncRequest): PostSignEncResponse {

        val keyStore = keyStoreRepository.findById(deviceId)
            .orElseThrow { throw Exception("Key not found") }

        val signature = signMessage(keyStore.signClientPrivKey.byteArray, request.plaintext.toByteArray())

        val (nonce, ciphertext) = encrypt(keyStore.encClientPrivKey.byteArray, keyStore.encServerPubKey.byteArray, signature)

        return PostSignEncResponse(nonce.hex, ciphertext.hex)

    }

    @PostMapping("/mobile-dec-verify", produces = ["application/json"])
    fun postMobileDecVerify(
        @RequestHeader("X-Device-ID") deviceId: String,
        @RequestBody request: PostDecVerifyRequest): PostDecVerifyResponse {

        val keyStore = keyStoreRepository.findById(deviceId)
            .orElseThrow { throw Exception("Key not found") }

        val signature = decrypt(keyStore.encClientPrivKey.byteArray, keyStore.encServerPubKey.byteArray, request.nonce.byteArray, request.ciphertext.byteArray)

        val plaintext = verifySignature(keyStore.signServerPubKey.byteArray, signature)

        return PostDecVerifyResponse(plaintext.string)

    }

    fun scalarMult(encPrivateKey: ByteArray, encPublicKey: ByteArray): ByteArray {

        // Generate shared key

        val privateKey = X25519PrivateKeyParameters(encPrivateKey)
        val publicKey = X25519PublicKeyParameters(encPublicKey)

        val agreement = X25519Agreement()
        agreement.init(privateKey)

        val sharedKey = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(publicKey, sharedKey, 0)

        println("[Scalar Multiplication, shared-key] \t${sharedKey.hex}")
        logger.info("[Scalar Multiplication, shared-key] \t${sharedKey.hex}")

        return sharedKey

    }

    fun signMessage(signPrivateKey: ByteArray, plaintext: ByteArray): ByteArray {

        // Sign message

        val signer = Ed25519Signer()

        signer.init(true, Ed25519PrivateKeyParameters(signPrivateKey))

        signer.update(plaintext, 0, plaintext.size)

        val signature = signer.generateSignature()

        println("[Message Signing, signed-message] \t\t${(signature + plaintext).hex}")
        logger.info("[Message Signing, signed-message] \t\t${(signature + plaintext).hex}")

        return signature + plaintext

    }

    fun encrypt(encPrivateKey: ByteArray, encPublicKey: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {

        // Encrypt message

        val sharedKey = scalarMult(encPrivateKey, encPublicKey)

        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)

        val cipher = GCMBlockCipher(AESEngine())
        val parameters = KeyParameter(sharedKey)
        val aeadParameters = AEADParameters(parameters, 128, nonce, null)

        cipher.init(true, aeadParameters)

        val ciphertext = ByteArray(cipher.getOutputSize(plaintext.size))
        val len = cipher.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)

        cipher.doFinal(ciphertext, len)

        println("[Encrypt, nonce] \t\t\t\t\t\t${nonce.hex}")
        logger.info("[Encrypt, nonce] \t\t\t\t\t\t${nonce.hex}")
        println("[Encrypt, encrypted-message] \t\t\t${ciphertext.hex}")
        logger.info("[Encrypt, encrypted-message] \t\t\t${ciphertext.hex}")

        return Pair(nonce, ciphertext)

    }

    fun decrypt(privateKey: ByteArray, publicKey: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray {

        // Decrypt message

        val sharedKey = scalarMult(privateKey, publicKey)

        val cipher = GCMBlockCipher(AESEngine())
        val parameters = KeyParameter(sharedKey)
        val aeadParameters = AEADParameters(parameters, 128, nonce, null)

        cipher.init(false, aeadParameters)

        val plaintext = ByteArray(cipher.getOutputSize(ciphertext.size))
        val len = cipher.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)

        cipher.doFinal(plaintext, len)

        println("[Decrypt, nonce] \t\t\t\t\t\t${nonce.hex}")
        logger.info("[Decrypt, nonce] \t\t\t\t\t\t${nonce.hex}")
        println("[Decrypt, encrypted-message] \t\t\t${plaintext.hex}")
        logger.info("[Decrypt, encrypted-message] \t\t\t${plaintext.hex}")

        return plaintext

    }

    fun verifySignature(signPublicKey: ByteArray, plaintext: ByteArray): ByteArray {

        // Verify signature

        val signature = plaintext.copyOfRange(0, Ed25519PrivateKeyParameters.SIGNATURE_SIZE)
        val message = plaintext.copyOfRange(Ed25519PrivateKeyParameters.SIGNATURE_SIZE, plaintext.size)

        val verifier = Ed25519Signer()

        verifier.init(false, Ed25519PublicKeyParameters(signPublicKey))

        verifier.update(message, 0, message.size)

        val isVerified = verifier.verifySignature(signature)

        if (isVerified) {

            println("[Signature Verification, message] \t\t${message.string}")
            logger.info("[Signature Verification, message] \t\t${message.string}")

            return message

        } else {

            throw Exception("Signature verification failed")

        }

    }

}