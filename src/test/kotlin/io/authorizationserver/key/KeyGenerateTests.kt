package io.authorizationserver.key

import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Base64

class KeyGenerateTests {


    @Test
    fun generateTests() {
        val keyPair = generateRSAKeyPair()

        val publicKey = keyPair.public
        val privateKey = keyPair.private

        val publicKeyEncoded = Base64.getEncoder().encodeToString(publicKey.encoded)
        val privateKeyEncoded = Base64.getEncoder().encodeToString(privateKey.encoded)

        println("Public Key:")
        println(publicKeyEncoded)
        println("\nPrivate Key:")
        println(privateKeyEncoded)    }

    fun generateRSAKeyPair(keySize: Int = 2048): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize)
        return keyPairGenerator.generateKeyPair()
    }

}