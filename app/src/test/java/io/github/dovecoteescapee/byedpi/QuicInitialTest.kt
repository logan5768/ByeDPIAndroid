package io.github.dovecoteescapee.byedpi

import io.github.dovecoteescapee.byedpi.core.QuicInitial
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Проверка вывода клиентских Initial-ключей против эталонного вектора
 * RFC 9001, Appendix A.1 (QUIC v1). Если ключи совпадают — значит HKDF-Extract,
 * HKDF-Expand-Label и соль реализованы верно, и наш QUIC Initial сервер сможет
 * расшифровать (иначе он молча дропнет пакет → ложный QUIC_TIMEOUT).
 */
class QuicInitialTest {

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
    private fun bytes(s: String): ByteArray =
        ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }

    @Test
    fun clientInitialKeysMatchRfc9001() {
        val dcid = bytes("8394c8f03e515708")
        val (secret, key, iv, hp) = QuicInitial.deriveClientKeysForTest(dcid)

        assertEquals(
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
            hex(secret),
        )
        assertEquals("1f369613dd76d5467730efcbe3b1a22d", hex(key))
        assertEquals("fa044b2f42a3fd3b46fb255c", hex(iv))
        assertEquals("9f50449e04a0e810283a1e9933adedd2", hex(hp))
    }
}
