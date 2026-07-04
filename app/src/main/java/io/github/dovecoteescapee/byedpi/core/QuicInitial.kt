package io.github.dovecoteescapee.byedpi.core

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Строит НАСТОЯЩИЙ QUIC Initial-пакет (QUIC v1, RFC 9000 + RFC 9001) с реальным
 * TLS 1.3 ClientHello, несущим заданный SNI.
 *
 * ЗАЧЕМ. Раньше QUIC-проба слала Version-Negotiation-пакет без SNI — DPI такой
 * пакет не за что резать, поэтому проба давала ложный OK даже там, где реальное
 * видео (googlevideo по UDP-443) блокируется. Честная проба несёт SNI внутри
 * зашифрованного Initial: DPI, который читает QUIC-Initial (ключи выводятся из
 * ОТКРЫТОГО DCID), увидит SNI и дропнет — и проба честно упадёт. Если DPI не
 * дропнул, сервер ответит Retry/Initial — получаем датаграмму = путь открыт.
 *
 * РАСШИРЯЕМОСТЬ. Всё собирается вручную из байт, поэтому сюда легко добавлять
 * SNI-трюки (padding в ClientHello, разбиение CRYPTO-фрейма на несколько,
 * фейковый SNI + реальный, изменение порядка расширений) по мере эволюции DPI.
 */
object QuicInitial {

    // Соль для вывода Initial-секретов, QUIC v1 (RFC 9001, §5.2).
    private val INITIAL_SALT = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    private const val VERSION_1 = 0x00000001
    private const val DATAGRAM_SIZE = 1200      // минимум для Initial (анти-амплификация)
    private const val PN_LEN = 4                // длина номера пакета (фикс, упрощает HP-сэмпл)

    private val rnd = SecureRandom()

    /** Готовый к отправке QUIC Initial с указанным SNI. */
    fun build(sni: String): ByteArray {
        val dcid = ByteArray(8).also { rnd.nextBytes(it) }
        val scid = ByteArray(8).also { rnd.nextBytes(it) }

        // 1. Ключи Initial из DCID (клиентское направление).
        val initialSecret = hkdfExtract(INITIAL_SALT, dcid)
        val clientSecret = hkdfExpandLabel(initialSecret, "client in", 32)
        val key = hkdfExpandLabel(clientSecret, "quic key", 16)
        val iv = hkdfExpandLabel(clientSecret, "quic iv", 12)
        val hp = hkdfExpandLabel(clientSecret, "quic hp", 16)

        // 2. ClientHello → CRYPTO-фрейм → PADDING до нужного размера.
        val ch = clientHello(sni, scid)
        val header = ByteArrayOutputStream()
        // headerBeforeLength: firstByte(1)+version(4)+dcidlen(1)+dcid(8)+scidlen(1)+scid(8)+tokenlen(1)=24
        val firstByte = (0xC0 or (PN_LEN - 1))          // long header, тип Initial, длина PN
        header.write(firstByte)
        writeUint32(header, VERSION_1)
        header.write(dcid.size); header.write(dcid)
        header.write(scid.size); header.write(scid)
        header.write(0)                                  // token length = 0 (varint)

        // plaintext = CRYPTO(0x06) + offset(0) + length(CHlen) + CH + PADDING(0x00…)
        val cryptoOverhead = 1 + 1 + 2                   // type + offset-varint(0) + len-varint(2 байта)
        val plaintextLen = DATAGRAM_SIZE - 24 - 2 - PN_LEN - 16   // 2 = 2-байтовый varint Length
        val payload = ByteArrayOutputStream()
        payload.write(0x06)                              // CRYPTO frame
        payload.write(0x00)                              // offset = 0 (varint)
        writeVarint(payload, ch.size.toLong())           // length CH (2-байтовый varint, CH>63)
        payload.write(ch)
        val padding = plaintextLen - cryptoOverhead - ch.size
        require(padding >= 0) { "ClientHello too large: ${ch.size}" }
        payload.write(ByteArray(padding))                // PADDING = нулевые байты
        val plaintext = payload.toByteArray()

        // 3. Length = PN_LEN + len(ciphertext); ciphertext = plaintext + 16 (GCM-тег).
        val lengthValue = (PN_LEN + plaintext.size + 16).toLong()
        writeVarint2(header, lengthValue)                // ровно 2 байта varint
        val pnBytes = byteArrayOf(0, 0, 0, 0)            // packet number = 0, 4 байта
        header.write(pnBytes)
        val aad = header.toByteArray()                   // заголовок = associated data для AEAD

        // 4. AEAD-шифрование payload. nonce = iv XOR pn (pn=0 → nonce=iv).
        val nonce = iv.copyOf()
        val ciphertext = aesGcmEncrypt(key, nonce, plaintext, aad)

        // 5. Header protection: маска из AES-ECB по сэмплу ciphertext.
        val sample = ciphertext.copyOfRange(0, 16)       // сэмпл со смещения pn_offset+4 = начало ct
        val mask = aesEcb(hp, sample)
        val out = aad.copyOf()
        out[0] = (out[0].toInt() xor (mask[0].toInt() and 0x0f)).toByte()   // low 4 бита (long header)
        val pnOffset = aad.size - PN_LEN
        for (i in 0 until PN_LEN) {
            out[pnOffset + i] = (out[pnOffset + i].toInt() xor mask[1 + i].toInt()).toByte()
        }

        return out + ciphertext
    }

    // ---- TLS 1.3 ClientHello ---------------------------------------------

    private fun clientHello(sni: String, scid: ByteArray): ByteArray {
        val body = ByteArrayOutputStream()
        writeUint16(body, 0x0303)                        // legacy_version = TLS 1.2
        body.write(ByteArray(32).also { rnd.nextBytes(it) })  // random
        body.write(0)                                    // legacy_session_id: пусто
        // cipher_suites: AES128-GCM, AES256-GCM, CHACHA20
        writeUint16(body, 6)
        writeUint16(body, 0x1301); writeUint16(body, 0x1302); writeUint16(body, 0x1303)
        body.write(1); body.write(0)                     // compression: [null]

        val ext = ByteArrayOutputStream()
        // server_name (0x0000)
        run {
            val name = sni.toByteArray(Charsets.US_ASCII)
            val d = ByteArrayOutputStream()
            writeUint16(d, name.size + 3)                // ServerNameList length
            d.write(0x00)                                // host_name
            writeUint16(d, name.size); d.write(name)
            writeExt(ext, 0x0000, d.toByteArray())
        }
        // supported_groups (0x000a): x25519
        run {
            val d = ByteArrayOutputStream(); writeUint16(d, 2); writeUint16(d, 0x001d)
            writeExt(ext, 0x000a, d.toByteArray())
        }
        // signature_algorithms (0x000d)
        run {
            val d = ByteArrayOutputStream(); writeUint16(d, 6)
            writeUint16(d, 0x0403); writeUint16(d, 0x0804); writeUint16(d, 0x0401)
            writeExt(ext, 0x000d, d.toByteArray())
        }
        // supported_versions (0x002b): TLS 1.3
        run {
            val d = ByteArrayOutputStream(); d.write(2); writeUint16(d, 0x0304)
            writeExt(ext, 0x002b, d.toByteArray())
        }
        // key_share (0x0033): x25519 со случайным (пробе достаточно ответа/Retry)
        run {
            val d = ByteArrayOutputStream()
            writeUint16(d, 36)                           // client_shares length
            writeUint16(d, 0x001d); writeUint16(d, 32)
            d.write(ByteArray(32).also { rnd.nextBytes(it) })
            writeExt(ext, 0x0033, d.toByteArray())
        }
        // ALPN (0x0010): h3
        run {
            val d = ByteArrayOutputStream(); writeUint16(d, 3); d.write(2); d.write("h3".toByteArray())
            writeExt(ext, 0x0010, d.toByteArray())
        }
        // quic_transport_parameters (0x0039): initial_source_connection_id = SCID
        run {
            val d = ByteArrayOutputStream()
            writeVarint(d, 0x0f)                          // initial_source_connection_id
            writeVarint(d, scid.size.toLong()); d.write(scid)
            writeExt(ext, 0x0039, d.toByteArray())
        }

        val extBytes = ext.toByteArray()
        writeUint16(body, extBytes.size); body.write(extBytes)

        val b = body.toByteArray()
        val hs = ByteArrayOutputStream()
        hs.write(0x01)                                   // handshake type = ClientHello
        writeUint24(hs, b.size); hs.write(b)
        return hs.toByteArray()
    }

    private fun writeExt(out: ByteArrayOutputStream, type: Int, data: ByteArray) {
        writeUint16(out, type); writeUint16(out, data.size); out.write(data)
    }

    // ---- HKDF (RFC 5869 + TLS 1.3 HkdfLabel) -----------------------------

    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        return mac.doFinal(ikm)
    }

    private fun hkdfExpandLabel(prk: ByteArray, label: String, length: Int): ByteArray {
        val full = "tls13 $label".toByteArray(Charsets.US_ASCII)
        val info = ByteArrayOutputStream()
        writeUint16(info, length)
        info.write(full.size); info.write(full)
        info.write(0)                                    // context пустой
        return hkdfExpand(prk, info.toByteArray(), length)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var i = 1
        while (out.size() < length) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t); mac.update(info); mac.update(i.toByte())
            t = mac.doFinal()
            out.write(t)
            i++
        }
        return out.toByteArray().copyOf(length)
    }

    // ---- AEAD / HP -------------------------------------------------------

    private fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, pt: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return c.doFinal(pt)
    }

    private fun aesEcb(key: ByteArray, block: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(block)
    }

    // ---- варинты / big-endian --------------------------------------------

    private fun writeUint16(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 8) and 0xff); out.write(v and 0xff)
    }

    private fun writeUint24(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 16) and 0xff); out.write((v ushr 8) and 0xff); out.write(v and 0xff)
    }

    private fun writeUint32(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 24) and 0xff); out.write((v ushr 16) and 0xff)
        out.write((v ushr 8) and 0xff); out.write(v and 0xff)
    }

    /** QUIC-varint минимальной длины. */
    private fun writeVarint(out: ByteArrayOutputStream, v: Long) {
        when {
            v < 0x40 -> out.write(v.toInt())
            v < 0x4000 -> writeVarint2(out, v)
            v < 0x40000000 -> {
                out.write(((v ushr 24) or 0x80).toInt() and 0xff)
                out.write((v ushr 16).toInt() and 0xff)
                out.write((v ushr 8).toInt() and 0xff); out.write(v.toInt() and 0xff)
            }
            else -> {
                out.write(((v ushr 56) or 0xC0).toInt() and 0xff)
                for (s in intArrayOf(48, 40, 32, 24, 16, 8, 0)) out.write((v ushr s).toInt() and 0xff)
            }
        }
    }

    /** QUIC-varint РОВНО в 2 байта (префикс 0x40) — для поля Length фикс-размера. */
    private fun writeVarint2(out: ByteArrayOutputStream, v: Long) {
        out.write((((v ushr 8) and 0x3f) or 0x40).toInt()); out.write(v.toInt() and 0xff)
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }

    /**
     * Тест-хук: клиентские Initial-ключи по DCID [secret, key, iv, hp].
     * Проверяется юнит-тестом против эталонного вектора RFC 9001 (Appendix A.1),
     * чтобы гарантировать корректность вывода ключей (иначе сервер не ответит и
     * проба даст ложный QUIC_TIMEOUT — так же плохо, как старый ложный OK).
     */
    internal fun deriveClientKeysForTest(dcid: ByteArray): Array<ByteArray> {
        val initialSecret = hkdfExtract(INITIAL_SALT, dcid)
        val clientSecret = hkdfExpandLabel(initialSecret, "client in", 32)
        return arrayOf(
            clientSecret,
            hkdfExpandLabel(clientSecret, "quic key", 16),
            hkdfExpandLabel(clientSecret, "quic iv", 12),
            hkdfExpandLabel(clientSecret, "quic hp", 16),
        )
    }
}
