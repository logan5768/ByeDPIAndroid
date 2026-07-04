package io.github.dovecoteescapee.byedpi.core

import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.PortUnreachableException
import java.net.Proxy
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Единый словарь причин дропа. Описание каждого кода — в HTML-карте (ветка «Дропы и логи»).
 */
enum class DropCause {
    OK,
    DNS_FAIL,
    CONNECT_TIMEOUT,
    TCP_RST,
    TLS_TIMEOUT,
    TLS_HANDSHAKE_FAIL,
    // Хендшейк TLS ПРОШЁЛ (SNI пробился сквозь DPI), но HTTP-ответ не пришёл.
    // Это «почти работает»: десинк победил блокировку SNI, осталась мелочь.
    HTTP_TIMEOUT,
    HTTP_BLOCKPAGE,
    // Медиа-URL ответил HTTP, но не 200/206 (обычно 403/410): ссылка протухла или
    // привязана к другому IP. Это НЕ вина DPI — надо обновить ссылку.
    MEDIA_URL_DEAD,
    QUIC_TIMEOUT,
    QUIC_DROP,
    PROXY_FAIL,
}

/**
 * Роль цели в вердикте:
 *  PAGE    — страница YouTube (должна открыться, иначе смотреть негде).
 *  VIDEO   — сам ролик (*.googlevideo.com). Достаточно ЛЮБОГО живого транспорта:
 *            QUIC (UDP-443) ИЛИ TLS (TCP). На разных сетях режется то одно, то
 *            другое — берём тот путь, что здесь проходит.
 *  CONTROL — позитивный контроль (yandex): на вердикт не влияет, ловит «нет сети/
 *            тестер врёт».
 */
enum class TargetRole { PAGE, VIDEO, CONTROL }

/**
 * Цель проверки (один SNI + транспорт).
 *  mediaPath — если задан (для VIDEO/TLS), проба не HEAD, а ranged-GET реального
 *  сегмента: тянем MEDIA_BYTES_NEEDED байт. Это и есть 100% критерий видеопотока.
 */
data class Target(
    val host: String,
    val role: TargetRole,
    val udp: Boolean = false,
    val mediaPath: String? = null,
)

/** Результат пробы одной цели (один SNI). */
data class ProbeResult(
    val host: String,
    val proto: String,
    val ok: Boolean,
    val cause: DropCause,
    val ms: Long,
)

/**
 * Агрегированный результат одного кандидата (набора флагов ByeDPI).
 *  flags        — что тестировали (desync-флаги без слушателя).
 *  flagsToApply — что реально применять: если видео победило ТОЛЬКО по TLS, сюда
 *                 добавляется `-U` (--no-udp), чтобы приложение не долбилось в
 *                 мёртвый QUIC, а сразу шло по TCP. Если победил QUIC — равно flags.
 *  videoVia     — «QUIC» / «TLS» / «—» (каким транспортом пробилось видео).
 */
data class CandidateResult(
    val flags: String,
    val ok: Boolean,
    val cause: DropCause,
    val ms: Long,
    val probes: List<ProbeResult>,
    val flagsToApply: String = flags,
    val videoVia: String = "—",
)

/**
 * Прямая ссылка на медиасегмент YouTube (googlevideo). host — конкретный CDN-edge
 * (rrN---sn-xxxx.googlevideo.com), path — путь `/videoplayback?...` со всей query.
 * Добывается один раз на сессию (YtStream.fetchPlayback) и переиспользуется всеми
 * кандидатами: сам байтопоток гоняем через прокси, а тяжёлое извлечение — один раз.
 */
data class PlaybackUrl(val host: String, val path: String)

/**
 * Перебирает наборы флагов ByeDPI и проверяет, открывается ли YouTube.
 *
 * Каждый кандидат проверяется СТРОГО последовательно: нативные params в ByeDPI
 * глобальны, поэтому одновременно может работать только один прокси.
 *
 * Изоляция DNS от DPI: имя цели резолвится нами заранее по обычной сети
 * (UnknownHostException → DNS_FAIL), а коннект через SOCKS идёт уже по IP —
 * так провал DNS не маскируется под провал обхода.
 */
class ByeDpiTester(
    private val testPort: Int = 10080,
    val targets: List<Target> = DEFAULT_TARGETS,
    // perProbeTimeoutMs — ОДНОВРЕМЕННО и таймаут пробы (обрубаем слишком долгие
    // попытки), и верхняя граница диагностического ms. Это НЕ критерий выбора.
    // 2500мс: рабочий флаг отвечает за сотни мс, а мёртвый всё равно ждать нет смысла —
    // урезали с 5000, чтобы неудачный кандидат не съедал по 5с на каждую пробу.
    private val perProbeTimeoutMs: Int = 2500,
) {
    companion object {
        private const val TAG = "ByeDpiTester"

        // АДАПТИВНЫЙ критерий (подтверждён замерами на реальном DPI):
        //   PAGE  = www.youtube.com/TLS — страница, обязана открыться;
        //   VIDEO = redirector.googlevideo.com, ЛЮБЫМ транспортом:
        //           QUIC (UDP-443) ИЛИ TLS (TCP). На этой сети googlevideo/TLS почти
        //           весь в блэкхоле (6%), а googlevideo/QUIC пробивается втрое чаще
        //           (25%) с -a-фейком; на «форс-TCP»-сетях — наоборот. Берём тот путь,
        //           что здесь жив, и под него подгоняем применяемый флаг (см. -U).
        //   CONTROL = yandex.ru — на вердикт не влияет, ловит «нет сети/тестер врёт».
        // Обе видео-пробы шлют НАСТОЯЩИЙ SNI (googlevideo@смещение 11) — проверка
        // позиционной независимости десинка (fix-смещение под youtube тут не пройдёт).
        val DEFAULT_TARGETS = listOf(
            Target("yandex.ru", TargetRole.CONTROL, udp = false),
            Target("www.youtube.com", TargetRole.PAGE, udp = false),
            Target("redirector.googlevideo.com", TargetRole.VIDEO, udp = false),
            Target("redirector.googlevideo.com", TargetRole.VIDEO, udp = true),
        )

        // Критерий «видео поехало»: сколько РЕАЛЬНЫХ байт медиа надо вытянуть сквозь
        // прокси, чтобы засчитать. Скорость НЕ меряем (это обходчик DPI, а не тоннель —
        // локальнее прокси всё равно не будет; важен факт, что байтопоток googlevideo
        // пробился). 32 КБ достаточно, чтобы отличить «поток пошёл» от «RST/блокстраница».
        private const val MEDIA_MIN_BYTES = 32 * 1024
        private const val MEDIA_RANGE = 128 * 1024
        private const val MEDIA_UA =
            "com.google.android.youtube/19.09.37 (Linux; U; Android 11) gzip"
    }

    private val sslFactory: SSLSocketFactory =
        SSLContext.getInstance("TLS").apply { init(null, null, null) }.socketFactory

    // Свежий видеосегмент-URL рикролла на текущую сессию (обновляется программно через
    // YtStream.fetchPlayback на каждый прогон — сам URL живёт ~6ч, но мы берём новый).
    // null = не добыли → VIDEO/TLS откатывается на старый критерий (SNI-хендшейк).
    @Volatile
    var videoUrl: PlaybackUrl? = null

    /**
     * Контрольный замер ДО перебора: без прокси, напрямую. Возвращает пробы В
     * ПОРЯДКЕ [targets] — вызывающий сам форматирует (единый вид с кандидатами).
     */
    suspend fun baseline(): List<ProbeResult> = coroutineScope {
        // Цели независимы — гоняем параллельно (быстрее в N раз).
        targets.map { t ->
            async(Dispatchers.IO) { probeDirectFor(t) }
        }.awaitAll()
    }

    /** Диспетчер прямой (без прокси) пробы: видео тянем реальным медиа-GET, если есть URL. */
    private suspend fun probeDirectFor(t: Target): ProbeResult {
        val pv = videoUrl
        return when {
            t.role == TargetRole.VIDEO && pv != null && !t.udp -> probeMedia(pv.host, pv.path, Proxy.NO_PROXY)
            t.role == TargetRole.VIDEO && pv != null && t.udp -> probeQuicDirect(pv.host)
            t.udp -> probeQuicDirect(t.host)
            else -> probeDirect(t.host)
        }
    }

    /** Диспетчер пробы через прокси-кандидат: видео = реальный медиа-GET, если есть URL. */
    private suspend fun probeProxyFor(t: Target): ProbeResult {
        val pv = videoUrl
        val socks = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", testPort))
        return when {
            t.role == TargetRole.VIDEO && pv != null && !t.udp -> probeMedia(pv.host, pv.path, socks)
            t.role == TargetRole.VIDEO && pv != null && t.udp -> probeQuicThroughProxy(pv.host)
            t.udp -> probeQuicThroughProxy(t.host)
            else -> probeThroughProxy(t.host)
        }
    }

    /** Прогоняет один кандидат и возвращает агрегированный результат. */
    suspend fun testCandidate(flags: String): CandidateResult {
        val proxy = ByeDpiProxy()
        val full = "-i 127.0.0.1 -p $testPort $flags"
        val scope = CoroutineScope(Dispatchers.IO)
        val job = scope.launch {
            try {
                proxy.startProxy(ByeDpiProxyCmdPreferences(full))
            } catch (e: Exception) {
                Log.e(TAG, "Proxy failed for: $full", e)
            }
        }

        try {
            if (!awaitPort(testPort, 1200)) {
                job.cancel()
                return CandidateResult(flags, false, DropCause.PROXY_FAIL, -1, emptyList())
            }

            // Пробы разных целей через ОДИН прокси независимы — гоняем параллельно.
            // (Параллелить сами КАНДИДАТЫ нельзя: нативные params ByeDPI глобальны,
            // одновременно живёт только один прокси. Внутри кандидата — можно.)
            var probes = coroutineScope {
                targets.map { t ->
                    async(Dispatchers.IO) { t to probeProxyFor(t) }
                }.awaitAll()
            }

            // РЕТРАЙ значимых целей (PAGE/VIDEO). Stateful-DPI может кратковременно
            // «чёрнодырить» googlevideo после серии неудачных хендшейков — и хороший
            // каскад ложно получает TLS_TIMEOUT. Одна повторная попытка через паузу
            // отсеивает этот транзиентный дроп: реально рабочий флаг пробьётся со
            // второго раза, а реально нерабочий — снова упадёт (ложных WORK не даёт).
            val failed = probes.filter { it.first.role != TargetRole.CONTROL && !it.second.ok }
            if (failed.isNotEmpty()) {
                delay(300)
                val retried = coroutineScope {
                    failed.map { (t, _) ->
                        async(Dispatchers.IO) { t to probeProxyFor(t) }
                    }.awaitAll()
                }.toMap()
                probes = probes.map { (t, r) ->
                    val re = retried[t]
                    if (re != null && re.ok) t to re else t to r
                }
            }

            // АДАПТИВНЫЙ вердикт: страница обязана открыться; видео — ЛЮБЫМ транспортом.
            val pageProbes = probes.filter { it.first.role == TargetRole.PAGE }
            val videoProbes = probes.filter { it.first.role == TargetRole.VIDEO }
            val pageOk = pageProbes.isNotEmpty() && pageProbes.all { it.second.ok }
            val videoQuicOk = videoProbes.any { it.first.udp && it.second.ok }
            val videoTlsOk = videoProbes.any { !it.first.udp && it.second.ok }
            val videoOk = videoQuicOk || videoTlsOk
            val ok = pageOk && videoOk
            val videoVia = when {
                videoQuicOk -> "QUIC"
                videoTlsOk -> "TLS"
                else -> "—"
            }
            // Если видео живо ТОЛЬКО по TLS — добавляем -U (--no-udp), чтобы приложение
            // не ждало дохлый QUIC, а сразу шло по TCP. При живом QUIC оставляем как есть
            // (в т.ч. -a-фейк). -U не дублируем, если он уже во флагах.
            val flagsToApply =
                if (ok && !videoQuicOk && videoTlsOk && !flags.contains("-U")) "$flags -U" else flags

            val firstBad = when {
                !pageOk -> pageProbes.firstOrNull { !it.second.ok }?.second
                !videoOk -> videoProbes.firstOrNull { !it.second.ok }?.second
                else -> null
            }
            val cause = if (ok) DropCause.OK else (firstBad?.cause ?: DropCause.OK)
            // ms — только для дебага: худшая из всех целей (ограничена perProbeTimeout).
            val ms = probes.maxOf { it.second.ms }
            return CandidateResult(
                flags, ok, cause, ms, probes.map { it.second },
                flagsToApply = flagsToApply, videoVia = videoVia,
            )
        } finally {
            try {
                proxy.stopProxy()
            } catch (e: Exception) {
                Log.w(TAG, "stopProxy after test", e)
            }
            job.join()
            // Освобождаем выделенный поток движка (по одному на кандидата).
            proxy.dispose()
        }
    }

    private suspend fun awaitPort(port: Int, timeoutMs: Long): Boolean =
        withContext(Dispatchers.IO) {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                try {
                    Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 200) }
                    return@withContext true
                } catch (_: IOException) {
                    delay(50)
                }
            }
            false
        }

    private suspend fun probeThroughProxy(host: String): ProbeResult {
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", testPort))
        return probe(host, proxy)
    }

    private suspend fun probeDirect(host: String): ProbeResult = probe(host, Proxy.NO_PROXY)

    private suspend fun probe(host: String, proxy: Proxy): ProbeResult =
        withContext(Dispatchers.IO) {
            val t0 = System.currentTimeMillis()

            // Форсим IPv4: иначе getByName может вернуть IPv6, ByeDPI получит
            // v6-литерал, а на v4-only сети коннект упадёт как PROXY_FAIL —
            // и провал семьи адресов замаскируется под провал обхода.
            val ip = resolveV4(host)?.hostAddress
                ?: return@withContext ProbeResult(host, "DNS", false, DropCause.DNS_FAIL, elapsed(t0))

            var raw: Socket? = null
            var handshakeDone = false
            try {
                raw = Socket(proxy)
                // createUnresolved → SOCKS получает IP (DNS уже сделали мы), не имя.
                raw.connect(InetSocketAddress.createUnresolved(ip, 443), perProbeTimeoutMs)
                raw.soTimeout = perProbeTimeoutMs

                // host в createSocket уже задаёт SNI; на API 24+ дублируем явно.
                val ssl = sslFactory.createSocket(raw, host, 443, true) as SSLSocket
                ssl.soTimeout = perProbeTimeoutMs
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    ssl.sslParameters = ssl.sslParameters.apply {
                        serverNames = listOf(SNIHostName(host))
                    }
                }
                ssl.startHandshake()
                handshakeDone = true   // SNI пробился — DPI не убил соединение на ClientHello
                ssl.outputStream.write(
                    "HEAD / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray()
                )
                ssl.outputStream.flush()
                val line = ssl.inputStream.bufferedReader().readLine()

                if (line != null && line.startsWith("HTTP")) {
                    ProbeResult(host, "TLS", true, DropCause.OK, elapsed(t0))
                } else {
                    ProbeResult(host, "TLS", false, DropCause.HTTP_BLOCKPAGE, elapsed(t0))
                }
            } catch (e: Exception) {
                ProbeResult(host, "TLS", false, classify(e, raw, handshakeDone), elapsed(t0))
            } finally {
                try {
                    raw?.close()
                } catch (_: Exception) {
                }
            }
        }

    // ---- Реальный медиа-GET к googlevideo (100% критерий: байты потока пошли) -----
    // probe() выше проверяет лишь пробитие SNI (TLS-хендшейк + HEAD). Здесь мы РЕАЛЬНО
    // тянем кусок видеосегмента рикролла (Range 0..128КБ) и требуем >=32КБ тела. Именно
    // этот трафик режет/тормозит stateful-DPI: пришли байты — ролик будет играть.
    private suspend fun probeMedia(host: String, path: String, proxy: Proxy): ProbeResult =
        withContext(Dispatchers.IO) {
            val t0 = System.currentTimeMillis()
            val ip = resolveV4(host)?.hostAddress
                ?: return@withContext ProbeResult(host, "MEDIA", false, DropCause.DNS_FAIL, elapsed(t0))
            var raw: Socket? = null
            var handshakeDone = false
            try {
                raw = Socket(proxy)
                raw.connect(InetSocketAddress.createUnresolved(ip, 443), perProbeTimeoutMs)
                raw.soTimeout = perProbeTimeoutMs
                val ssl = sslFactory.createSocket(raw, host, 443, true) as SSLSocket
                ssl.soTimeout = perProbeTimeoutMs
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    ssl.sslParameters = ssl.sslParameters.apply {
                        serverNames = listOf(SNIHostName(host))
                    }
                }
                ssl.startHandshake()
                handshakeDone = true
                val req = "GET $path HTTP/1.1\r\n" +
                    "Host: $host\r\n" +
                    "Range: bytes=0-${MEDIA_RANGE - 1}\r\n" +
                    "User-Agent: $MEDIA_UA\r\n" +
                    "Accept: */*\r\n" +
                    "Connection: close\r\n\r\n"
                ssl.outputStream.write(req.toByteArray())
                ssl.outputStream.flush()
                val ins = BufferedInputStream(ssl.inputStream, 16 * 1024)

                val status = readAsciiLine(ins)
                    ?: return@withContext ProbeResult(host, "MEDIA", false, DropCause.HTTP_TIMEOUT, elapsed(t0))
                if (!status.startsWith("HTTP")) {
                    return@withContext ProbeResult(host, "MEDIA", false, DropCause.HTTP_BLOCKPAGE, elapsed(t0))
                }
                val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                if (code != 200 && code != 206) {
                    return@withContext ProbeResult(host, "MEDIA", false, DropCause.HTTP_BLOCKPAGE, elapsed(t0))
                }
                // Пропускаем заголовки до пустой строки.
                while (true) {
                    val line = readAsciiLine(ins) ?: break
                    if (line.isEmpty()) break
                }
                // Тянем тело, пока не наберём порог (или поток не оборвётся).
                var total = 0
                val buf = ByteArray(16 * 1024)
                while (total < MEDIA_MIN_BYTES) {
                    val n = ins.read(buf)
                    if (n < 0) break
                    total += n
                }
                if (total >= MEDIA_MIN_BYTES) {
                    ProbeResult(host, "MEDIA", true, DropCause.OK, elapsed(t0))
                } else {
                    // Хендшейк прошёл, статус ок, но тело оборвалось не добрав порога —
                    // ровно stateful-DPI, режущий медиа после старта. Это НЕ PASS.
                    ProbeResult(host, "MEDIA", false, DropCause.HTTP_TIMEOUT, elapsed(t0))
                }
            } catch (e: Exception) {
                ProbeResult(host, "MEDIA", false, classify(e, raw, handshakeDone), elapsed(t0))
            } finally {
                try { raw?.close() } catch (_: Exception) {}
            }
        }

    /** Одна ASCII-строка из потока (до \n), \r отбрасывается. null — если поток пуст. */
    private fun readAsciiLine(ins: InputStream): String? {
        val sb = StringBuilder()
        var any = false
        while (true) {
            val b = ins.read()
            if (b < 0) return if (any) sb.toString() else null
            any = true
            if (b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return sb.toString()
    }

    // ---- QUIC / UDP проба -------------------------------------------------
    // Видео YouTube идёт по QUIC (UDP-443). Шлём ЧЕСТНЫЙ QUIC Initial с реальным
    // SNI (QuicInitial): DPI читает Initial (ключи из открытого DCID), видит SNI и
    // при блокировке дропает пакет — проба падает в QUIC_TIMEOUT. Если DPI пропустил,
    // сервер googlevideo отвечает Retry/Initial — любая датаграмма в ответ = путь
    // открыт (ролик поедет). В отличие от старого Version-Negotiation-пакета без
    // SNI, тут DPI реально есть что резать — ложных OK больше нет.

    private fun resolveV4(host: String): InetAddress? =
        try {
            InetAddress.getAllByName(host).firstOrNull { it is Inet4Address }
                ?: InetAddress.getByName(host)
        } catch (e: UnknownHostException) {
            null
        }

    private suspend fun probeQuicDirect(host: String): ProbeResult =
        withContext(Dispatchers.IO) {
            val t0 = System.currentTimeMillis()
            val ip = resolveV4(host)
                ?: return@withContext ProbeResult(host, "QUIC", false, DropCause.DNS_FAIL, elapsed(t0))
            var ds: DatagramSocket? = null
            try {
                ds = DatagramSocket().apply { soTimeout = perProbeTimeoutMs }
                val q = QuicInitial.build(host)
                ds.send(DatagramPacket(q, q.size, ip, 443))
                val buf = ByteArray(2048)
                ds.receive(DatagramPacket(buf, buf.size))
                ProbeResult(host, "QUIC", true, DropCause.OK, elapsed(t0))
            } catch (e: SocketTimeoutException) {
                ProbeResult(host, "QUIC", false, DropCause.QUIC_TIMEOUT, elapsed(t0))
            } catch (e: Exception) {
                ProbeResult(host, "QUIC", false, classifyUdp(e), elapsed(t0))
            } finally {
                try { ds?.close() } catch (_: Exception) {}
            }
        }

    private suspend fun probeQuicThroughProxy(host: String): ProbeResult =
        withContext(Dispatchers.IO) {
            val t0 = System.currentTimeMillis()
            val ip = resolveV4(host)
                ?: return@withContext ProbeResult(host, "QUIC", false, DropCause.DNS_FAIL, elapsed(t0))
            var ctrl: Socket? = null
            var ds: DatagramSocket? = null
            try {
                // SOCKS5 UDP ASSOCIATE — управляющее TCP-соединение держим открытым,
                // пока идёт обмен UDP, иначе ByeDPI закроет relay.
                ctrl = Socket().apply {
                    connect(InetSocketAddress("127.0.0.1", testPort), perProbeTimeoutMs)
                    soTimeout = perProbeTimeoutMs
                }
                val out = ctrl.getOutputStream()
                val ins = ctrl.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()      // greeting: no-auth
                val m = ByteArray(2); readFully(ins, m)
                if (m[1].toInt() != 0x00) throw SocketException("SOCKS auth rejected")
                // UDP ASSOCIATE, ATYP=IPv4, 0.0.0.0:0
                out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
                val head = ByteArray(4); readFully(ins, head)
                if (head[1].toInt() != 0x00) throw SocketException("SOCKS UDP associate failed")
                val addrLen = when (head[3].toInt()) {
                    0x01 -> 4; 0x04 -> 16
                    0x03 -> { val l = ByteArray(1); readFully(ins, l); l[0].toInt() and 0xff }
                    else -> throw SocketException("SOCKS bad ATYP")
                }
                val addr = ByteArray(addrLen); readFully(ins, addr)
                val pj = ByteArray(2); readFully(ins, pj)
                val relayPort = ((pj[0].toInt() and 0xff) shl 8) or (pj[1].toInt() and 0xff)
                val bnd = if (head[3].toInt() == 0x03) InetAddress.getByName(String(addr))
                          else InetAddress.getByAddress(addr)
                val relay = if (bnd.isAnyLocalAddress) InetAddress.getByName("127.0.0.1") else bnd

                ds = DatagramSocket().apply { soTimeout = perProbeTimeoutMs }
                val req = wrapSocksUdp(ip, 443, QuicInitial.build(host))
                ds.send(DatagramPacket(req, req.size, relay, relayPort))
                val buf = ByteArray(2048)
                ds.receive(DatagramPacket(buf, buf.size))            // ответ от CDN через relay
                ProbeResult(host, "QUIC", true, DropCause.OK, elapsed(t0))
            } catch (e: SocketTimeoutException) {
                ProbeResult(host, "QUIC", false, DropCause.QUIC_TIMEOUT, elapsed(t0))
            } catch (e: Exception) {
                ProbeResult(host, "QUIC", false, classifyUdp(e), elapsed(t0))
            } finally {
                try { ds?.close() } catch (_: Exception) {}
                try { ctrl?.close() } catch (_: Exception) {}
            }
        }

    /** SOCKS5 UDP-заголовок (RSV RSV FRAG ATYP ADDR PORT) + payload. */
    private fun wrapSocksUdp(ip: InetAddress, port: Int, data: ByteArray): ByteArray {
        val addr = ip.address
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0, 0, 0))                 // RSV(2) + FRAG(0)
        out.write(if (addr.size == 4) 0x01 else 0x04)   // ATYP
        out.write(addr)
        out.write((port ushr 8) and 0xff); out.write(port and 0xff)
        out.write(data)
        return out.toByteArray()
    }

    private fun readFully(ins: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = ins.read(buf, off, buf.size - off)
            if (n < 0) throw IOException("EOF from SOCKS control stream")
            off += n
        }
    }

    private fun classifyUdp(e: Exception): DropCause = when {
        e is PortUnreachableException -> DropCause.QUIC_DROP
        e is SocketException && e.message?.contains("SOCKS", ignoreCase = true) == true ->
            DropCause.PROXY_FAIL
        e is SocketException -> DropCause.PROXY_FAIL
        else -> DropCause.QUIC_DROP
    }

    private fun classify(e: Exception, raw: Socket?, handshakeDone: Boolean): DropCause = when {
        e is SocketTimeoutException && raw?.isConnected != true -> DropCause.CONNECT_TIMEOUT
        // Хендшейк уже прошёл → таймаут случился на чтении HTTP, а не на SNI.
        e is SocketTimeoutException && handshakeDone -> DropCause.HTTP_TIMEOUT
        e is SocketTimeoutException -> DropCause.TLS_TIMEOUT
        e is SSLException -> DropCause.TLS_HANDSHAKE_FAIL
        e is SocketException && e.message?.contains("SOCKS", ignoreCase = true) == true ->
            DropCause.PROXY_FAIL
        e is SocketException && e.message?.contains("reset", ignoreCase = true) == true ->
            DropCause.TCP_RST
        e is ConnectException -> DropCause.CONNECT_TIMEOUT
        else -> DropCause.TCP_RST
    }

    private fun elapsed(t0: Long): Long = System.currentTimeMillis() - t0
}
