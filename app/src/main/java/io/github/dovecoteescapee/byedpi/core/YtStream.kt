package io.github.dovecoteescapee.byedpi.core

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Программно добывает СВЕЖУЮ прямую ссылку на медиасегмент рикролла (googlevideo)
 * через InnerTube-API (клиент ANDROID). videoplayback-URL живёт ~6ч и привязан к
 * IP/сессии, поэтому хардкодить его нельзя — берём новый на каждый прогон теста.
 *
 * Клиент ANDROID выбран умышленно: у него streamingData.formats[].url отдаётся
 * ПРЯМОЙ ссылкой (без n-sig/cipher, которые пришлось бы гонять через JS-движок).
 *
 * Всё сетевое здесь идёт НАПРЯМУЮ (без прокси-кандидата) — это подготовка baseline.
 * Если запрос упал (DPI режет и сам youtube.com) — возвращаем null, и тестер честно
 * откатывается на старый критерий (SNI-хендшейк по redirector.googlevideo.com).
 */
object YtStream {
    private const val TAG = "YtStream"

    // Рикролл. Пользователю НЕ даём выбирать — нам нужен стабильный публичный ролик,
    // доступный без региональных ограничений и возрастных гейтов.
    private const val VIDEO_ID = "dQw4w9WgXcQ"

    // Публичный ключ InnerTube клиента ANDROID (не секрет, зашит в самом приложении YT).
    private const val API_KEY = "AIzaSyA8eiZmM1FaDVjRy-df2KTyQ_vz_yYM39w"
    private const val PLAYER_URL =
        "https://www.youtube.com/youtubei/v1/player?key=$API_KEY"

    private const val CLIENT_VERSION = "19.09.37"
    private const val USER_AGENT =
        "com.google.android.youtube/$CLIENT_VERSION (Linux; U; Android 11) gzip"

    private const val TIMEOUT_MS = 8000

    /**
     * Делает POST в InnerTube, парсит streamingData и возвращает host+path первого
     * годного формата с прямым url. null — если не удалось (сеть/DPI/парсинг).
     */
    suspend fun fetchPlayback(): PlaybackUrl? = withContext(Dispatchers.IO) {
        try {
            val body = buildRequestBody()
            val json = post(PLAYER_URL, body) ?: return@withContext null
            val root = JSONObject(json)

            val status = root.optJSONObject("playabilityStatus")?.optString("status")
            if (status != null && status != "OK") {
                Log.w(TAG, "playabilityStatus=$status")
            }

            val streaming = root.optJSONObject("streamingData")
                ?: run {
                    Log.w(TAG, "no streamingData in response")
                    return@withContext null
                }

            // Muxed formats — самые лёгкие и всегда с прямым url у ANDROID-клиента.
            // adaptiveFormats — запасной вариант (тоже прямые url).
            val url = pickUrl(streaming, "formats") ?: pickUrl(streaming, "adaptiveFormats")
            if (url == null) {
                Log.w(TAG, "no direct format url found")
                return@withContext null
            }

            val parsed = URL(url)
            val host = parsed.host
            val path = parsed.file // path + "?" + query
            Log.i(TAG, "playback host=$host")
            PlaybackUrl(host, path)
        } catch (e: Exception) {
            Log.w(TAG, "fetchPlayback failed", e)
            null
        }
    }

    /** Первый элемент массива [key] с непустым "url". */
    private fun pickUrl(streaming: JSONObject, key: String): String? {
        val arr = streaming.optJSONArray(key) ?: return null
        for (i in 0 until arr.length()) {
            val f = arr.optJSONObject(i) ?: continue
            val url = f.optString("url", "")
            if (url.isNotEmpty()) return url
        }
        return null
    }

    private fun buildRequestBody(): String {
        val client = JSONObject()
            .put("clientName", "ANDROID")
            .put("clientVersion", CLIENT_VERSION)
            .put("androidSdkVersion", 30)
            .put("hl", "en")
            .put("gl", "US")
        val context = JSONObject().put("client", client)
        return JSONObject()
            .put("context", context)
            .put("videoId", VIDEO_ID)
            .toString()
    }

    private fun post(urlStr: String, body: String): String? {
        var conn: HttpsURLConnection? = null
        return try {
            conn = (URL(urlStr).openConnection() as HttpsURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("User-Agent", USER_AGENT)
            }
            conn.outputStream.use { it.write(body.toByteArray()) }
            val code = conn.responseCode
            if (code != 200) {
                Log.w(TAG, "InnerTube HTTP $code")
                return null
            }
            conn.inputStream.bufferedReader().use { it.readText() }
        } catch (e: IOException) {
            Log.w(TAG, "InnerTube POST failed", e)
            null
        } finally {
            try { conn?.disconnect() } catch (_: Exception) {}
        }
    }
}
