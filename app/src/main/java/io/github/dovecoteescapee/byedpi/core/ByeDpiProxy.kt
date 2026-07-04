package io.github.dovecoteescapee.byedpi.core

import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors

class ByeDpiProxy {
    companion object {
        init {
            System.loadLibrary("byedpi")
        }
    }

    private val mutex = Mutex()
    private var fd = -1

    // Нативные params/NOT_EXIT теперь thread-local (__thread): у каждого движка своя
    // копия — это и даёт ПАРАЛЛЕЛЬНЫЙ перебор (несколько ByeDpiProxy одновременно).
    // Условие корректности: createSocket (пишет params) и jniStartProxy/event_loop
    // (читают params, а по выходе делают reset_params) обязаны идти на ОДНОМ и том же
    // OS-потоке. Поэтому пришпиливаем их к выделенному однопоточному исполнителю.
    // stopProxy НЕ идёт сюда: этот поток занят блокирующим event_loop; shutdown fd
    // потокобезопасен и будит event_loop извне.
    private val engineExecutor =
        Executors.newSingleThreadExecutor { r -> Thread(r, "byedpi-engine") }
    private val engineDispatcher = engineExecutor.asCoroutineDispatcher()

    suspend fun startProxy(preferences: ByeDpiProxyPreferences): Int =
        withContext(engineDispatcher) {
            val fd = createSocket(preferences)
            if (fd < 0) {
                return@withContext -1 // TODO: should be error code
            }
            jniStartProxy(fd)
        }

    suspend fun stopProxy(): Int {
        mutex.withLock {
            if (fd < 0) {
                throw IllegalStateException("Proxy is not running")
            }

            val result = jniStopProxy(fd)
            if (result == 0) {
                fd = -1
            }
            return result
        }
    }

    /** Освобождает выделенный поток движка. Звать после того, как startProxy завершился. */
    fun dispose() {
        engineExecutor.shutdownNow()
    }

    private suspend fun createSocket(preferences: ByeDpiProxyPreferences): Int =
        mutex.withLock {
            if (fd >= 0) {
                throw IllegalStateException("Proxy is already running")
            }

            val fd = createSocketFromPreferences(preferences)
            if (fd < 0) {
                return -1
            }
            this.fd = fd
            fd
        }

    private fun createSocketFromPreferences(preferences: ByeDpiProxyPreferences) =
        when (preferences) {
            is ByeDpiProxyCmdPreferences -> jniCreateSocketWithCommandLine(preferences.args)

            is ByeDpiProxyUIPreferences -> jniCreateSocket(
                ip = preferences.ip,
                port = preferences.port,
                maxConnections = preferences.maxConnections,
                bufferSize = preferences.bufferSize,
                defaultTtl = preferences.defaultTtl,
                customTtl = preferences.customTtl,
                noDomain = preferences.noDomain,
                desyncHttp = preferences.desyncHttp,
                desyncHttps = preferences.desyncHttps,
                desyncUdp = preferences.desyncUdp,
                desyncMethod = preferences.desyncMethod.ordinal,
                splitPosition = preferences.splitPosition,
                splitAtHost = preferences.splitAtHost,
                fakeTtl = preferences.fakeTtl,
                fakeSni = preferences.fakeSni,
                oobChar = preferences.oobChar,
                hostMixedCase = preferences.hostMixedCase,
                domainMixedCase = preferences.domainMixedCase,
                hostRemoveSpaces = preferences.hostRemoveSpaces,
                tlsRecordSplit = preferences.tlsRecordSplit,
                tlsRecordSplitPosition = preferences.tlsRecordSplitPosition,
                tlsRecordSplitAtSni = preferences.tlsRecordSplitAtSni,
                hostsMode = preferences.hostsMode.ordinal,
                hosts = preferences.hosts,
                tcpFastOpen = preferences.tcpFastOpen,
                udpFakeCount = preferences.udpFakeCount,
                dropSack = preferences.dropSack,
                fakeOffset = preferences.fakeOffset,
            )
        }

    private external fun jniCreateSocketWithCommandLine(args: Array<String>): Int

    private external fun jniCreateSocket(
        ip: String,
        port: Int,
        maxConnections: Int,
        bufferSize: Int,
        defaultTtl: Int,
        customTtl: Boolean,
        noDomain: Boolean,
        desyncHttp: Boolean,
        desyncHttps: Boolean,
        desyncUdp: Boolean,
        desyncMethod: Int,
        splitPosition: Int,
        splitAtHost: Boolean,
        fakeTtl: Int,
        fakeSni: String,
        oobChar: Byte,
        hostMixedCase: Boolean,
        domainMixedCase: Boolean,
        hostRemoveSpaces: Boolean,
        tlsRecordSplit: Boolean,
        tlsRecordSplitPosition: Int,
        tlsRecordSplitAtSni: Boolean,
        hostsMode: Int,
        hosts: String?,
        tcpFastOpen: Boolean,
        udpFakeCount: Int,
        dropSack: Boolean,
        fakeOffset: Int,
    ): Int

    private external fun jniStartProxy(fd: Int): Int

    private external fun jniStopProxy(fd: Int): Int
}