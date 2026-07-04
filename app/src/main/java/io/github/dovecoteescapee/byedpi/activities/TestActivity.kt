package io.github.dovecoteescapee.byedpi.activities

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import io.github.dovecoteescapee.byedpi.R
import io.github.dovecoteescapee.byedpi.core.ByeDpiTester
import io.github.dovecoteescapee.byedpi.core.CandidateResult
import io.github.dovecoteescapee.byedpi.core.ProbeResult
import io.github.dovecoteescapee.byedpi.core.Target
import io.github.dovecoteescapee.byedpi.core.TargetRole
import io.github.dovecoteescapee.byedpi.core.TestCommandGenerator
import io.github.dovecoteescapee.byedpi.core.YtStream
import io.github.dovecoteescapee.byedpi.data.AppStatus
import io.github.dovecoteescapee.byedpi.databinding.ActivityTestBinding
import io.github.dovecoteescapee.byedpi.services.appStatus
import io.github.dovecoteescapee.byedpi.utility.getPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class TestActivity : AppCompatActivity() {
    private lateinit var binding: ActivityTestBinding
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    private var job: Job? = null

    companion object {
        private val TAG: String = TestActivity::class.java.simpleName

        // Сколько движков ByeDPI гоняем ОДНОВРЕМЕННО. Стало возможно потому, что
        // нативные params/NOT_EXIT теперь thread-local (по копии на поток-движок).
        // 4 — компромисс: быстрее в ~4×, но не заваливаем stateful-DPI параллельными
        // хендшейками настолько, чтобы он массово «чёрнодырил» googlevideo.
        private const val WORKERS = 4
        private const val BASE_PORT = 10080
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityTestBinding.inflate(layoutInflater)
        setContentView(binding.root)

        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = getString(R.string.test_title)

        binding.btnStart.setOnClickListener {
            if (job?.isActive == true) {
                job?.cancel()
                return@setOnClickListener
            }
            val (status, _) = appStatus
            if (status == AppStatus.Running) {
                Toast.makeText(this, R.string.test_running_warning, Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            startSelection()
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        onBackPressedDispatcher.onBackPressed()
        return true
    }

    override fun onDestroy() {
        super.onDestroy()
        job?.cancel()
    }

    private fun startSelection() {
        binding.logText.text = ""
        binding.resultsContainer.removeAllViews()
        binding.resultsLabel.visibility = View.GONE
        binding.btnStart.setText(R.string.test_stop)

        job = lifecycleScope.launch {
            // По движку на воркер, каждый на своём порту. thread-local params делают
            // их независимыми — можно гонять параллельно.
            val testers = (0 until WORKERS).map { ByeDpiTester(testPort = BASE_PORT + it) }
            val targets = testers[0].targets

            // --- Свежий видео-URL рикролла: добываем ОДИН раз программно (InnerTube),
            // раздаём всем воркерам. Есть URL → видео проверяется реальным медиа-GET;
            // нет (DPI режет сам youtube.com) → откат на SNI-хендшейк. ---
            appendLine("Получаю свежий видео-URL рикролла…")
            val pv = withContext(Dispatchers.IO) { YtStream.fetchPlayback() }
            if (pv != null) {
                testers.forEach { it.videoUrl = pv }
                appendLine("  видео-URL получен (${pv.host}) — тест по реальному потоку", stamp = false)
            } else {
                appendLine("  видео-URL не добыт — откат на SNI-хендшейк googlevideo", stamp = false)
            }

            // --- BASELINE: контрольный замер без прокси ---
            appendLine("BASELINE (без прокси)")
            val base = testers[0].baseline()
            for ((t, p) in targets.zip(base)) appendLine(probeLine(t, p), stamp = false)

            // Полный список. Разделяем на два класса по потоко-безопасности:
            //  • parallel — можно гонять одновременно (нативные fake_udp/fake_http —
            //    read-only, params thread-local);
            //  • fakeTls — содержат -f (fake ClientHello): change_tls_sni ПИШЕТ в общий
            //    буфер fake_tls, поэтому такие кандидаты нельзя пускать параллельно —
            //    гоним их строго последовательно в конце, и то лишь если ничего не нашли.
            val all = TestCommandGenerator.deep()
            val fakeTls = all.filter { it.contains("-f") }
            val parallel = all.filter { !it.contains("-f") }
            appendLine("ПЕРЕБОР: ${all.size} (парал.: ${parallel.size} ×$WORKERS, fake→послед.: ${fakeTls.size})")

            val found = AtomicBoolean(false)
            val nextIdx = AtomicInteger(0)

            // --- ФАЗА 1: параллельный перебор безопасных кандидатов ---
            // Первый рабочий флаг применяется сразу и глушит остальных воркеров
            // (cancelChildren) — цель перебора «запустить YouTube» достигнута.
            coroutineScope {
                // Контекст самого scope: его дети — воркеры. Через него глушим их всех,
                // когда кто-то нашёл рабочий флаг (cancelChildren на КОНТЕКСТЕ launch'а
                // отменил бы только его собственных детей, а не сиблингов).
                val poolCtx = coroutineContext
                repeat(WORKERS) { w ->
                    launch {
                        val t = testers[w]
                        while (isActive && !found.get()) {
                            val i = nextIdx.getAndIncrement()
                            if (i >= parallel.size) break
                            runCandidate(t, targets, parallel[i], "[п$w]", i + 1, found)
                            if (found.get()) {
                                poolCtx.cancelChildren() // остановить сиблингов
                                break
                            }
                        }
                    }
                }
            }

            // --- ФАЗА 2: fake-кандидаты строго по одному (общий буфер fake_tls) ---
            if (!found.get()) {
                val t = testers[0]
                for ((k, flags) in fakeTls.withIndex()) {
                    if (!isActive || found.get()) break
                    runCandidate(t, targets, flags, "[f]", parallel.size + k + 1, found)
                }
            }

            appendLine("ИТОГО")
            if (found.get()) {
                appendLine(
                    "Готово. Рабочий флаг найден и применён автоматически — можно сразу " +
                        "подключать VPN.",
                    stamp = false,
                )
            } else {
                appendLine("Рабочих вариантов не найдено. Проверь baseline сверху (DNS/сеть).", stamp = false)
            }
        }
        // Восстанавливаем кнопку ВСЕГДА: и при нормальном завершении, и при отмене
        // (job.cancel() бросает CancellationException, из-за которой код в конце
        // launch{} не выполняется — поэтому сброс делаем в invokeOnCompletion).
        job?.invokeOnCompletion {
            runOnUiThread { binding.btnStart.setText(R.string.test_start) }
        }
    }

    // Флаги активной (применённой) кнопки — чтобы подсветить её пометкой.
    private var appliedFlags: String? = null
    private val resultButtons = mutableMapOf<String, MaterialButton>()
    private val resultMs = mutableMapOf<String, Long>()

    private fun addResultButton(flags: String, ms: Long, auto: Boolean) {
        binding.resultsLabel.visibility = View.VISIBLE
        val btn = MaterialButton(
            this, null,
            com.google.android.material.R.attr.materialButtonOutlinedStyle
        ).apply {
            isAllCaps = false
            setOnClickListener { applyFlags(flags) }
        }
        resultButtons[flags] = btn
        resultMs[flags] = ms
        binding.resultsContainer.addView(btn)
        if (auto) appliedFlags = flags
        refreshButtonLabels()
    }

    /** Обновляет подписи кнопок: у активной — пометка «● применён». */
    private fun refreshButtonLabels() {
        resultButtons.forEach { (f, b) ->
            val base = getString(R.string.test_apply_item, f, resultMs[f] ?: 0)
            b.text = if (f == appliedFlags) "● $base — применён" else base
        }
    }

    private fun applyFlags(flags: String) {
        getPreferences().edit()
            .putString("byedpi_cmd_args", flags)
            .putBoolean("byedpi_enable_cmd_settings", true)
            .apply()
        appliedFlags = flags
        refreshButtonLabels()
        Log.i(TAG, "APPLIED: $flags")
        Toast.makeText(this, getString(R.string.test_applied, flags), Toast.LENGTH_LONG).show()
    }

    /**
     * Прогоняет один кандидат (на своём движке/порту) и печатает результат. Первый
     * прошедший проверку атомарно захватывает `found`, применяется автоматически;
     * последующие рабочие остаются альтернативными кнопками. UI — на Main, сам тест —
     * на IO.
     */
    private suspend fun runCandidate(
        tester: ByeDpiTester,
        targets: List<Target>,
        flags: String,
        tag: String,
        no: Int,
        found: AtomicBoolean,
    ) {
        val r = withContext(Dispatchers.IO) { tester.testCandidate(flags) }
        appendLine("%s #%02d  %s".format(tag, no, flags))
        appendLine(verdictLine(targets, r), stamp = false)
        for ((t, p) in targets.zip(r.probes)) appendLine(probeLine(t, p), stamp = false)
        if (r.ok) {
            if (found.compareAndSet(false, true)) {
                addResultButton(r.flagsToApply, r.ms, true)
                applyFlags(r.flagsToApply)
                appendLine("  → применён автоматически (видео по ${r.videoVia})", stamp = false)
            } else {
                addResultButton(r.flagsToApply, r.ms, false)
            }
        }
    }

    // ---- форматирование лога (единое для baseline и кандидатов) ----------

    /** Короткое человекочитаемое имя цели. */
    private fun hostLabel(t: Target): String = when {
        t.host.contains("googlevideo") -> "googlevideo"
        t.host.contains("youtube") -> "youtube.com"
        t.host.contains("yandex") -> "yandex.ru"
        else -> t.host
    }

    /** Имя цели с протоколом — для строки вердикта («по googlevideo/QUIC»). */
    private fun targetName(t: Target, p: ProbeResult): String = "${hostLabel(t)}/${p.proto}"

    /** Одна выровненная строка пробы: имя | протокол | OK/FAIL | причина | ms | пометка. */
    private fun probeLine(t: Target, p: ProbeResult): String {
        val res = if (p.ok) "OK" else "FAIL"
        val cause = if (p.ok) "-" else p.cause.name
        val marker = when (t.role) {
            TargetRole.PAGE -> "  ← страница"
            TargetRole.VIDEO -> "  ← видео"
            TargetRole.CONTROL -> "  (контроль)"
        }
        return "    " + hostLabel(t).padEnd(13) + p.proto.padEnd(5) +
            res.padEnd(5) + cause.padEnd(18) + "${p.ms}ms".padStart(7) + marker
    }

    /** Строка вердикта попытки: WORK (каким транспортом видео) или FAILED (где упало). */
    private fun verdictLine(targets: List<Target>, r: CandidateResult): String {
        if (r.ok) return "  verdict: WORK    (${r.ms}ms — страница + видео по ${r.videoVia})"
        val zipped = targets.zip(r.probes)
        val bad = zipped.firstOrNull { it.first.role == TargetRole.PAGE && !it.second.ok }
            ?: zipped.firstOrNull { it.first.role == TargetRole.VIDEO && !it.second.ok }
            ?: zipped.firstOrNull { !it.second.ok }
        val where = bad?.let { targetName(it.first, it.second) } ?: "?"
        val cz = bad?.second?.cause ?: r.cause
        return "  verdict: FAILED  (по $where: $cz)"
    }

    /**
     * Пишет строку в лог. stamp=true — с временной меткой (шапки: BASELINE, #NN,
     * ИТОГО). stamp=false — без метки (строки-детали под шапкой выравниваются).
     */
    private fun appendLine(line: String, stamp: Boolean = true) {
        val text = if (stamp) "[${timeFmt.format(Date())}] $line" else line
        Log.i(TAG, text)
        binding.logText.append(text + "\n")
        binding.logScroll.post {
            binding.logScroll.fullScroll(View.FOCUS_DOWN)
        }
    }
}
