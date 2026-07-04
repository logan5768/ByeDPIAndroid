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
import io.github.dovecoteescapee.byedpi.data.AppStatus
import io.github.dovecoteescapee.byedpi.databinding.ActivityTestBinding
import io.github.dovecoteescapee.byedpi.services.appStatus
import io.github.dovecoteescapee.byedpi.utility.getPreferences
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class TestActivity : AppCompatActivity() {
    private lateinit var binding: ActivityTestBinding
    private val tester = ByeDpiTester()
    private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    private var job: Job? = null

    companion object {
        private val TAG: String = TestActivity::class.java.simpleName
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
            // --- BASELINE: контрольный замер без прокси ---
            appendLine("BASELINE (без прокси)")
            val base = tester.baseline()
            for ((t, p) in tester.targets.zip(base)) appendLine(probeLine(t, p), stamp = false)

            // Всегда полный (глубокий) список: компактный набор ненадёжен против
            // stateful-DPI, который на короткое время «чёрнодырит» googlevideo после
            // первых неудачных хендшейков. Полный перебор даёт цели восстановиться,
            // прежде чем дойдёт до пробивного tlsrec-каскада.
            val list = TestCommandGenerator.deep()
            appendLine("ПЕРЕБОР: ${list.size} вариантов")

            var workCount = 0
            var idx = 0
            for (flags in list) {
                if (!isActive) break
                idx++
                val r = withContext(Dispatchers.IO) { tester.testCandidate(flags) }

                // Шапка попытки: #NN + флаги (с временной меткой).
                appendLine("#%02d  %s".format(idx, flags))
                // Вердикт отдельной строкой — сразу видно ЧТО зарубило вариант.
                appendLine(verdictLine(r), stamp = false)
                // По строке на цель — выровнено колонками, с пометками решающих/контроля.
                for ((t, p) in tester.targets.zip(r.probes)) appendLine(probeLine(t, p), stamp = false)

                // ms — НЕ критерий. Перебор идёт до конца, каждый рабочий вариант
                // добавляется кнопкой. НО первый прошедший проверку применяется
                // ПРОГРАММНО СРАЗУ (без ручного тапа) — приложение уже настроено,
                // как только найден рабочий флаг. Остальные рабочие остаются
                // кнопками: можно переключиться вручную.
                if (r.ok) {
                    workCount++
                    val auto = workCount == 1
                    // Применяем flagsToApply (может включать авто-добавленный -U для
                    // TLS-only видео), а не сырой тестовый flags.
                    addResultButton(r.flagsToApply, r.ms, auto)
                    if (auto) {
                        applyFlags(r.flagsToApply)
                        appendLine("  → применён автоматически (видео по ${r.videoVia})", stamp = false)
                    }
                }
            }

            appendLine("ИТОГО")
            if (workCount > 0) {
                appendLine(
                    "Готово. Рабочих: $workCount. Первый уже применён автоматически — " +
                        "можно сразу подключать VPN. Кнопками выше можно выбрать другой.",
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
    private fun verdictLine(r: CandidateResult): String {
        if (r.ok) return "  verdict: WORK    (${r.ms}ms — страница + видео по ${r.videoVia})"
        val zipped = tester.targets.zip(r.probes)
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
