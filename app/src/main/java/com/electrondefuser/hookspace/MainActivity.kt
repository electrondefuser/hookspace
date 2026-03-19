package com.electrondefuser.hookspace

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.electrondefuser.hookspace.ui.theme.HookSpaceTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            HookSpaceTheme {
                HookSpaceApp()
            }
        }
    }
}

// ─────────────────────────────────────────────
//  Data
// ─────────────────────────────────────────────

enum class CheckStatus { CLEAN, DETECTED, ERROR, PENDING }

data class DetectionResult(
    val label: String,
    val raw: String,
    val status: CheckStatus
)

private fun parseStatus(output: String): CheckStatus = when {
    output.contains("DETECTED") -> CheckStatus.DETECTED
    output.contains("ERROR")    -> CheckStatus.ERROR
    output.contains("CLEAN")    -> CheckStatus.CLEAN
    else                        -> CheckStatus.PENDING
}

// ─────────────────────────────────────────────
//  Composables
// ─────────────────────────────────────────────

@Composable
fun HookSpaceApp() {
    var libcEnabled    by remember { mutableStateOf(true) }
    var syscallEnabled by remember { mutableStateOf(true) }
    var memEnabled     by remember { mutableStateOf(true) }

    var results by remember { mutableStateOf<List<DetectionResult>>(emptyList()) }
    var running by remember { mutableStateOf(false) }

    val scope  = rememberCoroutineScope()
    val scroll = rememberScrollState()

    Scaffold(
        topBar = {
            Surface(tonalElevation = 3.dp) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .statusBarsPadding()
                        .padding(horizontal = 16.dp, vertical = 14.dp)
                ) {
                    Text(
                        text  = "HookSpace",
                        style = MaterialTheme.typography.titleLarge.copy(
                            fontFamily  = FontFamily.Monospace,
                            fontWeight  = FontWeight.Bold
                        )
                    )
                    Spacer(Modifier.weight(1f))
                    Text(
                        text  = "v1.0",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(scroll)
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // ── Section label ──
            SectionLabel("Detection Methods")

            // ── Checkboxes ──
            MethodCheckbox(
                label       = "libc Scanning",
                description = "maps / threads / fds via fopen, readdir, read…",
                checked     = libcEnabled,
                onChecked   = { libcEnabled = it }
            )
            MethodCheckbox(
                label       = "Syscall Scanning",
                description = "Same scans via raw inline-asm SVC (bypasses hooked libc)",
                checked     = syscallEnabled,
                onChecked   = { syscallEnabled = it }
            )
            MethodCheckbox(
                label       = "Memory Integrity",
                description = "ELF disk-vs-memory checksum + prologue trampoline",
                checked     = memEnabled,
                onChecked   = { memEnabled = it }
            )

            Spacer(Modifier.height(4.dp))

            // ── Run button ──
            Button(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                enabled  = !running && (libcEnabled || syscallEnabled || memEnabled),
                onClick  = {
                    scope.launch {
                        running = true
                        results = emptyList()

                        val r = mutableListOf<DetectionResult>()
                        withContext(Dispatchers.IO) {
                            if (libcEnabled) {
                                val out = HookDetector.scanWithLibc()
                                r.add(DetectionResult("libc Scan", out, parseStatus(out)))
                            }
                            if (syscallEnabled) {
                                val out = HookDetector.scanWithSyscall()
                                r.add(DetectionResult("Syscall Scan", out, parseStatus(out)))
                            }
                            if (memEnabled) {
                                val out = HookDetector.scanMemoryIntegrity()
                                r.add(DetectionResult("Memory Integrity", out, parseStatus(out)))
                            }
                        }
                        results = r
                        running = false
                    }
                }
            ) {
                if (running) {
                    CircularProgressIndicator(
                        modifier    = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color       = MaterialTheme.colorScheme.onPrimary
                    )
                    Spacer(Modifier.width(10.dp))
                    Text("Running…")
                } else {
                    Text("Run Detection", fontFamily = FontFamily.Monospace)
                }
            }

            // ── Results ──
            AnimatedVisibility(
                visible = results.isNotEmpty(),
                enter   = fadeIn() + expandVertically(),
                exit    = fadeOut() + shrinkVertically()
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Spacer(Modifier.height(4.dp))
                    SectionLabel("Results")

                    val overall = when {
                        results.any { it.status == CheckStatus.DETECTED } -> CheckStatus.DETECTED
                        results.any { it.status == CheckStatus.ERROR }    -> CheckStatus.ERROR
                        else                                               -> CheckStatus.CLEAN
                    }
                    OverallBadge(overall)

                    results.forEach { ResultCard(it) }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text  = text.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        letterSpacing = 1.2.sp
    )
}

@Composable
private fun MethodCheckbox(
    label: String,
    description: String,
    checked: Boolean,
    onChecked: (Boolean) -> Unit
) {
    Surface(
        shape         = MaterialTheme.shapes.small,
        tonalElevation = 2.dp,
        modifier      = Modifier.fillMaxWidth()
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier          = Modifier.padding(end = 12.dp)
        ) {
            Checkbox(checked = checked, onCheckedChange = onChecked)
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text       = label,
                    fontWeight = FontWeight.Medium,
                    fontSize   = 14.sp
                )
                Text(
                    text  = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun OverallBadge(status: CheckStatus) {
    val (bg, fg, text) = when (status) {
        CheckStatus.DETECTED -> Triple(
            Color(0x22EF5350), Color(0xFFEF5350), "HOOK DETECTED"
        )
        CheckStatus.ERROR -> Triple(
            Color(0x22FFA726), Color(0xFFFFA726), "ERROR"
        )
        else -> Triple(
            Color(0x2266BB6A), Color(0xFF66BB6A), "CLEAN — No hooks found"
        )
    }
    Surface(
        color  = bg,
        shape  = MaterialTheme.shapes.small,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text       = text,
            color      = fg,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace,
            fontSize   = 13.sp,
            modifier   = Modifier.padding(horizontal = 14.dp, vertical = 10.dp)
        )
    }
}

@Composable
private fun ResultCard(result: DetectionResult) {
    val (badgeBg, badgeFg, badge) = when (result.status) {
        CheckStatus.DETECTED -> Triple(Color(0x22EF5350), Color(0xFFEF5350), "DETECTED")
        CheckStatus.ERROR    -> Triple(Color(0x22FFA726), Color(0xFFFFA726), "ERROR")
        CheckStatus.CLEAN    -> Triple(Color(0x2266BB6A), Color(0xFF66BB6A), "CLEAN")
        CheckStatus.PENDING  -> Triple(Color(0x22AAAAAA), Color(0xFFAAAAAA), "?")
    }

    Surface(
        shape          = MaterialTheme.shapes.small,
        tonalElevation  = 2.dp,
        modifier       = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier              = Modifier.fillMaxWidth()
            ) {
                Text(
                    text       = result.label,
                    fontWeight = FontWeight.SemiBold,
                    fontSize   = 14.sp
                )
                Surface(
                    color  = badgeBg,
                    shape  = MaterialTheme.shapes.extraSmall
                ) {
                    Text(
                        text       = badge,
                        color      = badgeFg,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        fontSize   = 10.sp,
                        modifier   = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            HorizontalDivider(
                thickness = 0.5.dp,
                color     = MaterialTheme.colorScheme.outlineVariant
            )
            Spacer(Modifier.height(8.dp))
            Text(
                text       = result.raw.trim(),
                fontFamily = FontFamily.Monospace,
                fontSize   = 11.sp,
                lineHeight = 17.sp,
                color      = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
