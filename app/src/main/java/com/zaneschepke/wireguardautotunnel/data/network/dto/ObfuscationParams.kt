package com.zaneschepke.wireguardautotunnel.data.network.dto

/**
 * Holds the AmneziaWG-style obfuscation parameters fetched from the remote
 * Apps Script endpoint. These are interpolated into the `[Interface]`
 * section of every generated WireGuard `.conf`, between the standard
 * keys (PrivateKey / Address / DNS) and the empty line that precedes
 * `[Peer]`.
 *
 * Sample raw text from the endpoint:
 * ```
 * MTU = 1280
 * S1 = 0
 * S2 = 0
 * Jc = 4
 * Jmin = 40
 * Jmax = 70
 * H1 = 1
 * H2 = 2
 * H3 = 3
 * H4 = 4
 * I1 = <b 0xce0000...>
 * ```
 *
 * The original Proton script returns plain text (NOT JSON), so we parse
 * `key = value` lines into a Map.
 */
data class ObfuscationParams(
    val raw: String,
    val lines: List<Pair<String, String>>,
) {
    /** Render the parameters as `key = value` lines (no trailing newline). */
    fun toConfigLines(): String = lines.joinToString("\n") { (k, v) -> "$k = $v" }

    fun isEmpty(): Boolean = lines.isEmpty()

    companion object {
        /**
         * Parses the Apps Script's plain-text response into structured
         * parameters. Skips blank lines and `#`-prefixed comments. Tolerant
         * of extra whitespace around `=`. Empty input yields an empty
         * `ObfuscationParams(raw = "", lines = emptyList())`.
         */
        fun parse(text: String): ObfuscationParams {
            val lines =
                text.lineSequence()
                    .map { it.trimEnd() }
                    .filter { it.isNotBlank() && !it.trimStart().startsWith("#") }
                    .mapNotNull { line ->
                        val eq = line.indexOf('=')
                        if (eq <= 0) null
                        else {
                            val key = line.substring(0, eq).trim()
                            val value = line.substring(eq + 1).trim()
                            if (key.isEmpty()) null else key to value
                        }
                    }
                    .toList()
            return ObfuscationParams(raw = text, lines = lines)
        }
    }
}