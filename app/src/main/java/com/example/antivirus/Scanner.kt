package com.example.antivirus

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import org.json.JSONObject
import java.security.MessageDigest
import java.util.zip.ZipInputStream

data class Hallazgo(val nivel: String, val tipo: String, val detalle: String)

data class ResultadoArchivo(val nombre: String, val hallazgos: List<Hallazgo>) {
    val esAmenaza: Boolean get() = hallazgos.any { it.nivel == "amenaza" }
}

data class Patron(val nombre: String, val regex: Regex)

data class Firmas(
    val hashes: Set<String>,
    val eicar: ByteArray,
    val patrones: List<Patron>,
    val permisos: List<String>,
    val sdks: List<String>,
)

/**
 * Port del escaner Python (antivirus.py): hash, EICAR, patrones,
 * doble extension, URLs/IPs y analisis basico de APK.
 */
object Scanner {

    const val MAX_BYTES = 100L * 1024 * 1024

    private val DOBLE_EXT =
        Regex("\\.(pdf|doc|docx|xls|jpg|jpeg|png|mp3|mp4|txt|zip)\\.(exe|sh|py|js|bat|cmd|apk|jar)$", RegexOption.IGNORE_CASE)
    private val URL_RE = Regex("https?://[^\\s\"'<>]+", RegexOption.IGNORE_CASE)
    private val IP_RE = Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")

    fun cargar(context: Context): Firmas {
        val json = JSONObject(
            context.assets.open("signatures.json").use { it.readBytes().toString(Charsets.UTF_8) }
        )
        val hashes = mutableSetOf<String>()
        val arr = json.optJSONArray("hashes_maliciosos")
        if (arr != null) for (i in 0 until arr.length()) hashes.add(arr.getString(i))
        val patrones = mutableListOf<Patron>()
        val parr = json.getJSONArray("patrones")
        for (i in 0 until parr.length()) {
            val o = parr.getJSONObject(i)
            patrones.add(Patron(o.getString("nombre"), Regex(o.getString("regex"))))
        }
        fun strings(key: String): List<String> {
            val a = json.optJSONArray(key) ?: return emptyList()
            return (0 until a.length()).map { a.getString(it) }
        }
        return Firmas(
            hashes = hashes,
            eicar = json.optString("eicar", "").toByteArray(Charsets.UTF_8),
            patrones = patrones,
            permisos = strings("permisos_riesgosos"),
            sdks = strings("sdk_publicitarios"),
        )
    }

    fun tamano(cr: ContentResolver, uri: Uri): Long {
        try {
            cr.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val i = c.getColumnIndex(OpenableColumns.SIZE)
                    if (i >= 0 && !c.isNull(i)) return c.getLong(i)
                }
            }
        } catch (_: Exception) {
        }
        return -1
    }

    fun nombre(cr: ContentResolver, uri: Uri): String {
        try {
            cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) return c.getString(0) ?: "archivo"
            }
        } catch (_: Exception) {
        }
        return uri.lastPathSegment ?: "archivo"
    }

    /** Lista recursiva de documentos bajo un arbol SAF. Devuelve pares (uri, nombre). */
    fun listarArbol(cr: ContentResolver, treeUri: Uri): List<Pair<Uri, String>> {
        val out = mutableListOf<Pair<Uri, String>>()
        fun visitar(dirDocId: String) {
            val treeDocId = DocumentsContract.getTreeDocumentId(treeUri)
            val children = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, dirDocId)
            try {
                cr.query(
                    children,
                    arrayOf(
                        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                        DocumentsContract.Document.COLUMN_MIME_TYPE,
                    ),
                    null, null, null,
                )?.use { c ->
                    val idIdx = c.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    val nameIdx = c.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                    val mimeIdx = c.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
                    while (c.moveToNext()) {
                        val docId = c.getString(idIdx)
                        val name = c.getString(nameIdx) ?: "archivo"
                        val mime = c.getString(mimeIdx) ?: ""
                        val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                        if (mime == DocumentsContract.Document.MIME_TYPE_DIR) visitar(docId)
                        else out.add(docUri to name)
                    }
                }
            } catch (_: Exception) {
            }
        }
        try {
            visitar(DocumentsContract.getTreeDocumentId(treeUri))
        } catch (_: Exception) {
        }
        return out
    }

    fun escanearBytes(nombreArchivo: String, data: ByteArray, firmas: Firmas): ResultadoArchivo {
        val amenazas = mutableListOf<Hallazgo>()
        val infos = mutableListOf<Hallazgo>()

        val sha = MessageDigest.getInstance("SHA-256").digest(data).joinToString("") {
            "%02x".format(it)
        }
        if (sha in firmas.hashes) {
            amenazas.add(Hallazgo("amenaza", "hash_bloqueado", sha.take(16) + "..."))
        }
        if (firmas.eicar.isNotEmpty() && data.indexOfSub(firmas.eicar) >= 0) {
            amenazas.add(Hallazgo("amenaza", "archivo_prueba_eicar", "firma EICAR detectada"))
        }

        val texto = data.toString(Charsets.UTF_8)
        for (p in firmas.patrones) {
            if (p.regex.containsMatchIn(texto)) {
                amenazas.add(Hallazgo("amenaza", "patron_sospechoso", p.nombre))
            }
        }
        if (DOBLE_EXT.containsMatchIn(nombreArchivo)) {
            amenazas.add(Hallazgo("amenaza", "doble_extension", nombreArchivo.substringAfterLast('.')))
        }

        URL_RE.findAll(texto).map { it.value }.filter { it != "http://www.w3.org" }
            .distinct().take(5).forEach { infos.add(Hallazgo("info", "url", it.take(80))) }
        IP_RE.findAll(texto).map { it.value }.distinct().take(5)
            .forEach { infos.add(Hallazgo("info", "ip", it)) }

        if (nombreArchivo.endsWith(".apk", ignoreCase = true)) {
            amenazas.addAll(analizarApk(data, firmas))
        }

        return ResultadoArchivo(nombreArchivo, amenazas + infos)
    }

    private fun analizarApk(data: ByteArray, firmas: Firmas): List<Hallazgo> {
        val out = mutableListOf<Hallazgo>()
        try {
            ZipInputStream(data.inputStream()).use { zip ->
                val nombres = mutableListOf<String>()
                var manifiesto: ByteArray? = null
                var entry = zip.nextEntry
                while (entry != null) {
                    nombres.add(entry.name)
                    if (entry.name == "AndroidManifest.xml") manifiesto = zip.readBytes()
                    zip.closeEntry()
                    entry = zip.nextEntry
                }
                // ISO-8859-1 no falla con binario y conserva subcadenas ASCII.
                val manifiestoTxt = manifiesto?.toString(Charsets.ISO_8859_1) ?: ""
                for (perm in firmas.permisos) {
                    if (manifiestoTxt.contains(perm)) {
                        out.add(Hallazgo("amenaza", "permiso_riesgoso", perm))
                    }
                }
                val blob = (nombres.joinToString(" ") + " " + manifiestoTxt)
                for (sdk in firmas.sdks) {
                    if (blob.contains(sdk)) {
                        out.add(Hallazgo("amenaza", "sdk_publicitario", sdk))
                    }
                }
            }
        } catch (_: Exception) {
        }
        return out
    }

    private fun ByteArray.indexOfSub(sub: ByteArray): Int {
        if (sub.isEmpty() || sub.size > size) return -1
        outer@ for (i in 0..size - sub.size) {
            for (j in sub.indices) if (this[i + j] != sub[j]) continue@outer
            return i
        }
        return -1
    }
}
