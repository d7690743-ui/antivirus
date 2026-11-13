package com.example.antivirus

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import java.io.File

class MainActivity : Activity() {

    private lateinit var statusText: TextView
    private lateinit var resultsText: TextView
    private lateinit var scanButton: Button

    private var pickUri: Uri? = null
    private var pickEsCarpeta: Boolean = false
    private var pickNombre: String = ""

    private val pickFileCode = 3001
    private val pickFolderCode = 3002

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.status)
        resultsText = findViewById(R.id.results)
        scanButton = findViewById(R.id.scan)

        findViewById<Button>(R.id.pick_file).setOnClickListener { pickArchivo() }
        findViewById<Button>(R.id.pick_folder).setOnClickListener { pickCarpeta() }
        scanButton.setOnClickListener { doScan() }

        statusText.text = "Elige un archivo o carpeta y pulsa Escanear."
    }

    private fun pickArchivo() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        @Suppress("DEPRECATION") // Sin AndroidX a proposito: app minima.
        startActivityForResult(intent, pickFileCode)
    }

    private fun pickCarpeta() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
        @Suppress("DEPRECATION") // Sin AndroidX a proposito: app minima.
        startActivityForResult(intent, pickFolderCode)
    }

    @Deprecated("Sin AndroidX a proposito: app minima")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        try {
            val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
            contentResolver.takePersistableUriPermission(uri, flags)
        } catch (_: Exception) {
        }
        when (requestCode) {
            pickFileCode -> {
                pickUri = uri
                pickEsCarpeta = false
                pickNombre = Scanner.nombre(contentResolver, uri)
                statusText.text = "Archivo: $pickNombre"
            }
            pickFolderCode -> {
                pickUri = uri
                pickEsCarpeta = true
                pickNombre = "carpeta elegida"
                statusText.text = "Carpeta elegida. Pulsa Escanear."
            }
        }
        resultsText.text = ""
    }

    private fun quarantineDir(): File {
        val dir = File(filesDir, "cuarentena")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    private fun doScan() {
        val uri = pickUri
        if (uri == null) {
            Toast.makeText(this, "Elige un archivo o carpeta primero", Toast.LENGTH_SHORT).show()
            return
        }
        scanButton.isEnabled = false
        statusText.text = "Escaneando..."
        resultsText.text = ""
        Thread {
            try {
                val firmas = Scanner.cargar(this)
                val objetivos: List<Pair<Uri, String>> = if (pickEsCarpeta) {
                    Scanner.listarArbol(contentResolver, uri)
                } else {
                    listOf(uri to pickNombre)
                }
                if (objetivos.isEmpty()) throw Exception("La carpeta no tiene archivos legibles")
                val sb = StringBuilder()
                var amenazas = 0
                for ((u, nombre) in objetivos) {
                    val size = Scanner.tamano(contentResolver, u)
                    if (size > Scanner.MAX_BYTES) {
                        sb.append("[info] $nombre: omitido por tamano ($size bytes)\n")
                        continue
                    }
                    val data = try {
                        contentResolver.openInputStream(u)?.use { it.readBytes() }
                    } catch (_: Exception) {
                        null
                    }
                    if (data == null) {
                        sb.append("[info] $nombre: no legible\n")
                        continue
                    }
                    val r = Scanner.escanearBytes(nombre, data, firmas)
                    if (r.hallazgos.isEmpty()) continue
                    if (r.esAmenaza) {
                        amenazas++
                        sb.append("[AMENAZA] $nombre\n")
                    } else {
                        sb.append("[info] $nombre\n")
                    }
                    for (h in r.hallazgos) {
                        val marca = if (h.nivel == "amenaza") "-" else "(i)"
                        sb.append("    $marca ${h.tipo}: ${h.detalle}\n")
                    }
                    if (r.esAmenaza) {
                        try {
                            val dest = File(quarantineDir(), nombre.replace('/', '_'))
                            dest.writeBytes(data)
                            sb.append("    -> copia en cuarentena interna\n")
                        } catch (_: Exception) {
                            sb.append("    -> no se pudo copiar a cuarentena\n")
                        }
                    }
                }
                sb.append("\nArchivos: ${objetivos.size}, con amenazas: $amenazas")
                runOnUiThread {
                    resultsText.text = sb.toString()
                    statusText.text = if (amenazas > 0) {
                        "Listo: $amenazas archivo(s) con amenazas (copiados a cuarentena interna)."
                    } else {
                        "Listo: sin amenazas en ${objetivos.size} archivo(s)."
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    statusText.text = "Error: ${e.message}"
                    Toast.makeText(this, "Fallo: ${e.message}", Toast.LENGTH_LONG).show()
                }
            } finally {
                runOnUiThread { scanButton.isEnabled = true }
            }
        }.start()
    }
}
