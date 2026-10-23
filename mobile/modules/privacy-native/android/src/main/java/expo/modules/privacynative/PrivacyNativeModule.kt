package expo.modules.privacynative

import android.content.Context
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Collections
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Network primitives the JS detectors need and React Native doesn't expose:
 * WiFi scan results, link info, parallel TCP connect probes and raw TCP
 * request/response (used for RTSP and HTTP fingerprinting).
 * Detection-only: no credentials are ever sent.
 */
class PrivacyNativeModule : Module() {
  private val context: Context
    get() = requireNotNull(appContext.reactContext) { "React context unavailable" }

  private fun wifi(): WifiManager =
    context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

  override fun definition() = ModuleDefinition {
    Name("PrivacyNative")

    Function("getNetworkInfo") {
      val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
      val props = cm.getLinkProperties(cm.activeNetwork) ?: return@Function null
      val link = props.linkAddresses.firstOrNull { it.address is Inet4Address } ?: return@Function null
      val gateway = props.routes
        .firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }
        ?.gateway?.hostAddress ?: ""
      mapOf(
        "ip" to (link.address.hostAddress ?: ""),
        "prefixLength" to link.prefixLength,
        "gateway" to gateway,
        "interface" to (props.interfaceName ?: ""),
      )
    }

    Function("startWifiScan") {
      @Suppress("DEPRECATION")
      wifi().startScan()
    }

    Function("getWifiScanResults") {
      try {
        wifi().scanResults.map { r ->
          @Suppress("DEPRECATION")
          mapOf(
            "bssid" to (r.BSSID ?: ""),
            "ssid" to (r.SSID ?: ""),
            "level" to r.level,
            "frequency" to r.frequency,
          )
        }
      } catch (e: SecurityException) {
        emptyList<Map<String, Any>>()
      }
    }

    // Returns the subset of host:port pairs that accept a TCP connection.
    AsyncFunction("probePorts") { hosts: List<String>, ports: List<Int>, timeoutMs: Int, concurrency: Int, promise: Promise ->
      val pool = Executors.newFixedThreadPool(concurrency.coerceIn(1, 256))
      val open = Collections.synchronizedList(mutableListOf<Map<String, Any>>())
      for (host in hosts) {
        for (port in ports) {
          pool.execute {
            try {
              Socket().use { s ->
                s.connect(InetSocketAddress(host, port), timeoutMs)
                open.add(mapOf("host" to host, "port" to port))
              }
            } catch (_: Exception) {
            }
          }
        }
      }
      pool.shutdown()
      // Wait off the module queue so other calls aren't blocked
      Thread {
        pool.awaitTermination(5, TimeUnit.MINUTES)
        promise.resolve(open.toList())
      }.start()
    }

    // Sends payload and returns the reply as latin-1 text, or null if unreachable.
    // untilClose=false stops after headers (+ Content-Length body), for RTSP.
    AsyncFunction("tcpExchange") { host: String, port: Int, payload: String, timeoutMs: Int, maxBytes: Int, untilClose: Boolean, promise: Promise ->
      Thread {
        try {
          Socket().use { s ->
            s.connect(InetSocketAddress(host, port), timeoutMs)
            s.soTimeout = timeoutMs
            s.getOutputStream().apply {
              write(payload.toByteArray(Charsets.ISO_8859_1))
              flush()
            }
            val input = s.getInputStream()
            val buf = ByteArrayOutputStream()
            val chunk = ByteArray(4096)
            try {
              while (buf.size() < maxBytes) {
                val n = input.read(chunk)
                if (n < 0) break
                buf.write(chunk, 0, n)
                if (!untilClose && messageComplete(buf.toString("ISO-8859-1"))) break
              }
            } catch (_: SocketTimeoutException) {
            }
            promise.resolve(buf.toString("ISO-8859-1"))
          }
        } catch (_: Exception) {
          promise.resolve(null)
        }
      }.start()
    }
  }

  private fun messageComplete(text: String): Boolean {
    val end = text.indexOf("\r\n\r\n")
    if (end < 0) return false
    val length = Regex("(?im)^content-length:\\s*(\\d+)").find(text.substring(0, end))
      ?.groupValues?.get(1)?.toIntOrNull() ?: return true
    return text.length - (end + 4) >= length
  }
}
