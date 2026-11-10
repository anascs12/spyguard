package expo.modules.privacynative

import android.app.Activity
import android.content.Context
import android.graphics.Bitmap
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.view.TextureView
import android.view.ViewGroup
import android.widget.FrameLayout
import androidx.media3.common.MediaItem
import androidx.media3.common.PlaybackException
import androidx.media3.common.Player
import androidx.media3.common.VideoSize
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.rtsp.RtspMediaSource
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

    // One JPEG frame from an UNAUTHENTICATED RTSP stream, as a data: URI, or null.
    // The URL carries no username or password: a stream that needs a login simply
    // fails here. No credentials are ever sent — detection, never access.
    AsyncFunction("grabRtspFrame") { host: String, port: Int, path: String, timeoutMs: Int, promise: Promise ->
      val activity = appContext.currentActivity
      if (activity == null) {
        promise.resolve(null)
      } else {
        val url = "rtsp://$host:$port$path"
        Handler(Looper.getMainLooper()).post {
          RtspFrameGrabber(activity, url, timeoutMs.toLong(), promise).start()
        }
      }
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

/**
 * Pulls a single frame from an open RTSP stream so the finder can show what a
 * camera sees. Plays the stream into an off-screen TextureView with ExoPlayer,
 * grabs the first rendered frame as a JPEG, then tears everything down.
 *
 * It opens only the URL it is given, which never contains credentials. If the
 * camera demands a password, ExoPlayer errors and this returns null — the app
 * never tries to log in. Any failure returns null, so the UI just shows no frame.
 */
@UnstableApi
private class RtspFrameGrabber(
  private val activity: Activity,
  private val url: String,
  private val timeoutMs: Long,
  private val promise: Promise,
) {
  private val handler = Handler(Looper.getMainLooper())
  private var player: ExoPlayer? = null
  private var container: FrameLayout? = null
  private var textureView: TextureView? = null
  private var videoW = 640
  private var videoH = 360
  private var done = false

  fun start() {
    try {
      val tv = TextureView(activity)
      textureView = tv
      val fl = FrameLayout(activity).apply { alpha = 0f }  // present but invisible
      container = fl
      fl.addView(tv, FrameLayout.LayoutParams(videoW, videoH))
      activity.findViewById<ViewGroup>(android.R.id.content)
        .addView(fl, FrameLayout.LayoutParams(videoW, videoH))

      val p = ExoPlayer.Builder(activity)
        .setMediaSourceFactory(RtspMediaSource.Factory().setForceUseRtpTcp(true))
        .build()
      player = p
      p.setVideoTextureView(tv)
      p.volume = 0f
      p.addListener(object : Player.Listener {
        override fun onVideoSizeChanged(size: VideoSize) {
          if (size.width > 0 && size.height > 0) {
            videoW = size.width
            videoH = size.height
          }
        }
        override fun onRenderedFirstFrame() {
          handler.postDelayed({ capture() }, 150)
        }
        override fun onPlayerError(error: PlaybackException) {
          finish(null)
        }
      })
      p.setMediaItem(MediaItem.fromUri(url))
      p.prepare()
      p.playWhenReady = true
      handler.postDelayed({ finish(null) }, timeoutMs)
    } catch (t: Throwable) {
      finish(null)
    }
  }

  private fun capture() {
    if (done) return
    try {
      val w = videoW.coerceIn(16, 1920)
      val h = videoH.coerceIn(16, 1080)
      val bmp = textureView?.getBitmap(w, h)
      if (bmp == null || bmp.width < 2) {
        finish(null)
        return
      }
      val maxW = 480
      val scaled = if (bmp.width > maxW) {
        Bitmap.createScaledBitmap(bmp, maxW, (bmp.height * maxW / bmp.width).coerceAtLeast(1), true)
      } else {
        bmp
      }
      val baos = ByteArrayOutputStream()
      scaled.compress(Bitmap.CompressFormat.JPEG, 80, baos)
      finish("data:image/jpeg;base64," + Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP))
    } catch (t: Throwable) {
      finish(null)
    }
  }

  private fun finish(result: String?) {
    if (done) return
    done = true
    handler.removeCallbacksAndMessages(null)
    try { player?.release() } catch (_: Throwable) {}
    try { container?.let { (it.parent as? ViewGroup)?.removeView(it) } } catch (_: Throwable) {}
    player = null
    container = null
    textureView = null
    promise.resolve(result)
  }
}
