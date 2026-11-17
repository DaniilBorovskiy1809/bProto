package dev.bproto

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View
import kotlin.math.min

/** Decorative globe and accessible connection button; no fabricated location data. */
class GlobeView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {
    private val ink = Paint(Paint.ANTI_ALIAS_FLAG)
    var connected = false
        set(value) { field = value; updateState() }
    var connecting = false
        set(value) { field = value; updateState() }
    init { isClickable = true; isFocusable = true; updateState() }
    private fun updateState() {
        contentDescription = context.getString(when {
            connecting -> dev.bproto.client.R.string.tap_to_cancel
            connected -> dev.bproto.client.R.string.globe_disconnect
            else -> dev.bproto.client.R.string.globe_connect
        })
        invalidate()
    }
    override fun performClick(): Boolean { super.performClick(); return true }
    override fun onInitializeAccessibilityNodeInfo(info: android.view.accessibility.AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        info.className = android.widget.Button::class.java.name
        info.isClickable = true
        info.isEnabled = isEnabled
    }
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val r = min(width, height) * .34f
        val x = width / 2f
        val y = height / 2f
        val accent = if (connecting) 0xFFB4A5FF.toInt() else 0xFF88E1CF.toInt()
        ink.style = Paint.Style.FILL
        ink.shader = RadialGradient(x, y, r * 1.4f, intArrayOf(if (connected) 0x303DE4B9 else 0x2045A2A0, Color.TRANSPARENT), null, Shader.TileMode.CLAMP)
        canvas.drawCircle(x, y, r * 1.4f, ink)
        ink.shader = null
        ink.style = Paint.Style.STROKE
        ink.strokeWidth = resources.displayMetrics.density
        ink.color = 0xFF24394B.toInt()
        canvas.drawCircle(x, y, r, ink)
        for (scale in listOf(.35f, .7f)) {
            canvas.drawOval(RectF(x-r*scale, y-r, x+r*scale, y+r), ink)
            canvas.drawOval(RectF(x-r, y-r*scale, x+r, y+r*scale), ink)
        }
        ink.color = accent
        ink.strokeWidth = resources.displayMetrics.density * 2
        canvas.drawArc(RectF(x-r, y-r, x+r, y+r), -70f, if (connected) 320f else if (connecting) 200f else 100f, false, ink)
        ink.style = Paint.Style.FILL
        ink.color = 0xFF172B37.toInt()
        canvas.drawCircle(x, y, r * .58f, ink)
        ink.style = Paint.Style.STROKE
        ink.color = accent
        canvas.drawCircle(x, y, r * .58f, ink)
        ink.strokeWidth = resources.displayMetrics.density * 4
        ink.strokeCap = Paint.Cap.ROUND
        val p = r * .22f
        canvas.drawArc(RectF(x-p, y-p, x+p, y+p), -45f, 270f, false, ink)
        canvas.drawLine(x, y-p*1.35f, x, y-p*.1f, ink)
        ink.strokeCap = Paint.Cap.BUTT
        if (isFocused) {
            ink.strokeWidth = resources.displayMetrics.density * 2
            canvas.drawCircle(x, y, r * 1.12f, ink)
        }
    }
}
