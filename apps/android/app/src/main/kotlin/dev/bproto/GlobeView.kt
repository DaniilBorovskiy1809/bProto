package dev.bproto

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import kotlin.math.min

/** Accessible connection control; the globe does not imply server geolocation. */
class GlobeView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {
    private val ink = Paint(Paint.ANTI_ALIAS_FLAG)
    var connected = false
        set(value) { field = value; invalidate(); contentDescription = if (value) "Disconnect VPN" else "Connect selected server" }

    init {
        isClickable = true
        isFocusable = true
        contentDescription = "Connect selected server"
    }

    override fun performClick(): Boolean {
        super.performClick()
        return true
    }

    override fun onTouchEvent(event: android.view.MotionEvent): Boolean {
        if (!isEnabled) return false
        if (event.action == android.view.MotionEvent.ACTION_UP) {
            performClick()
            return true
        }
        return event.action == android.view.MotionEvent.ACTION_DOWN
    }

    override fun onInitializeAccessibilityNodeInfo(info: android.view.accessibility.AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        info.className = android.widget.Button::class.java.name
        info.isClickable = true
        info.isEnabled = isEnabled
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val radius = min(width, height) * .36f
        val x = width / 2f
        val y = height / 2f
        ink.style = Paint.Style.FILL
        ink.color = Color.rgb(15, 33, 58)
        canvas.drawCircle(x, y, radius * 1.18f, ink)
        ink.color = if (connected) Color.rgb(67, 224, 173) else Color.rgb(96, 165, 250)
        ink.style = Paint.Style.STROKE
        ink.strokeWidth = resources.displayMetrics.density * 1.5f
        canvas.drawCircle(x, y, radius, ink)
        for (scale in listOf(.35f, .7f)) {
            canvas.drawOval(RectF(x - radius * scale, y - radius, x + radius * scale, y + radius), ink)
            canvas.drawOval(RectF(x - radius, y - radius * scale, x + radius, y + radius * scale), ink)
        }
        canvas.drawLine(x - radius, y, x + radius, y, ink)
        ink.style = Paint.Style.FILL
        canvas.drawCircle(x + radius * .55f, y - radius * .4f, radius * .07f, ink)
    }
}
