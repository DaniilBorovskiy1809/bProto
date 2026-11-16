package dev.bproto

import android.content.Context
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import org.json.JSONArray
import org.json.JSONObject

object RoutingDialog {
    fun show(context: Context, original: RoutingPolicy, save: (RoutingPolicy) -> Unit) {
        val container = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 16, 32, 16) }
        fun input(label: String, values: List<String>): EditText = EditText(context).apply {
            hint = label
            setText(values.joinToString("\n"))
            minLines = 2
            contentDescription = label
            container.addView(this)
        }
        val routes = input("IPv4 networks, one CIDR per line", original.routes)
        val dns = input("DNS IPv4 addresses", original.dns)
        val bypass = input("Applications outside VPN, package names", original.bypassApps)
        val dialog = AlertDialog.Builder(context).setTitle("Routing · this server")
            .setView(container).setNegativeButton("Cancel", null).setPositiveButton("Save", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                fun entries(field: EditText) = JSONArray(field.text.toString().lines().map { it.trim() }.filter { it.isNotEmpty() })
                runCatching {
                    RoutingPolicy.parse(JSONObject().put("routes", entries(routes)).put("dns", entries(dns)).put("bypass_apps", entries(bypass)))
                }.onSuccess { save(it); dialog.dismiss() }
                    .onFailure { Toast.makeText(context, it.message ?: "Invalid routing", Toast.LENGTH_LONG).show() }
            }
        }
        dialog.show()
    }
}
