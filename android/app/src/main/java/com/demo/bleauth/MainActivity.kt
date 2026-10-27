package com.demo.bleauth

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.demo.bleauth.ble.HybridSession
import com.demo.bleauth.databinding.ActivityMainBinding
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity(), HybridSession.Ui {

    private lateinit var binding: ActivityMainBinding
    private var session: HybridSession? = null
    private var approvalDialog: AlertDialog? = null
    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

    private val blePermissions: Array<String> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            emptyArray()
        }

    private val permissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
            if (granted.values.all { it }) ensureBluetoothOn() else setStatus("Bluetooth permissions are required")
        }

    private val enableBluetoothLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (bluetoothAdapter()?.isEnabled == true) launchScanner() else setStatus("Bluetooth must be on")
        }

    private val scanLauncher = registerForActivityResult(ScanContract()) { result ->
        result.contents?.let(::onQrScanned)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.scan.setOnClickListener { startFlow() }
        binding.cancel.setOnClickListener { session?.cancel() }
    }

    override fun onDestroy() {
        session?.cancel()
        super.onDestroy()
    }

    private fun startFlow() {
        val missing = blePermissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) permissionLauncher.launch(missing.toTypedArray()) else ensureBluetoothOn()
    }

    private fun ensureBluetoothOn() {
        val adapter = bluetoothAdapter() ?: return setStatus("This device has no Bluetooth")
        if (adapter.isEnabled) launchScanner()
        else enableBluetoothLauncher.launch(Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE))
    }

    private fun launchScanner() {
        scanLauncher.launch(
            ScanOptions()
                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                .setPrompt("Scan the browser QR code")
                .setBeepEnabled(false)
                .setOrientationLocked(false),
        )
    }

    private fun onQrScanned(text: String) {
        val qr = try {
            QrPayload.parse(text)
        } catch (e: Exception) {
            return setStatus("Invalid QR: ${e.message}")
        }
        session?.cancel()
        binding.log.text = ""
        binding.code.visibility = View.GONE
        appendLog("QR scanned, ${qr.secondsLeft()}s left")
        session = HybridSession(this, qr, this).also { it.start() }
        binding.scan.isEnabled = false
        binding.cancel.isEnabled = true
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }

    // ---------- HybridSession.Ui (main thread) ----------

    override fun onState(state: HybridSession.State, detail: String) {
        setStatus(detail)
        if (state == HybridSession.State.DONE || state == HybridSession.State.ERROR) {
            approvalDialog?.dismiss()
            binding.scan.isEnabled = true
            binding.cancel.isEnabled = false
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
    }

    override fun onLog(message: String) = appendLog(message)

    override fun onApprovalRequest(request: HybridSession.ApprovalRequest) {
        binding.code.text = request.code
        binding.code.visibility = View.VISIBLE
        approvalDialog = AlertDialog.Builder(this)
            .setTitle("Approve sign-in?")
            .setMessage(
                "Origin: ${request.origin}\n" +
                    "Browser: ${request.browser}\n\n" +
                    "Code: ${request.code}\n" +
                    "Only approve if this code matches the one in the browser.",
            )
            .setCancelable(false)
            .setPositiveButton("Approve") { _, _ -> session?.respond(true) }
            .setNegativeButton("Reject") { _, _ -> session?.respond(false) }
            .show()
    }

    // ---------- helpers ----------

    private fun bluetoothAdapter(): BluetoothAdapter? = getSystemService(BluetoothManager::class.java)?.adapter

    private fun setStatus(text: String) {
        binding.status.text = text
    }

    private fun appendLog(message: String) {
        binding.log.append("[${timeFormat.format(Date())}] $message\n")
        binding.logScroll.post { binding.logScroll.fullScroll(View.FOCUS_DOWN) }
    }
}
