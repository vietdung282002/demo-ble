package com.demo.bleauth.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import java.io.ByteArrayOutputStream
import java.util.ArrayDeque
import java.util.UUID

/**
 * GATT server + advertiser. The browser (Web Bluetooth central) connects to us; the advert carries
 * the encrypted EID so only a client holding the QR secret can recognise this phone.
 *
 * Callers must hold BLUETOOTH_ADVERTISE / BLUETOOTH_CONNECT before calling [start].
 */
@SuppressLint("MissingPermission")
class BlePeripheral(
    private val context: Context,
    private val eid: ByteArray,
    private val listener: Listener,
) {
    interface Listener {
        fun onLog(message: String)
        fun onAdvertising()
        fun onCentralConnected(address: String)
        fun onCentralDisconnected(address: String)
        fun onMessage(type: Int, payload: ByteArray)
        fun onFatal(message: String)
    }

    companion object {
        val SERVICE_UUID: UUID = UUID.fromString("0000fff3-0000-1000-8000-00805f9b34fb")
        val EID_CHAR_UUID: UUID = UUID.fromString("b1e0a001-6f2c-4d6e-9d1a-5c3e0f7a2b01")
        val RX_CHAR_UUID: UUID = UUID.fromString("b1e0a001-6f2c-4d6e-9d1a-5c3e0f7a2b02")
        val TX_CHAR_UUID: UUID = UUID.fromString("b1e0a001-6f2c-4d6e-9d1a-5c3e0f7a2b03")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        const val MSG_HANDSHAKE_1 = 0x01
        const val MSG_HANDSHAKE_2 = 0x02
        const val MSG_DATA = 0x03
        const val MSG_ERROR = 0x7f

        private const val LAST_CHUNK = 0x80
        private const val DEFAULT_MTU = 23
    }

    private val manager = context.getSystemService(BluetoothManager::class.java)
    private val advertiser get() = manager.adapter.bluetoothLeAdvertiser
    private var server: BluetoothGattServer? = null
    private lateinit var txChar: BluetoothGattCharacteristic

    // Only one central may talk to us per session.
    private var central: BluetoothDevice? = null
    private var mtu = DEFAULT_MTU
    private var notificationsEnabled = false
    private val rxBuffer = ByteArrayOutputStream()
    private val preparedWrite = ByteArrayOutputStream()
    private val txQueue = ArrayDeque<ByteArray>()
    private var txInFlight = false
    private var advertisingWithName = true
    private var advertising = false

    fun start() {
        val adapter = manager.adapter
        if (adapter == null || !adapter.isEnabled) return listener.onFatal("Bluetooth is off")
        if (advertiser == null) return listener.onFatal("This device cannot advertise BLE")

        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                EID_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ,
            ),
        )
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                RX_CHAR_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_WRITE,
            ),
        )
        txChar = BluetoothGattCharacteristic(
            TX_CHAR_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            0,
        ).apply {
            addDescriptor(
                BluetoothGattDescriptor(
                    CCCD_UUID,
                    BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
                ),
            )
        }
        service.addCharacteristic(txChar)

        server = manager.openGattServer(context, gattCallback)
        if (server?.addService(service) != true) listener.onFatal("Failed to register GATT service")
        // Advertising starts in onServiceAdded.
    }

    fun stop() {
        if (advertising) advertiser?.stopAdvertising(advertiseCallback)
        advertising = false
        central?.let { server?.cancelConnection(it) }
        server?.close()
        server = null
    }

    fun stopAdvertising() {
        if (advertising) advertiser?.stopAdvertising(advertiseCallback)
        advertising = false
    }

    /** Sends one framed message `[type][payload]` as notifications of at most (MTU - 3) bytes. */
    @Synchronized
    fun send(type: Int, payload: ByteArray) {
        if (central == null || !notificationsEnabled) {
            listener.onLog("Cannot send: browser not subscribed")
            return
        }
        val msg = byteArrayOf(type.toByte()) + payload
        val chunkPayload = mtu - 3 - 1
        var off = 0
        while (off < msg.size) {
            val end = minOf(off + chunkPayload, msg.size)
            val flags = if (end == msg.size) LAST_CHUNK else 0
            txQueue.add(byteArrayOf(flags.toByte()) + msg.copyOfRange(off, end))
            off = end
        }
        pumpTx()
    }

    @Synchronized
    private fun pumpTx() {
        if (txInFlight) return
        val chunk = txQueue.poll() ?: return
        val device = central ?: return
        txInFlight = true
        val ok = if (Build.VERSION.SDK_INT >= 33) {
            server?.notifyCharacteristicChanged(device, txChar, false, chunk) == BluetoothGatt.GATT_SUCCESS
        } else {
            @Suppress("DEPRECATION")
            txChar.value = chunk
            @Suppress("DEPRECATION")
            server?.notifyCharacteristicChanged(device, txChar, false) == true
        }
        if (!ok) {
            txInFlight = false
            listener.onLog("notifyCharacteristicChanged failed")
        }
    }

    private fun startAdvertising() {
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            // Low TX power keeps the radio range short, which is the point of the proximity check.
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_LOW)
            .setConnectable(true)
            .setTimeout(0)
            .build()
        // flags(3) + 16-bit UUID list(4) + service data(2 + 2 + 20) = 31 bytes: exactly a legacy advert.
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .addServiceData(ParcelUuid(SERVICE_UUID), eid)
            .build()
        if (advertisingWithName) {
            // Device name in the scan response so the browser chooser shows something readable.
            val scanResponse = AdvertiseData.Builder().setIncludeDeviceName(true).build()
            advertiser.startAdvertising(settings, data, scanResponse, advertiseCallback)
        } else {
            advertiser.startAdvertising(settings, data, advertiseCallback)
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            advertising = true
            listener.onAdvertising()
        }

        override fun onStartFailure(errorCode: Int) {
            if (errorCode == ADVERTISE_FAILED_DATA_TOO_LARGE && advertisingWithName) {
                listener.onLog("Device name too long for scan response, advertising without it")
                advertisingWithName = false
                startAdvertising()
            } else {
                listener.onFatal("Advertising failed (error $errorCode)")
            }
        }
    }

    private val gattCallback = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            if (status == BluetoothGatt.GATT_SUCCESS) startAdvertising()
            else listener.onFatal("GATT service add failed ($status)")
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                if (central == null) {
                    central = device
                    mtu = DEFAULT_MTU
                    listener.onCentralConnected(device.address)
                } else if (central != device) {
                    listener.onLog("Rejecting second central ${device.address}")
                    server?.cancelConnection(device)
                }
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED && device == central) {
                central = null
                notificationsEnabled = false
                synchronized(this@BlePeripheral) {
                    txQueue.clear()
                    txInFlight = false
                }
                rxBuffer.reset()
                listener.onCentralDisconnected(device.address)
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, newMtu: Int) {
            if (device == central) {
                mtu = newMtu
                listener.onLog("MTU = $newMtu")
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic,
        ) {
            if (characteristic.uuid == EID_CHAR_UUID && device == central && offset <= eid.size) {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, eid.copyOfRange(offset, eid.size))
            } else {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, offset, null)
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            val accepted = characteristic.uuid == RX_CHAR_UUID && device == central
            if (accepted) {
                if (preparedWrite) {
                    // Long write (chunk bigger than MTU): buffered until onExecuteWrite.
                    this@BlePeripheral.preparedWrite.write(value)
                } else {
                    onChunk(value)
                }
            }
            if (responseNeeded) {
                val status = if (accepted) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_WRITE_NOT_PERMITTED
                server?.sendResponse(device, requestId, status, offset, value)
            }
        }

        override fun onExecuteWrite(device: BluetoothDevice, requestId: Int, execute: Boolean) {
            if (execute && device == central) onChunk(preparedWrite.toByteArray())
            preparedWrite.reset()
            server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            if (descriptor.uuid == CCCD_UUID && device == central) {
                notificationsEnabled = value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                listener.onLog("Notifications ${if (notificationsEnabled) "enabled" else "disabled"}")
            }
            if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
        }

        override fun onDescriptorReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            descriptor: BluetoothGattDescriptor,
        ) {
            val value = if (notificationsEnabled) BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            else BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
            server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, value)
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            synchronized(this@BlePeripheral) { txInFlight = false }
            pumpTx()
        }
    }

    private fun onChunk(chunk: ByteArray) {
        if (chunk.isEmpty()) return
        rxBuffer.write(chunk, 1, chunk.size - 1)
        if (chunk[0].toInt() and LAST_CHUNK == 0) return
        val msg = rxBuffer.toByteArray()
        rxBuffer.reset()
        if (msg.isNotEmpty()) listener.onMessage(msg[0].toInt() and 0xff, msg.copyOfRange(1, msg.size))
    }
}
