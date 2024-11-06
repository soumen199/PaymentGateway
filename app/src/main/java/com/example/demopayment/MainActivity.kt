package com.example.demopayment

import android.annotation.SuppressLint
import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.razorpay.Checkout
import com.razorpay.PaymentData
import com.razorpay.PaymentResultWithDataListener
import org.json.JSONObject
import android.app.AlertDialog
import android.util.Log




class MainActivity : ComponentActivity(), PaymentResultWithDataListener {

    private lateinit var paymentManager: PaymentManager
    companion object {
        // Load the native library on application startup.
        init {
            System.loadLibrary("native-lib")
        }
    }
    val ACTION_USB_PERMISSION = "com.example.demopayment.USB_PERMISSION"
    var fileDescriptor: Int = 0

    @SuppressLint("MissingInflatedId")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Checkout.preload(applicationContext)  // Preload Razorpay for faster response

        paymentManager = PaymentManager(this)

        val payButton = findViewById<Button>(R.id.button)
        val amountEditText = findViewById<EditText>(R.id.amountInput)

        payButton.setOnClickListener {
            val amount = amountEditText.text.toString().toIntOrNull()
            if (amount != null && amount > 0) {
//              add token check here
                showPinDialog { pin ->
                    val isConnected = isUsbTokenConnected(pin)
                    if (!isConnected) {
//                        Toast.makeText(this, "Failed to connect to USB Token", Toast.LENGTH_SHORT).show()
                        return@showPinDialog
                    }
                    // Use the entered PIN here
                    paymentManager.initPayment(amount, "Demo Payment")
                }
//                paymentManager.initPayment(amount, "Demo Payment")
            } else {
                Toast.makeText(this, "Enter a valid amount", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun showPinDialog(onPinEntered: (String) -> Unit) {
        val builder = AlertDialog.Builder(this)
        builder.setTitle("Enter PIN")

        val input = EditText(this,)
        input.inputType = android.text.InputType.TYPE_CLASS_NUMBER
        builder.setView(input)

        builder.setPositiveButton("OK") { dialog, _ ->
            val pin = input.text.toString()
            onPinEntered(pin)
            dialog.dismiss()
        }
        builder.setNegativeButton("Cancel") { dialog, _ ->
            dialog.cancel()
        }

        builder.show()
    }

    override fun onPaymentSuccess(razorpayPaymentID: String?, paymentData: PaymentData?) {
        Toast.makeText(this, "Payment Successful: ID - $razorpayPaymentID", Toast.LENGTH_SHORT).show()
    }

    override fun onPaymentError(errorCode: Int, errorDescription: String?, paymentData: PaymentData?) {
        Toast.makeText(this, "Payment Failed: $errorDescription (Code: $errorCode)", Toast.LENGTH_LONG).show()
    }

    private fun isUsbTokenConnected(pin: String): Boolean {
        fileDescriptor = detectSmartCard()
        if (fileDescriptor == -1) {
            Toast.makeText(this, "Failed to connect to USB Token", Toast.LENGTH_SHORT).show()
            return false
        }
        else if (fileDescriptor == 1) {
            Toast.makeText(this, "Permission denied", Toast.LENGTH_SHORT).show()
            return false
        }
        else{
            val resp = libint(fileDescriptor)
            if (resp != 0) {
                Toast.makeText(this, "Error occurred while connecting to USB Token", Toast.LENGTH_SHORT).show()
                return false
            }
            Log.d("MainActivity", resp.toString())
            Log.d("MainActivity", "Login called")
            val res = login(pin)
            Log.d("MainActivity", res)
            if (res=="Login Success") {
                Toast.makeText(this, "Login Successful", Toast.LENGTH_SHORT).show()
                return true
            }
            else {
                Toast.makeText(this, "Failed to login", Toast.LENGTH_SHORT).show()
                return false
            }
        }
    }
    fun detectSmartCard(): Int {
        val usbManager = getSystemService(Context.USB_SERVICE) as UsbManager?
        if (usbManager != null) {
            for (device in usbManager.deviceList.values) {
                if (isSmartCardReader(device)) {
                    val permissionIntent: PendingIntent =
                        PendingIntent.getBroadcast(
                            this,
                            0,
                            Intent(ACTION_USB_PERMISSION),
                            PendingIntent.FLAG_IMMUTABLE
                        )

                    usbManager.requestPermission(device, permissionIntent)
//                    while (!usbManager.hasPermission(device)) {
//                    usbManager.requestPermission(device, permissionIntent)
//                    }
//                    Thread.sleep(5000)
                    if (usbManager.hasPermission(device)) {
                        // check the extra permission
                        Log.d("device", device.toString())
                        return getFileDescriptor(usbManager, device)
                    }
                }
            }
        }
        return -1
    }

    private fun isSmartCardReader(device: UsbDevice): Boolean {
        val vendorId = 10381
        val productId = 64
        return device.vendorId == vendorId && device.productId == productId
    }

    private fun getFileDescriptor(manager: UsbManager, device: UsbDevice): Int {
        val connection = manager.openDevice(device)
        if (connection != null) {
            return connection.fileDescriptor
        }
        return -1
    }



    // Declare the native method
    external fun login(jstr: String): String
    external fun libint(fileDescriptor: Int): Int
    external fun readCertificate(): String
    external fun logout(): String
}
