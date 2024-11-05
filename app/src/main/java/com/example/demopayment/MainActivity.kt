package com.example.demopayment

import android.annotation.SuppressLint
import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.razorpay.Checkout
import com.razorpay.PaymentData
import com.razorpay.PaymentResultWithDataListener
import org.json.JSONObject

class MainActivity : ComponentActivity(), PaymentResultWithDataListener {

    private lateinit var paymentManager: PaymentManager

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
                paymentManager.initPayment(amount, "Demo Payment")
            } else {
                Toast.makeText(this, "Enter a valid amount", Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onPaymentSuccess(razorpayPaymentID: String?, paymentData: PaymentData?) {
        Toast.makeText(this, "Payment Successful: ID - $razorpayPaymentID", Toast.LENGTH_SHORT).show()
    }

    override fun onPaymentError(errorCode: Int, errorDescription: String?, paymentData: PaymentData?) {
        Toast.makeText(this, "Payment Failed: $errorDescription (Code: $errorCode)", Toast.LENGTH_LONG).show()
    }
}
