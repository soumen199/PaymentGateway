package com.example.demopayment

import android.annotation.SuppressLint
import android.app.Activity
import android.os.Bundle
import android.os.Parcel
import android.os.Parcelable
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.activity.ComponentActivity
import com.razorpay.Checkout
import com.razorpay.PaymentData
import com.razorpay.PaymentResultWithDataListener
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class MainActivity : ComponentActivity(), PaymentResultWithDataListener {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Checkout.preload(applicationContext)
        val button = findViewById<Button>(R.id.button)
        button.setOnClickListener {
            CoroutineScope(Dispatchers.IO).launch {
                initPayment()
            }
        }
    }

    private suspend fun initPayment() {
        withContext(Dispatchers.Main) {
            val activity: Activity = this@MainActivity
            val co = Checkout()
            co.setKeyID("rzp_test_Nqy8gmPWtyPySL") // Replace with your key

            try {
                val options = JSONObject()
                options.put("name", "Demo Payment")
                options.put("description", "Demoing Charges")
                options.put("image", "http://example.com/image/rzp.jpg")
                options.put("theme.color", "#3399cc")
                options.put("currency", "INR")
                options.put("amount", "50000") // Amount in subunits

                val retryObj = JSONObject()
                retryObj.put("enabled", true)
                retryObj.put("max_count", 4)
                options.put("retry", retryObj)

                val prefill = JSONObject()
                prefill.put("email", "demo@example.com")
                prefill.put("contact", "9876543210")
                options.put("prefill", prefill)

                co.open(activity, options)
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, "Error in payment: " + e.message, Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onPaymentSuccess(paymentId: String?, paymentData: PaymentData?) {
        Toast.makeText(this, "Payment Success", Toast.LENGTH_SHORT).show()
    }

    override fun onPaymentError(code: Int, response: String?, paymentData: PaymentData?) {
        Toast.makeText(this, "Error: $response", Toast.LENGTH_SHORT).show()
    }
}

