package com.example.demopayment

import android.app.Activity
import android.widget.Toast
import com.razorpay.Checkout
import org.json.JSONObject

class PaymentManager(private val activity: Activity) {

    private val checkout = Checkout().apply {
        setKeyID("rzp_test_Nqy8gmPWtyPySL")  // Your Razorpay Test Key
    }

    fun initPayment(amount: Int, description: String) {
        try {
            val options = JSONObject().apply {
                put("name", "Demo Payment")
                put("description", description)
                put("image", "https://example.com/logo.png")  // Optional image
                put("currency", "INR")
                put("amount", amount * 100)  // Amount in subunits
                put("theme.color", "#3399cc")

                // Prefill customer details for convenience
                put("prefill", JSONObject().apply {
                    put("email", "customer@example.com")
                    put("contact", "9999999999")
                })

                // Retry option in case of payment failure
                put("retry", JSONObject().apply {
                    put("enabled", true)
                    put("max_count", 4)
                })
            }
            checkout.open(activity, options)
        } catch (e: Exception) {
            Toast.makeText(activity, "Payment initialization failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
