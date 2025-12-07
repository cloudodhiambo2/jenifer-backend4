/**
 * API Route: /api/verify-payment
 * Handles payment verification webhooks from Polar
 */

export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Extract webhook signature from headers
    const signature = req.headers['x-polar-signature'] || req.headers['polar-signature'];
    const webhookSecret = process.env.POLAR_WEBHOOK_SECRET;

    // Verify webhook signature if secret is configured
    if (webhookSecret && signature) {
      const isValid = verifyPolarSignature(
        JSON.stringify(req.body),
        signature,
        webhookSecret
      );

      if (!isValid) {
        console.error('Invalid webhook signature');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }

    // Extract webhook data
    const webhookData = req.body;
    const eventType = webhookData.type || webhookData.event;

    // Handle different webhook event types
    switch (eventType) {
      case 'payment.succeeded':
      case 'payment.completed':
        await handlePaymentSuccess(webhookData);
        break;

      case 'payment.failed':
      case 'payment.cancelled':
        await handlePaymentFailure(webhookData);
        break;

      case 'payment.refunded':
        await handlePaymentRefund(webhookData);
        break;

      default:
        console.log(`Unhandled webhook event type: ${eventType}`);
    }

    // Return success response
    return res.status(200).json({ 
      success: true, 
      message: 'Webhook processed successfully' 
    });

  } catch (error) {
    console.error('Error processing webhook:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
}

/**
 * Verify Polar webhook signature
 * @param {string} payload - The request body as a string
 * @param {string} signature - The signature from headers
 * @param {string} secret - The webhook secret
 * @returns {boolean} - Whether the signature is valid
 */
function verifyPolarSignature(payload, signature, secret) {
  const crypto = require('crypto');
  
  // Polar typically uses HMAC SHA256
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  // Compare signatures securely
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );
}

/**
 * Handle successful payment
 * @param {Object} data - Webhook data
 */
async function handlePaymentSuccess(data) {
  console.log('Payment succeeded:', data);
  
  // Extract payment information
  const paymentId = data.data?.id || data.payment_id;
  const amount = data.data?.amount || data.amount;
  const currency = data.data?.currency || data.currency;
  const customerId = data.data?.customer_id || data.customer_id;

  // TODO: Update your database
  // Example:
  // await updatePaymentStatus(paymentId, 'completed');
  // await grantAccess(customerId);

  // TODO: Send confirmation email, update user subscription, etc.
}

/**
 * Handle failed payment
 * @param {Object} data - Webhook data
 */
async function handlePaymentFailure(data) {
  console.log('Payment failed:', data);
  
  const paymentId = data.data?.id || data.payment_id;
  const reason = data.data?.failure_reason || data.failure_reason;

  // TODO: Update payment status in database
  // await updatePaymentStatus(paymentId, 'failed', reason);

  // TODO: Notify user, log for review, etc.
}

/**
 * Handle payment refund
 * @param {Object} data - Webhook data
 */
async function handlePaymentRefund(data) {
  console.log('Payment refunded:', data);
  
  const paymentId = data.data?.id || data.payment_id;
  const refundAmount = data.data?.refund_amount || data.refund_amount;

  // TODO: Update payment status, revoke access, etc.
  // await updatePaymentStatus(paymentId, 'refunded');
  // await revokeAccess(customerId);
}

