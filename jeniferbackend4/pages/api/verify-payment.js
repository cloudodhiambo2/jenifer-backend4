/**
 * API Route: /api/verify-payment
 * Handles payment verification webhooks from Polar
 */

import crypto from 'crypto';

// Polar API Configuration
const POLAR_API_BASE_URL = process.env.POLAR_API_BASE_URL || 'https://api.polar.sh/v1';
const POLAR_API_KEY = process.env.POLAR_API_KEY;
const POLAR_WEBHOOK_SECRET = process.env.POLAR_WEBHOOK_SECRET;

export default async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Extract webhook signature from headers
    const signature = req.headers['x-polar-signature'] || req.headers['polar-signature'];
    
    // Verify webhook signature if secret is configured
    if (POLAR_WEBHOOK_SECRET && signature) {
      const rawBody = typeof req.body === 'string' 
        ? req.body 
        : JSON.stringify(req.body);
      
      const isValid = verifyPolarSignature(
        rawBody,
        signature,
        POLAR_WEBHOOK_SECRET
      );

      if (!isValid) {
        console.error('Invalid webhook signature');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }

    // Extract webhook data
    const webhookData = req.body;
    const eventType = webhookData.type || webhookData.event;

    // Verify payment with Polar API before processing
    const paymentId = extractPaymentId(webhookData);
    if (paymentId) {
      const isValidPayment = await verifyPaymentWithPolar(paymentId);
      
      if (!isValidPayment) {
        console.error('Payment verification failed with Polar API');
        return res.status(400).json({ error: 'Payment verification failed' });
      }
    }

    // Handle different webhook event types
    switch (eventType) {
      case 'payment.succeeded':
      case 'payment.completed':
      case 'checkout.succeeded':
        await handlePaymentSuccess(webhookData);
        break;

      case 'payment.failed':
      case 'payment.cancelled':
      case 'checkout.failed':
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
  try {
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
  } catch (error) {
    console.error('Error verifying signature:', error);
    return false;
  }
}

/**
 * Extract payment ID from webhook data
 * @param {Object} webhookData - Webhook payload
 * @returns {string|null} - Payment ID or null
 */
function extractPaymentId(webhookData) {
  // Try different possible structures
  return webhookData.data?.id || 
         webhookData.data?.payment_id || 
         webhookData.payment_id || 
         webhookData.id ||
         webhookData.data?.checkout_id ||
         null;
}

/**
 * Verify payment with Polar API
 * @param {string} paymentId - Payment ID to verify
 * @returns {Promise<boolean>} - Whether the payment is valid
 */
async function verifyPaymentWithPolar(paymentId) {
  if (!POLAR_API_KEY) {
    console.warn('POLAR_API_KEY not configured, skipping API verification');
    return true; // Allow if API key is not configured
  }

  try {
    // Fetch payment details from Polar API
    const response = await fetch(`${POLAR_API_BASE_URL}/payments/${paymentId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${POLAR_API_KEY}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      console.error(`Polar API error: ${response.status} ${response.statusText}`);
      return false;
    }

    const paymentData = await response.json();
    
    // Verify payment status
    const status = paymentData.status || paymentData.state;
    const validStatuses = ['succeeded', 'completed', 'paid'];
    
    return validStatuses.includes(status?.toLowerCase());
    
  } catch (error) {
    console.error('Error verifying payment with Polar API:', error);
    return false;
  }
}

/**
 * Handle successful payment
 * @param {Object} data - Webhook data
 */
async function handlePaymentSuccess(data) {
  console.log('Payment succeeded:', data);
  
  // Extract payment information
  const paymentId = extractPaymentId(data);
  const amount = data.data?.amount || data.amount || data.data?.amount_cents;
  const currency = data.data?.currency || data.currency || 'USD';
  const customerId = data.data?.customer_id || data.customer_id || data.data?.user_id;
  const productId = data.data?.product_id || data.product_id;
  const subscriptionId = data.data?.subscription_id || data.subscription_id;

  // Verify payment one more time with Polar API for additional security
  if (paymentId && POLAR_API_KEY) {
    const isValid = await verifyPaymentWithPolar(paymentId);
    if (!isValid) {
      console.error(`Payment ${paymentId} failed final verification`);
      throw new Error('Payment verification failed');
    }
  }

  // TODO: Update your database
  // Example:
  // await updatePaymentStatus(paymentId, 'completed', {
  //   amount,
  //   currency,
  //   customerId,
  //   productId,
  //   subscriptionId
  // });
  // await grantAccess(customerId, productId);

  // TODO: Send confirmation email, update user subscription, etc.
  console.log(`Payment ${paymentId} verified and processed successfully`);
}

/**
 * Handle failed payment
 * @param {Object} data - Webhook data
 */
async function handlePaymentFailure(data) {
  console.log('Payment failed:', data);
  
  const paymentId = extractPaymentId(data);
  const reason = data.data?.failure_reason || data.failure_reason || data.data?.error || 'Unknown error';
  const customerId = data.data?.customer_id || data.customer_id || data.data?.user_id;

  // Verify payment status with Polar API
  if (paymentId && POLAR_API_KEY) {
    try {
      const response = await fetch(`${POLAR_API_BASE_URL}/payments/${paymentId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${POLAR_API_KEY}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const paymentData = await response.json();
        console.log(`Payment ${paymentId} status confirmed: ${paymentData.status || paymentData.state}`);
      }
    } catch (error) {
      console.error('Error fetching payment status:', error);
    }
  }

  // TODO: Update payment status in database
  // await updatePaymentStatus(paymentId, 'failed', {
  //   reason,
  //   customerId,
  //   failedAt: new Date()
  // });

  // TODO: Notify user, log for review, etc.
  console.log(`Payment ${paymentId} failed: ${reason}`);
}

/**
 * Handle payment refund
 * @param {Object} data - Webhook data
 */
async function handlePaymentRefund(data) {
  console.log('Payment refunded:', data);
  
  const paymentId = extractPaymentId(data);
  const refundAmount = data.data?.refund_amount || data.refund_amount || data.data?.amount;
  const customerId = data.data?.customer_id || data.customer_id || data.data?.user_id;
  const productId = data.data?.product_id || data.product_id;

  // Verify refund with Polar API
  if (paymentId && POLAR_API_KEY) {
    try {
      const response = await fetch(`${POLAR_API_BASE_URL}/payments/${paymentId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${POLAR_API_KEY}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const paymentData = await response.json();
        const status = paymentData.status || paymentData.state;
        console.log(`Payment ${paymentId} refund status confirmed: ${status}`);
      }
    } catch (error) {
      console.error('Error verifying refund:', error);
    }
  }

  // TODO: Update payment status, revoke access, etc.
  // await updatePaymentStatus(paymentId, 'refunded', {
  //   refundAmount,
  //   refundedAt: new Date()
  // });
  // await revokeAccess(customerId, productId);

  console.log(`Payment ${paymentId} refunded: ${refundAmount}`);
}

