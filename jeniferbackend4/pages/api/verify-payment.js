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
    return res.status(405).json({ 
      success: false,
      error: 'Method not allowed',
      message: 'Only POST requests are accepted' 
    });
  }

  try {
    // Parse incoming request body
    let requestBody = req.body;
    
    // Handle raw body if needed (for signature verification)
    if (!requestBody || Object.keys(requestBody).length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid request',
        message: 'Request body is empty or invalid'
      });
    }

    // Extract webhook signature from headers
    const signature = req.headers['x-polar-signature'] || 
                     req.headers['polar-signature'] ||
                     req.headers['x-signature'];
    
    // Verify webhook signature if secret is configured
    if (POLAR_WEBHOOK_SECRET && signature) {
      const rawBody = typeof requestBody === 'string' 
        ? requestBody 
        : JSON.stringify(requestBody);
      
      const isValid = verifyPolarSignature(
        rawBody,
        signature,
        POLAR_WEBHOOK_SECRET
      );

      if (!isValid) {
        console.error('Invalid webhook signature');
        return res.status(401).json({ 
          success: false,
          error: 'Invalid signature',
          message: 'Webhook signature verification failed'
        });
      }
    }

    // Parse payment details from webhook data
    const paymentDetails = parsePaymentDetails(requestBody);
    
    if (!paymentDetails.paymentId) {
      return res.status(400).json({
        success: false,
        error: 'Invalid payment data',
        message: 'Payment ID not found in request'
      });
    }

    // Verify payment status using Polar API
    const verificationResult = await verifyPaymentWithPolar(paymentDetails.paymentId);
    
    if (!verificationResult.success) {
      console.error('Payment verification failed:', verificationResult.error);
      return res.status(400).json({
        success: false,
        error: 'Payment verification failed',
        message: verificationResult.message || 'Could not verify payment with Polar API',
        paymentId: paymentDetails.paymentId
      });
    }

    // Extract event type
    const eventType = requestBody.type || requestBody.event || paymentDetails.eventType;

    // Handle different webhook event types based on verification result
    let processingResult;
    switch (eventType) {
      case 'payment.succeeded':
      case 'payment.completed':
      case 'checkout.succeeded':
        processingResult = await handlePaymentSuccess(requestBody, paymentDetails, verificationResult.data);
        break;

      case 'payment.failed':
      case 'payment.cancelled':
      case 'checkout.failed':
        processingResult = await handlePaymentFailure(requestBody, paymentDetails);
        break;

      case 'payment.refunded':
        processingResult = await handlePaymentRefund(requestBody, paymentDetails);
        break;

      default:
        console.log(`Unhandled webhook event type: ${eventType}`);
        processingResult = {
          success: true,
          message: `Event type '${eventType}' received but not processed`
        };
    }

    // Return success response with verification details
    return res.status(200).json({ 
      success: true,
      message: 'Payment verified and processed successfully',
      verification: {
        verified: true,
        paymentId: paymentDetails.paymentId,
        status: verificationResult.data?.status || paymentDetails.status,
        verifiedAt: new Date().toISOString()
      },
      payment: {
        id: paymentDetails.paymentId,
        amount: paymentDetails.amount,
        currency: paymentDetails.currency,
        customerId: paymentDetails.customerId
      },
      processing: processingResult
    });

  } catch (error) {
    console.error('Error processing webhook:', error);
    return res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      message: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
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
 * Parse payment details from webhook data
 * @param {Object} webhookData - Webhook payload
 * @returns {Object} - Parsed payment details
 */
function parsePaymentDetails(webhookData) {
  // Extract payment ID from various possible structures
  const paymentId = webhookData.data?.id || 
                   webhookData.data?.payment_id || 
                   webhookData.payment_id || 
                   webhookData.id ||
                   webhookData.data?.checkout_id ||
                   webhookData.checkout_id ||
                   null;

  // Extract amount (handle both cents and decimal formats)
  const amountCents = webhookData.data?.amount_cents || 
                      webhookData.amount_cents ||
                      webhookData.data?.amount || 
                      webhookData.amount;
  const amount = amountCents ? (amountCents / 100).toFixed(2) : null;

  // Extract currency
  const currency = webhookData.data?.currency || 
                   webhookData.currency || 
                   'USD';

  // Extract customer/user information
  const customerId = webhookData.data?.customer_id || 
                    webhookData.customer_id || 
                    webhookData.data?.user_id ||
                    webhookData.user_id ||
                    webhookData.data?.customer?.id ||
                    null;

  // Extract product/subscription information
  const productId = webhookData.data?.product_id || 
                   webhookData.product_id ||
                   webhookData.data?.product?.id ||
                   null;

  const subscriptionId = webhookData.data?.subscription_id || 
                         webhookData.subscription_id ||
                         webhookData.data?.subscription?.id ||
                         null;

  // Extract status
  const status = webhookData.data?.status || 
                webhookData.status ||
                webhookData.data?.state ||
                webhookData.state ||
                null;

  // Extract event type
  const eventType = webhookData.type || 
                   webhookData.event ||
                   null;

  // Extract metadata
  const metadata = webhookData.data?.metadata || 
                  webhookData.metadata ||
                  {};

  // Extract timestamps
  const createdAt = webhookData.data?.created_at || 
                   webhookData.created_at ||
                   null;
  const updatedAt = webhookData.data?.updated_at || 
                   webhookData.updated_at ||
                   null;

  return {
    paymentId,
    amount: amount ? parseFloat(amount) : null,
    amountCents: amountCents || null,
    currency,
    customerId,
    productId,
    subscriptionId,
    status,
    eventType,
    metadata,
    createdAt,
    updatedAt,
    rawData: webhookData
  };
}

/**
 * Extract payment ID from webhook data (backward compatibility)
 * @param {Object} webhookData - Webhook payload
 * @returns {string|null} - Payment ID or null
 */
function extractPaymentId(webhookData) {
  const details = parsePaymentDetails(webhookData);
  return details.paymentId;
}

/**
 * Verify payment with Polar API
 * @param {string} paymentId - Payment ID to verify
 * @returns {Promise<Object>} - Verification result with success status and payment data
 */
async function verifyPaymentWithPolar(paymentId) {
  if (!POLAR_API_KEY) {
    console.warn('POLAR_API_KEY not configured, skipping API verification');
    return {
      success: true,
      message: 'API key not configured, verification skipped',
      data: null
    };
  }

  if (!paymentId) {
    return {
      success: false,
      error: 'Missing payment ID',
      message: 'Payment ID is required for verification'
    };
  }

  try {
    // Fetch payment details from Polar API
    const response = await fetch(`${POLAR_API_BASE_URL}/payments/${paymentId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${POLAR_API_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`Polar API error: ${response.status} ${response.statusText} - ${errorText}`);
      
      return {
        success: false,
        error: 'API verification failed',
        message: `Polar API returned ${response.status}: ${response.statusText}`,
        statusCode: response.status
      };
    }

    const paymentData = await response.json();
    
    // Verify payment status
    const status = paymentData.status || paymentData.state || paymentData.payment_status;
    const validStatuses = ['succeeded', 'completed', 'paid', 'processed'];
    const isValidStatus = status && validStatuses.includes(status.toLowerCase());
    
    if (!isValidStatus) {
      return {
        success: false,
        error: 'Invalid payment status',
        message: `Payment status '${status}' is not valid. Expected: ${validStatuses.join(', ')}`,
        data: paymentData
      };
    }

    return {
      success: true,
      message: 'Payment verified successfully',
      data: {
        ...paymentData,
        status: status.toLowerCase(),
        verifiedAt: new Date().toISOString()
      }
    };
    
  } catch (error) {
    console.error('Error verifying payment with Polar API:', error);
    return {
      success: false,
      error: 'Verification error',
      message: `Failed to verify payment: ${error.message}`,
      details: error
    };
  }
}

/**
 * Handle successful payment
 * @param {Object} webhookData - Original webhook data
 * @param {Object} paymentDetails - Parsed payment details
 * @param {Object} verificationData - Verification result from Polar API
 * @returns {Promise<Object>} - Processing result
 */
async function handlePaymentSuccess(webhookData, paymentDetails, verificationData) {
  console.log('Payment succeeded:', {
    paymentId: paymentDetails.paymentId,
    amount: paymentDetails.amount,
    currency: paymentDetails.currency,
    customerId: paymentDetails.customerId
  });

  // TODO: Update your database
  // Example:
  // await updatePaymentStatus(paymentDetails.paymentId, 'completed', {
  //   amount: paymentDetails.amount,
  //   currency: paymentDetails.currency,
  //   customerId: paymentDetails.customerId,
  //   productId: paymentDetails.productId,
  //   subscriptionId: paymentDetails.subscriptionId,
  //   verifiedAt: new Date(),
  //   verificationData: verificationData
  // });
  // await grantAccess(paymentDetails.customerId, paymentDetails.productId);

  // TODO: Send confirmation email, update user subscription, etc.
  
  return {
    success: true,
    message: `Payment ${paymentDetails.paymentId} verified and processed successfully`,
    action: 'granted_access',
    timestamp: new Date().toISOString()
  };
}

/**
 * Handle failed payment
 * @param {Object} webhookData - Original webhook data
 * @param {Object} paymentDetails - Parsed payment details
 * @returns {Promise<Object>} - Processing result
 */
async function handlePaymentFailure(webhookData, paymentDetails) {
  console.log('Payment failed:', {
    paymentId: paymentDetails.paymentId,
    customerId: paymentDetails.customerId
  });
  
  const reason = webhookData.data?.failure_reason || 
                webhookData.failure_reason || 
                webhookData.data?.error || 
                webhookData.error ||
                'Unknown error';

  // Verify payment status with Polar API for confirmation
  if (paymentDetails.paymentId && POLAR_API_KEY) {
    try {
      const verificationResult = await verifyPaymentWithPolar(paymentDetails.paymentId);
      if (verificationResult.success) {
        console.log(`Payment ${paymentDetails.paymentId} status confirmed: ${verificationResult.data?.status}`);
      }
    } catch (error) {
      console.error('Error fetching payment status:', error);
    }
  }

  // TODO: Update payment status in database
  // await updatePaymentStatus(paymentDetails.paymentId, 'failed', {
  //   reason,
  //   customerId: paymentDetails.customerId,
  //   failedAt: new Date()
  // });

  // TODO: Notify user, log for review, etc.
  
  return {
    success: true,
    message: `Payment ${paymentDetails.paymentId} failure processed`,
    reason: reason,
    action: 'logged_failure',
    timestamp: new Date().toISOString()
  };
}

/**
 * Handle payment refund
 * @param {Object} webhookData - Original webhook data
 * @param {Object} paymentDetails - Parsed payment details
 * @returns {Promise<Object>} - Processing result
 */
async function handlePaymentRefund(webhookData, paymentDetails) {
  console.log('Payment refunded:', {
    paymentId: paymentDetails.paymentId,
    amount: paymentDetails.amount
  });
  
  const refundAmount = webhookData.data?.refund_amount || 
                      webhookData.refund_amount || 
                      paymentDetails.amount ||
                      null;

  // Verify refund with Polar API
  if (paymentDetails.paymentId && POLAR_API_KEY) {
    try {
      const verificationResult = await verifyPaymentWithPolar(paymentDetails.paymentId);
      if (verificationResult.success) {
        const status = verificationResult.data?.status || verificationResult.data?.state;
        console.log(`Payment ${paymentDetails.paymentId} refund status confirmed: ${status}`);
      }
    } catch (error) {
      console.error('Error verifying refund:', error);
    }
  }

  // TODO: Update payment status, revoke access, etc.
  // await updatePaymentStatus(paymentDetails.paymentId, 'refunded', {
  //   refundAmount: refundAmount || paymentDetails.amount,
  //   refundedAt: new Date()
  // });
  // await revokeAccess(paymentDetails.customerId, paymentDetails.productId);

  return {
    success: true,
    message: `Payment ${paymentDetails.paymentId} refund processed`,
    refundAmount: refundAmount || paymentDetails.amount,
    action: 'revoked_access',
    timestamp: new Date().toISOString()
  };
}

