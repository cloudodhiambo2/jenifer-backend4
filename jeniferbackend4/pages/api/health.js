/**
 * Health check endpoint to verify API routes are working
 */
export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  return res.status(200).json({
    status: 'ok',
    message: 'API routes are working',
    timestamp: new Date().toISOString()
  });
}

