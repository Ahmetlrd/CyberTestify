import { Router } from 'express';
import { verifyWebhookSignature, handlePaymentSucceeded } from '../services/payment/iyzico.js';

export const webhooksRouter = Router();

// Not: bu route'a express.raw() ile ham body verilmeli ki imza dogrulamasi
// calissin — server.ts'de bu route icin json() middleware'i BYPASS edilir.
webhooksRouter.post('/iyzico', async (req, res) => {
  const signature = req.header('x-iyzico-signature') ?? '';
  const rawBody = (req as any).rawBody as string;

  if (!verifyWebhookSignature(rawBody, signature)) {
    return res.status(401).json({ error: 'Gecersiz imza' });
  }

  const payload = JSON.parse(rawBody);
  if (payload.status === 'success') {
    await handlePaymentSucceeded(payload.conversationId);
  }

  res.json({ received: true });
});
