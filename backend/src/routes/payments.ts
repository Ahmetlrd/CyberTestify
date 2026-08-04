import { Router, urlencoded } from 'express';
import { config } from '../config.js';
import { handleIyzicoCallback } from '../services/payment/iyzico.js';

export const paymentsRouter = Router();

/**
 * iyzico CheckoutForm callback — iyzico odeme sonrasi bu URL'e tarayiciyi POST'la
 * yonlendirir (application/x-www-form-urlencoded, body.token). Token'i SUNUCU-TARAF
 * dogrulariz (retrieve); guvenilir olan iyzico'nun cevabidir, musteri degil.
 * Sonra tarayiciyi dashboard'a (basari) ya da order sayfasina (hata) yonlendiririz.
 */
paymentsRouter.post('/iyzico/callback', urlencoded({ extended: false }), async (req, res) => {
  const token = (req.body?.token as string) ?? '';
  try {
    const out = await handleIyzicoCallback(token);
    if (out.ok && out.orderId) {
      return res.redirect(303, `${config.frontendUrl}/dashboard/${out.orderId}`);
    }
    console.warn('[iyzico][callback] odeme dogrulanamadi:', out.error);
    const q = new URLSearchParams({ payment: 'failed', reason: out.error ?? 'unknown' }).toString();
    return res.redirect(303, `${config.frontendUrl}/order?${q}`);
  } catch (err) {
    console.error('[iyzico][callback] hata:', err);
    return res.redirect(303, `${config.frontendUrl}/order?payment=error`);
  }
});
