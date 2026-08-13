import type { ZodError } from 'zod';

/**
 * Zod doğrulama hatasını, kullanıcıya gösterilebilir TEK ve TEMİZ bir cümleye indirger.
 * Ham `error.flatten()` objesini ({formErrors, fieldErrors}) ASLA API yanıtına koyma —
 * frontend onu JSON.stringify edip "{"fieldErrors":...}" gibi çirkin bir metin gösteriyordu.
 * Bunun yerine ilk anlamlı alan/form hatasını döndür (şemalardaki Türkçe mesajlar).
 */
export function zodError(err: ZodError): string {
  const fe = err.flatten();
  for (const msgs of Object.values(fe.fieldErrors)) {
    if (Array.isArray(msgs) && msgs.length && msgs[0]) return String(msgs[0]);
  }
  if (fe.formErrors.length && fe.formErrors[0]) return String(fe.formErrors[0]);
  return 'Girdiğiniz bilgiler geçersiz. Lütfen kontrol edip tekrar deneyin.';
}
