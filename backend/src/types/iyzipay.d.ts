// iyzipay resmi Node SDK'sinin tip tanimi yok — kullandigimiz kadarini bildiriyoruz.
declare module 'iyzipay' {
  interface IyzipayOptions { apiKey: string; secretKey: string; uri: string; }
  type Callback = (err: unknown, result: any) => void;
  class Iyzipay {
    constructor(options: IyzipayOptions);
    checkoutFormInitialize: { create(request: Record<string, unknown>, cb: Callback): void };
    checkoutForm: { retrieve(request: Record<string, unknown>, cb: Callback): void };
    static LOCALE: { TR: string; EN: string };
    static CURRENCY: { TRY: string; USD: string; EUR: string; GBP: string };
    static PAYMENT_GROUP: { PRODUCT: string; LISTING: string; SUBSCRIPTION: string };
    static BASKET_ITEM_TYPE: { PHYSICAL: string; VIRTUAL: string };
  }
  export = Iyzipay;
}
