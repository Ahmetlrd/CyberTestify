-- (AKTİF paketler — ÇELİK KAPI) Ödeme alınmış olsa bile alan adı DNS ile doğrulanana
-- kadar aktif taramanın başlamadığı ara durum. Postgres 12+ enum'a değer eklemeye izin verir.
ALTER TYPE "OrderStatus" ADD VALUE IF NOT EXISTS 'awaiting_domain_verification';
