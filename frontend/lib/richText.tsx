import React from 'react';

// Pazarlama/paket açıklamaları kaynak metinde markdown **kalın** işaretleri içerir. Bu metinler
// düz metin olarak basıldığında kullanıcıya "**" olarak sızıyordu (UI hatası). Aşağıdaki yardımcı
// yalnızca **...** kalıplarını gerçek <strong>'a çevirir (başka markdown YOK — güvenli/dar kapsam).
// Dengesiz (tek/eşleşmemiş) ** varsa güvenli tarafta kalıp işaretleri temizler, asla yanlış kalın yapmaz.
export function renderEmphasis(text: string | null | undefined): React.ReactNode {
  if (!text || !text.includes('**')) return text ?? '';
  const parts = text.split('**');
  // Dengeli çift → parça sayısı TEK olur (a**b**c → 3). Çift ise eşleşmemiş demektir → sadece temizle.
  if (parts.length % 2 === 0) return text.replace(/\*\*/g, '');
  return parts.map((p, i) =>
    i % 2 === 1 ? <strong key={i}>{p}</strong> : <React.Fragment key={i}>{p}</React.Fragment>,
  );
}

// Yapısal veri (JSON-LD), meta ve düz-metin bağlamları için: kalın işaretlerini tamamen kaldırır.
export function stripEmphasis(text: string | null | undefined): string {
  return (text ?? '').replace(/\*\*/g, '');
}
