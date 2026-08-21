/**
 * (3b-ii) SSH KONTROL-KANALI — prod → droplet (outbound). Puller/kill bunu kullanır.
 * Droplet CyberTestify'a HİÇ bağlanmaz (PUSH yok); prod, read-only komutları buradan çalıştırır.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { config } from '../config.js';
import type { RemoteExec } from './puller.js';

const execFileAsync = promisify(execFile);

/** RedTeam SSH anahtar yolu (gitignored id_pentagi; prod host'a konur). Env ile override. */
export function redteamKeyPath(): string {
  return process.env.REDTEAM_SSH_KEY ?? 'infra/pentagi-isolated/id_pentagi';
}

/**
 * (KÖK-NEDEN DÜZELTME — setup exit 255 "REMOTE HOST IDENTIFICATION HAS CHANGED") EFEMER droplet host-key
 * opsiyonları. DigitalOcean IP'leri GERİ DÖNÜŞÜMLÜdür + fresh droplet ilk-boot'ta cloud-init host-key'leri
 * YENİDEN üretir → aynı IP'ye ait ESKİ anahtar api-container'ın kalıcı /root/.ssh/known_hosts'unda kalınca
 * sonraki bağlantı "anahtar DEĞİŞTİ" der ve `StrictHostKeyChecking=no` TEK BAŞINA bunu AŞMAZ (değişmiş/
 * çakışan anahtarda SSH auth'u kapatıp `Permission denied (publickey)` → exit 255 verir). Çözüm: known_hosts'u
 * HİÇ okuma/yazma → /dev/null. Efemer, sahibimiz, firewall-kilitli, sabit-anahtarlı droplet için güvenli.
 */
export const EPHEMERAL_SSH_HOSTKEY_OPTS = [
  '-o', 'StrictHostKeyChecking=no',
  '-o', 'UserKnownHostsFile=/dev/null',
  '-o', 'GlobalKnownHostsFile=/dev/null',
  '-o', 'LogLevel=ERROR', // "Warning: Permanently added ..." gürültüsünü sustur
];

/** Belirli droplet IP'sine read-only SSH exec üreten factory (BatchMode; parola sormaz). */
export function makeSshExec(ip: string, keyPath = redteamKeyPath()): RemoteExec {
  return async (remoteCmd: string) => {
    try {
      const { stdout, stderr } = await execFileAsync(
        'ssh',
        ['-i', keyPath, '-o', 'ConnectTimeout=10', ...EPHEMERAL_SSH_HOSTKEY_OPTS, '-o', 'BatchMode=yes',
          // Keepalive: uzun süren komut (setup: cloud-init/apt/docker-pull) sırasında oturum düşmesin.
          '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=8', `root@${ip}`, remoteCmd],
        { timeout: 900_000, maxBuffer: 8 * 1024 * 1024 }, // setup uzun sürebilir (docker pull kali)
      );
      return { code: 0, stdout, stderr };
    } catch (e: any) {
      return { code: typeof e?.code === 'number' ? e.code : 1, stdout: e?.stdout ?? '', stderr: e?.stderr ?? String(e?.message ?? e) };
    }
  };
}

// config referansı (ileride config.redteam eklenirse); şimdilik env yeterli.
void config;
