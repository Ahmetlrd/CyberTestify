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

/** Belirli droplet IP'sine read-only SSH exec üreten factory (BatchMode; parola sormaz). */
export function makeSshExec(ip: string, keyPath = redteamKeyPath()): RemoteExec {
  return async (remoteCmd: string) => {
    try {
      const { stdout, stderr } = await execFileAsync(
        'ssh',
        ['-i', keyPath, '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes',
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
