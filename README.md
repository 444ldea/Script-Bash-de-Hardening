# harden.sh — Automatizaciones de hardening para Linux

Script único y **idempotente** para aplicar buenas prácticas de seguridad en servidores Linux (Debian/Ubuntu y RHEL/Rocky-like).

## Qué automatiza

- **Firewall**: UFW (Ubuntu/Debian) o **nftables** (fallback universal). Deny por defecto; permite SSH y puertos que indiques.  
- **SSH**: desactiva `root` por SSH, deshabilita password, deja **solo claves**; puerto configurable.  
- **MFA/OTP opcional**: configura PAM + OpenSSH para **publickey + OTP** (Google Authenticator).  
- **Fail2ban**: protege `sshd` y envía alertas por mail si configuras `--email`.  
- **Journald**: almacenamiento persistente, límites de tamaño y rate-limit.  
- **Parches automáticos**: `unattended-upgrades` (Debian/Ubuntu) o `dnf-automatic` (RHEL/Rocky).  
- **Auditoría**: `auditd` con reglas base + carga con `augenrules`.  
- **Lynis**: auditoría semanal (cron lunes 04:00).  
- **Backups opcionales**: `restic` diario 02:15 si defines variables `RESTIC_*`.

> El script hace **backup** de todo archivo modificado en `/root/hardening-backups/FECHA-HORA/`.

## Uso rápido

```bash
sudo bash harden.sh --all --firewall ufw --allow-ports "22,80,443" --email ops@midominio.com
