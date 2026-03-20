# Magento 2 PolyShell Vulnerability Scanner

A bash script to detect signs of compromise related to the [Magento PolyShell vulnerability](https://sansec.io/research/magento-polyshell).

This vulnerability allows attackers to upload polyglot files (executable code disguised as images) via the Magento REST API's file upload feature for product custom options. All Magento Open Source and Adobe Commerce versions through 2.4.9-alpha2 are potentially affected.

## Features

- **Auto-detection** of Magento 2 instances on the server (supports Capistrano-style deploys with `current` symlinks)
- **Upload directory scanning** (`custom_options/` and `tmp/`) for executable files and polyglot images
- **Permission checks** on upload directories (detects world-writable)
- **`.htaccess` protection** verification
- **Webshell detection** in `pub/media/`
- **Database check** for products with file-type custom options (attack surface)
- **Log analysis** for exploitation attempts
- **Multi-instance support** with per-instance and global summary
- **Exit codes** for monitoring integration (`0` = clean, `1` = alert, `2` = warning only)

## Installation

```bash
curl -o /usr/local/bin/polyshell_check.sh https://raw.githubusercontent.com/mabt/magento2-polyshell-check/main/polyshell_check.sh
chmod 755 /usr/local/bin/polyshell_check.sh
```

## Usage

```bash
# Auto-detect and scan all Magento instances
# Root scans /home/*, regular user scans $HOME only
polyshell_check.sh

# Scan a specific instance
polyshell_check.sh /path/to/magento2

# Quiet mode: only show instances with problems (for Ansible/cron)
polyshell_check.sh --quiet
polyshell_check.sh -q /path/to/magento2
```

### Ansible example

```yaml
- name: Deploy and run PolyShell scanner
  hosts: magento_servers
  tasks:
    - name: Install polyshell_check.sh
      get_url:
        url: https://raw.githubusercontent.com/mabt/magento2-polyshell-check/main/polyshell_check.sh
        dest: /usr/local/bin/polyshell_check.sh
        mode: "0755"

    - name: Run PolyShell scan
      command: /usr/local/bin/polyshell_check.sh --quiet
      register: scan_result
      failed_when: scan_result.rc == 1
      changed_when: false

    - name: Show results
      debug:
        msg: "{{ scan_result.stdout }}"
      when: scan_result.rc != 0
```

## Example output

```
============================================================
 [server01] Instance 1/3 : prod
============================================================
 Racine    : /home/user-prod/www/production/releases/20260319132459
 Home      : /home/user-prod
 Date      : 2026-03-20 14:40:41
------------------------------------------------------------

  [INFO] 1. Version de Magento
         Version : 2.4.6-p12

  [INFO] 2. Analyse des répertoires d'upload
  [OK] [custom_options] Aucun fichier avec extension exécutable.
  [OK] [custom_options] Aucun fichier polyglot détecté.
  [OK] [tmp] Aucun fichier polyglot détecté.

  [INFO] 3. Vérification des permissions
  [OK] [custom_options] Permissions OK (2755, user:user)

  [INFO] 4. Vérification de la protection .htaccess
  [OK] .htaccess pub/media : protection PHP active.
  [OK] .htaccess custom_options : protection active.

  [INFO] 5. Recherche de webshells dans pub/media/
  [OK] Aucun fichier PHP dans pub/media.

  [INFO] 6. Vérification des produits avec options de type 'file'
  [OK] Aucun produit avec option de type 'file'.

  [INFO] 7. Analyse des logs
  [OK] Aucun payload suspect dans les logs Magento.
  [OK] Logs serveur analysés.

------------------------------------------------------------
  prod : aucun problème (25s)
============================================================
```

## What it checks

| # | Check | Severity |
|---|-------|----------|
| 1 | Magento version | Info |
| 2 | Executable files or polyglot images in upload dirs | Alert |
| 3 | World-writable upload directories | Alert |
| 4 | Missing or misconfigured `.htaccess` | Warning |
| 5 | PHP files in `pub/media/` | Alert |
| 6 | Products with file-type custom options | Warning |
| 7 | Suspicious payloads in logs | Alert |

## Requirements

- Bash 4+
- `grep` with PCRE support (`-P` flag)
- `php` CLI (for reading database config from `env.php`)
- `mysql` CLI (for querying product options)
- `stat`, `find`, `realpath`

## Server log path

The script expects server access logs in `~/logs/**/*.log` (common on shared/managed hosting). Adjust the `LOGS_DIR` variable if your setup differs.

## Read-only

This script performs **no modifications** whatsoever. It only reads files, queries the database with `SELECT`, and reports findings.

## References

- [Sansec Research: Magento PolyShell](https://sansec.io/research/magento-polyshell)

## License

MIT
