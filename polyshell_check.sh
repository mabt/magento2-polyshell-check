#!/usr/bin/env bash
#
# polyshell_check.sh
# Détecte les signes de compromission liés à la vulnérabilité Magento PolyShell
# Ref: https://sansec.io/research/magento-polyshell
#
# Usage:
#   polyshell_check.sh                         # Auto-détection des Magento
#   polyshell_check.sh /chemin/vers/magento2   # Scan d'une instance spécifique
#   polyshell_check.sh --quiet                 # N'affiche que les instances avec problèmes
#   polyshell_check.sh --quiet /chemin/magento  # Combinable
#
# Codes retour:
#   0 = aucun problème détecté
#   1 = alerte(s) critique(s) détectée(s)
#   2 = point(s) d'attention uniquement (pas d'alerte critique)

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TOTAL_ALERTS=0
TOTAL_WARNINGS=0
TOTAL_EXPLOITED=0
INSTANCE_NUM=0
INSTANCE_TOTAL=0
SUMMARY_LINES=()
QUIET=false
HOSTNAME=$(hostname)

# En mode quiet, on bufferise la sortie de chaque instance
BUFFER=""

out() {
    if [[ "$QUIET" == true ]]; then
        BUFFER+="$1"$'\n'
    else
        echo -e "$1"
    fi
}

warn()  { out "  ${YELLOW}[ATTENTION]${NC} $*"; WARNINGS=$((WARNINGS + 1)); TOTAL_WARNINGS=$((TOTAL_WARNINGS + 1)); }
alert() { out "  ${RED}[ALERTE]${NC} $*"; ALERTS=$((ALERTS + 1)); TOTAL_ALERTS=$((TOTAL_ALERTS + 1)); }
ok()    { out "  ${GREEN}[OK]${NC} $*"; }
info()  { out "  ${BOLD}[INFO]${NC} $*"; }
detail(){ out "         $*"; }

# -------------------------------------------------------------------
# Scan d'une instance Magento
# -------------------------------------------------------------------
scan_magento() {
    local MAGENTO_ROOT="$1"
    local SCAN_START
    SCAN_START=$(date +%s)
    ALERTS=0
    WARNINGS=0
    EXPLOITED=0
    BUFFER=""

    local USER_HOME
    USER_HOME=$(echo "$MAGENTO_ROOT" | grep -oP '^/home/[^/]+' || true)
    if [[ -z "$USER_HOME" ]]; then
        USER_HOME="$HOME"
    fi

    # Extraire un nom court pour l'instance (ex: "prod", "staging", "dev")
    local INSTANCE_LABEL
    INSTANCE_LABEL=$(echo "$USER_HOME" | grep -oP '[^-]+$' || basename "$USER_HOME")

    INSTANCE_NUM=$((INSTANCE_NUM + 1))

    out ""
    out "${BOLD}============================================================${NC}"
    out " ${CYAN}${BOLD}[$HOSTNAME] Instance $INSTANCE_NUM/$INSTANCE_TOTAL : $INSTANCE_LABEL${NC}"
    out "${BOLD}============================================================${NC}"
    out " ${DIM}Racine    :${NC} $MAGENTO_ROOT"
    out " ${DIM}Home      :${NC} $USER_HOME"
    out " ${DIM}Date      :${NC} $(date '+%Y-%m-%d %H:%M:%S')"
    out "${BOLD}------------------------------------------------------------${NC}"
    out ""

    # ---------------------------------------------------------------
    # 1. Version de Magento
    # ---------------------------------------------------------------
    info "1. Version de Magento"

    local COMPOSER_JSON="$MAGENTO_ROOT/composer.json"
    local MAGE_VERSION="inconnue"
    if [[ -f "$COMPOSER_JSON" ]]; then
        MAGE_VERSION=$(grep -oP '"magento/product-(community|enterprise)-edition"\s*:\s*"\K[^"]+' "$COMPOSER_JSON" 2>/dev/null || echo "inconnue")
        detail "Version : $MAGE_VERSION"
        detail "Toutes les versions jusqu'à 2.4.9-alpha2 sont potentiellement affectées."
    else
        warn "Impossible de déterminer la version (composer.json introuvable)."
    fi
    out ""

    # ---------------------------------------------------------------
    # 2. Fichiers suspects dans les répertoires d'upload
    # ---------------------------------------------------------------
    info "2. Analyse des répertoires d'upload"

    local UPLOAD_DIRS=("$MAGENTO_ROOT/pub/media/custom_options" "$MAGENTO_ROOT/pub/media/tmp")
    for UPLOAD_DIR in "${UPLOAD_DIRS[@]}"; do
        local DIR_NAME
        DIR_NAME=$(basename "$UPLOAD_DIR")

        if [[ ! -d "$UPLOAD_DIR" ]]; then
            ok "[$DIR_NAME] Répertoire inexistant."
            continue
        fi

        local FILE_COUNT
        FILE_COUNT=$(find "$UPLOAD_DIR" -type f 2>/dev/null | wc -l)
        detail "[$DIR_NAME] Fichiers trouvés : $FILE_COUNT"

        if [[ $FILE_COUNT -eq 0 ]]; then
            ok "[$DIR_NAME] Répertoire vide."
            continue
        fi

        # Fichiers avec extensions exécutables
        local EXEC_FILES
        EXEC_FILES=$(find "$UPLOAD_DIR" -type f \( -iname '*.php' -o -iname '*.php3' -o -iname '*.php4' -o -iname '*.php5' -o -iname '*.php7' -o -iname '*.php8' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phps' -o -iname '*.cgi' -o -iname '*.pl' -o -iname '*.py' -o -iname '*.jsp' -o -iname '*.asp' -o -iname '*.aspx' -o -iname '*.sh' -o -iname '*.shtml' \) 2>/dev/null || true)

        if [[ -n "$EXEC_FILES" ]]; then
            alert "[$DIR_NAME] Fichiers avec extension exécutable :"
            echo "$EXEC_FILES" | while read -r f; do detail "-> $f"; done
        else
            ok "[$DIR_NAME] Aucun fichier avec extension exécutable."
        fi

        # Fichiers image contenant du code (polyglot)
        info "[$DIR_NAME] Recherche de fichiers polyglot..."
        local POLYGLOT_COUNT=0
        while IFS= read -r -d '' img; do
            local MATCH
            MATCH=$(grep -oPa '(<\?php|eval\s*\(|base64_decode|system\s*\(|passthru|shell_exec)' "$img" 2>/dev/null | head -3 || true)
            if [[ -n "$MATCH" ]]; then
                alert "[$DIR_NAME] Fichier polyglot suspect : $img"
                detail "Patterns : $MATCH"
                POLYGLOT_COUNT=$((POLYGLOT_COUNT + 1))
            fi
        done < <(find "$UPLOAD_DIR" -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.svg' -o -iname '*.ico' -o -iname '*.bmp' -o -iname '*.webp' \) -print0 2>/dev/null)

        if [[ $POLYGLOT_COUNT -eq 0 ]]; then
            ok "[$DIR_NAME] Aucun fichier polyglot détecté."
        fi
    done
    out ""

    # ---------------------------------------------------------------
    # 3. Permissions des répertoires d'upload
    # ---------------------------------------------------------------
    info "3. Vérification des permissions"

    for UPLOAD_DIR in "${UPLOAD_DIRS[@]}"; do
        local DIR_NAME
        DIR_NAME=$(basename "$UPLOAD_DIR")

        if [[ -d "$UPLOAD_DIR" ]]; then
            local PERMS OWNER
            PERMS=$(stat -c '%a' "$UPLOAD_DIR" 2>/dev/null || echo "000")
            OWNER=$(stat -c '%U:%G' "$UPLOAD_DIR" 2>/dev/null || echo "???")

            if [[ $(( ${PERMS: -1} & 2 )) -ne 0 ]]; then
                alert "[$DIR_NAME] World-writable ($PERMS, $OWNER)"
                detail "Corriger avec : chmod 2775 $UPLOAD_DIR"
            else
                ok "[$DIR_NAME] Permissions OK ($PERMS, $OWNER)"
            fi
        fi
    done
    out ""

    # ---------------------------------------------------------------
    # 4. Protection .htaccess
    # ---------------------------------------------------------------
    info "4. Vérification de la protection .htaccess"

    local HTACCESS="$MAGENTO_ROOT/pub/media/.htaccess"
    if [[ -f "$HTACCESS" ]]; then
        if grep -qi 'SetHandler\|php_flag\|RemoveHandler\|php_admin_flag' "$HTACCESS" 2>/dev/null; then
            ok ".htaccess pub/media : protection PHP active."
        else
            warn ".htaccess pub/media : ne semble pas bloquer l'exécution PHP."
        fi
    else
        warn "Pas de .htaccess dans pub/media."
    fi

    local HTACCESS_CO="$MAGENTO_ROOT/pub/media/custom_options/.htaccess"
    if [[ -f "$HTACCESS_CO" ]]; then
        if grep -qi 'SetHandler\|php_flag\|RemoveHandler\|php_admin_flag\|deny from all\|Require all denied' "$HTACCESS_CO" 2>/dev/null; then
            ok ".htaccess custom_options : protection active."
        else
            warn ".htaccess custom_options : ne semble pas bloquer l'exécution PHP."
        fi
    else
        warn "Pas de .htaccess dans custom_options."
    fi
    out ""

    # ---------------------------------------------------------------
    # 5. Webshells dans pub/media
    # ---------------------------------------------------------------
    info "5. Recherche de webshells dans pub/media/"

    local MEDIA_DIR="$MAGENTO_ROOT/pub/media"
    if [[ -d "$MEDIA_DIR" ]]; then
        local PHP_IN_MEDIA
        PHP_IN_MEDIA=$(find "$MEDIA_DIR" -type f -iname '*.php' 2>/dev/null || true)
        if [[ -n "$PHP_IN_MEDIA" ]]; then
            alert "Fichiers PHP trouvés dans pub/media :"
            echo "$PHP_IN_MEDIA" | while read -r f; do detail "-> $f"; done
        else
            ok "Aucun fichier PHP dans pub/media."
        fi
    else
        warn "Répertoire pub/media introuvable."
    fi
    out ""

    # ---------------------------------------------------------------
    # 6. Produits avec custom options de type "file"
    # ---------------------------------------------------------------
    info "6. Vérification des produits avec options de type 'file'"

    local ENV_PHP="$MAGENTO_ROOT/app/etc/env.php"
    local DB_HOST="" DB_NAME="" DB_USER="" DB_PASS="" DB_PREFIX=""

    eval "$(php -r "
        \$c = include '$ENV_PHP';
        \$d = \$c['db']['connection']['default'] ?? [];
        echo 'DB_HOST=' . escapeshellarg(\$d['host'] ?? 'localhost') . ' ';
        echo 'DB_NAME=' . escapeshellarg(\$d['dbname'] ?? '') . ' ';
        echo 'DB_USER=' . escapeshellarg(\$d['username'] ?? '') . ' ';
        echo 'DB_PASS=' . escapeshellarg(\$d['password'] ?? '') . ' ';
        echo 'DB_PREFIX=' . escapeshellarg(\$c['db']['table_prefix'] ?? '');
    " 2>/dev/null || echo "")"

    if [[ -n "$DB_NAME" && -n "$DB_USER" ]]; then
        local FILE_OPTIONS
        FILE_OPTIONS=$(mysql -h "$DB_HOST" -u "$DB_USER" ${DB_PASS:+-p"$DB_PASS"} "$DB_NAME" -N -e "SELECT COUNT(*) FROM ${DB_PREFIX}catalog_product_option WHERE type = 'file';" 2>/dev/null || echo "erreur")

        if [[ "$FILE_OPTIONS" == "erreur" ]]; then
            warn "Impossible de se connecter à la base de données."
        elif [[ "$FILE_OPTIONS" -gt 0 ]]; then
            warn "$FILE_OPTIONS produit(s) avec des options de type 'file' détecté(s)."
            detail "Ces produits exposent la surface d'attaque PolyShell."

            mysql -h "$DB_HOST" -u "$DB_USER" ${DB_PASS:+-p"$DB_PASS"} "$DB_NAME" -e "
                SELECT cpo.product_id, cpev.value AS product_name, cpo.option_id, cpo.type
                FROM ${DB_PREFIX}catalog_product_option cpo
                LEFT JOIN ${DB_PREFIX}catalog_product_entity_varchar cpev
                    ON cpo.product_id = cpev.entity_id AND cpev.attribute_id = (
                        SELECT attribute_id FROM ${DB_PREFIX}eav_attribute
                        WHERE attribute_code = 'name' AND entity_type_id = 4
                    )
                WHERE cpo.type = 'file'
                GROUP BY cpo.product_id, cpo.option_id
                LIMIT 20;
            " 2>/dev/null || true
        else
            ok "Aucun produit avec option de type 'file'."
        fi
    else
        warn "Impossible de lire la configuration DB depuis env.php."
    fi
    out ""

    # ---------------------------------------------------------------
    # 7. Logs d'exploitation
    # ---------------------------------------------------------------
    info "7. Analyse des logs"

    local LOG_DIR="$MAGENTO_ROOT/var/log"
    if [[ -d "$LOG_DIR" ]]; then
        local SUSPICIOUS_LOGS
        SUSPICIOUS_LOGS=$(grep -rlP 'file_info.*base64|base64.*file_info' "$LOG_DIR" 2>/dev/null | head -5 || true)
        if [[ -n "$SUSPICIOUS_LOGS" ]]; then
            alert "Logs contenant des payloads suspects (file_info + base64) :"
            echo "$SUSPICIOUS_LOGS" | while read -r f; do detail "-> $f"; done
        else
            ok "Aucun payload suspect dans les logs Magento."
        fi
    fi

    local LOGS_DIR="$USER_HOME/logs"
    if [[ -d "$LOGS_DIR" ]]; then
        info "Recherche dans les logs serveur : $LOGS_DIR"

        # Exploitation RÉUSSIE : accès HTTP 200 à des .php dans custom_options
        local EXPLOITED_LINES
        EXPLOITED_LINES=$(grep -ahP 'custom_options/.*\.php.*"\s+200\s' "$LOGS_DIR"/*/*.log 2>/dev/null | head -20 || true)
        if [[ -n "$EXPLOITED_LINES" ]]; then
            local EXPLOITED_COUNT
            EXPLOITED_COUNT=$(echo "$EXPLOITED_LINES" | wc -l)
            EXPLOITED=1
            TOTAL_EXPLOITED=$((TOTAL_EXPLOITED + 1))
            alert "EXPLOITATION ACTIVE : $EXPLOITED_COUNT requête(s) HTTP 200 sur des .php dans custom_options :"
            echo "$EXPLOITED_LINES" | while read -r line; do detail "$line"; done
        fi

        # Tentatives d'accès (tous codes HTTP)
        while IFS= read -r ACCESS_LOG; do
            local EXPLOIT_ATTEMPTS
            EXPLOIT_ATTEMPTS=$(grep -caP 'custom_options/quote/.*\.(php|phtml|pht|cgi|sh|pl)' "$ACCESS_LOG" 2>/dev/null || true)
            EXPLOIT_ATTEMPTS="${EXPLOIT_ATTEMPTS//[^0-9]/}"
            EXPLOIT_ATTEMPTS="${EXPLOIT_ATTEMPTS:-0}"
            if [[ "$EXPLOIT_ATTEMPTS" -gt 0 ]]; then
                warn "$EXPLOIT_ATTEMPTS tentative(s) d'accès dans : $ACCESS_LOG"
            fi
        done < <(find "$LOGS_DIR" -type f -name '*.log' 2>/dev/null)
        ok "Logs serveur analysés."
    else
        warn "Répertoire de logs $LOGS_DIR introuvable."
    fi
    out ""

    # ---------------------------------------------------------------
    # 8. Résumé de l'instance
    # ---------------------------------------------------------------
    local SCAN_END
    SCAN_END=$(date +%s)
    local SCAN_DURATION=$((SCAN_END - SCAN_START))

    out "${BOLD}------------------------------------------------------------${NC}"
    if [[ $EXPLOITED -gt 0 ]]; then
        out "  ${RED}${BOLD}$INSTANCE_LABEL : EXPLOITATION ACTIVE + $ALERTS alerte(s), $WARNINGS attention(s)${NC} ${DIM}(${SCAN_DURATION}s)${NC}"
        SUMMARY_LINES+=("${RED}  [$HOSTNAME] $INSTANCE_LABEL ($MAGE_VERSION) : EXPLOITÉ - $ALERTS alerte(s), $WARNINGS attention(s)${NC}")
    elif [[ $ALERTS -gt 0 ]]; then
        out "  ${YELLOW}${BOLD}$INSTANCE_LABEL : $ALERTS alerte(s), $WARNINGS attention(s)${NC} ${DIM}(${SCAN_DURATION}s)${NC}"
        SUMMARY_LINES+=("${YELLOW}  [$HOSTNAME] $INSTANCE_LABEL ($MAGE_VERSION) : $ALERTS alerte(s), $WARNINGS attention(s)${NC}")
    elif [[ $WARNINGS -gt 0 ]]; then
        out "  ${YELLOW}${BOLD}$INSTANCE_LABEL : $WARNINGS point(s) d'attention${NC} ${DIM}(${SCAN_DURATION}s)${NC}"
        SUMMARY_LINES+=("${YELLOW}  [$HOSTNAME] $INSTANCE_LABEL ($MAGE_VERSION) : $WARNINGS point(s) d'attention${NC}")
    else
        out "  ${GREEN}${BOLD}$INSTANCE_LABEL : aucun problème${NC} ${DIM}(${SCAN_DURATION}s)${NC}"
        SUMMARY_LINES+=("${GREEN}  [$HOSTNAME] $INSTANCE_LABEL ($MAGE_VERSION) : aucun problème${NC}")
    fi
    out "${BOLD}============================================================${NC}"

    # En mode quiet, n'afficher que si problème détecté
    if [[ "$QUIET" == true ]]; then
        if [[ $ALERTS -gt 0 || $WARNINGS -gt 0 ]]; then
            echo -e "$BUFFER"
        fi
    fi
}

# -------------------------------------------------------------------
# Auto-détection des instances Magento
# -------------------------------------------------------------------
add_instance() {
    local resolved="$1"
    for existing in "${INSTANCES[@]+"${INSTANCES[@]}"}"; do
        [[ "$existing" == "$resolved" ]] && return
    done
    INSTANCES+=("$resolved")
}

find_magento_instances() {
    local SEARCH_DIR

    if [[ "$(id -u)" -eq 0 ]]; then
        SEARCH_DIR="/home"
    else
        SEARCH_DIR="$HOME"
    fi

    echo -e "  ${BOLD}[INFO]${NC} [$HOSTNAME] Recherche des instances Magento 2 dans $SEARCH_DIR ..."
    echo ""

    INSTANCES=()

    # Symlinks "current" (Capistrano)
    while IFS= read -r current_link; do
        local resolved
        resolved="$(realpath "$current_link")"
        if [[ -f "$resolved/app/etc/env.php" && -f "$resolved/composer.json" ]]; then
            add_instance "$resolved"
        fi
    done < <(find "$SEARCH_DIR" -maxdepth 5 -name 'current' -type l 2>/dev/null)

    # Installations classiques (sans Capistrano)
    while IFS= read -r env_php; do
        local mage_root
        mage_root="$(dirname "$(dirname "$(dirname "$env_php")")")"
        if [[ -f "$mage_root/composer.json" ]]; then
            add_instance "$(realpath "$mage_root")"
        fi
    done < <(find "$SEARCH_DIR" -maxdepth 8 -path '*/app/etc/env.php' -type f -not -path '*/shared/*' 2>/dev/null)

    if [[ ${#INSTANCES[@]} -eq 0 ]]; then
        echo "  Aucune instance Magento 2 trouvée dans $SEARCH_DIR."
        exit 0
    fi

    INSTANCE_TOTAL=${#INSTANCES[@]}
    echo "  Instances trouvées : $INSTANCE_TOTAL"
    for inst in "${INSTANCES[@]}"; do
        echo -e "         -> $inst"
    done

    for inst in "${INSTANCES[@]}"; do
        scan_magento "$inst"
    done
}

# -------------------------------------------------------------------
# Parsing des arguments
# -------------------------------------------------------------------
MAGENTO_PATH=""
for arg in "$@"; do
    case "$arg" in
        --quiet|-q) QUIET=true ;;
        *) MAGENTO_PATH="$arg" ;;
    esac
done

# -------------------------------------------------------------------
# Point d'entrée
# -------------------------------------------------------------------
if [[ -n "$MAGENTO_PATH" ]]; then
    MAGENTO_ROOT="$(realpath "$MAGENTO_PATH")"
    if [[ ! -f "$MAGENTO_ROOT/app/etc/env.php" ]]; then
        echo "Erreur: '$MAGENTO_ROOT' ne semble pas être une installation Magento 2."
        exit 1
    fi
    INSTANCE_TOTAL=1
    scan_magento "$MAGENTO_ROOT"
else
    find_magento_instances
fi

# -------------------------------------------------------------------
# Résumé global
# -------------------------------------------------------------------
if [[ $INSTANCE_TOTAL -gt 1 ]]; then
    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e " ${BOLD}[$HOSTNAME] RÉSUMÉ GLOBAL ($INSTANCE_TOTAL instances)${NC}"
    echo -e "${BOLD}============================================================${NC}"
    for line in "${SUMMARY_LINES[@]}"; do
        echo -e "$line"
    done
    echo -e "${BOLD}------------------------------------------------------------${NC}"
    if [[ $TOTAL_EXPLOITED -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}TOTAL : $TOTAL_EXPLOITED EXPLOITÉ(S), $TOTAL_ALERTS alerte(s), $TOTAL_WARNINGS attention(s)${NC}"
    elif [[ $TOTAL_ALERTS -gt 0 ]]; then
        echo -e "  ${YELLOW}${BOLD}TOTAL : $TOTAL_ALERTS alerte(s), $TOTAL_WARNINGS attention(s)${NC}"
    elif [[ $TOTAL_WARNINGS -gt 0 ]]; then
        echo -e "  ${YELLOW}${BOLD}TOTAL : $TOTAL_WARNINGS point(s) d'attention${NC}"
    else
        echo -e "  ${GREEN}${BOLD}TOTAL : aucun problème détecté${NC}"
    fi
    echo -e "${BOLD}============================================================${NC}"
fi

if [[ "$QUIET" != true ]]; then
    echo ""
    echo "Recommandations :"
    echo "  1. Bloquer l'exécution PHP/CGI dans pub/media/ (config serveur web)"
    echo "  2. Supprimer les options produit de type 'file' si non nécessaires"
    echo "  3. Mettre à jour Magento vers la dernière version avec les patches"
    echo "  4. Scanner régulièrement avec un outil comme eComscan (sansec.io)"
    echo "  5. Surveiller le répertoire pub/media/custom_options/ pour tout nouveau fichier"
    echo ""
fi

if [[ $TOTAL_ALERTS -gt 0 ]]; then
    exit 1
elif [[ $TOTAL_WARNINGS -gt 0 ]]; then
    exit 2
else
    exit 0
fi
