#!/usr/bin/env bash
# =============================================================================
#  AttackMap — Subdomain Reconnaissance Tool
#  By Adrian Martinez | HAAK Cybersecurity Consulting
#  v2.0
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Colores
# -----------------------------------------------------------------------------
VERDE="\033[92m"
ROJO="\033[91m"
AMARILLO="\033[93m"
CIAN="\033[96m"
BLANCO="\033[97m"
NEGRITA="\033[1m"
GRIS="\033[90m"
RESET="\033[0m"

# -----------------------------------------------------------------------------
# Tiempo de inicio
# -----------------------------------------------------------------------------
TIEMPO_INICIO=$(date +%s)

# -----------------------------------------------------------------------------
# Mensajes
# -----------------------------------------------------------------------------
msg_ok()    { echo -e "${VERDE}[+]${RESET} $*"; }
msg_err()   { echo -e "${ROJO}[-]${RESET} $*" >&2; }
msg_info()  { echo -e "${CIAN}[*]${RESET} $*"; }
msg_warn()  { echo -e "${AMARILLO}[!]${RESET} $*"; }
msg_dim()   { echo -e "${GRIS}    $*${RESET}"; }
seccion()   { echo -e "\n${NEGRITA}${CIAN}══════════════════════════════════════════${RESET}"; \
              echo -e "${NEGRITA}${BLANCO}  $*${RESET}"; \
              echo -e "${NEGRITA}${CIAN}══════════════════════════════════════════${RESET}"; }

# -----------------------------------------------------------------------------
# Trap: limpieza y SIGINT
# -----------------------------------------------------------------------------
DIRECTORIO_TEMP=""
cleanup() {
    if [[ -n "$DIRECTORIO_TEMP" && -d "$DIRECTORIO_TEMP" ]]; then
        rm -rf "$DIRECTORIO_TEMP"
    fi
}
trap cleanup EXIT

sigint_handler() {
    echo -e "\n${AMARILLO}[!] Interrumpido por el usuario. Limpiando...${RESET}"
    cleanup
    exit 130
}
trap sigint_handler INT TERM

# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------
mostrar_banner() {
    echo -e "${VERDE}${NEGRITA}"
    echo " █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗ "
    echo "██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝████╗ ████║██╔══██╗██╔══██╗"
    echo "███████║   ██║      ██║   ███████║██║     █████╔╝ ██╔████╔██║███████║██████╔╝ "
    echo "██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ ██║╚██╔╝██║██╔══██║██╔═══╝  "
    echo "██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗██║ ╚═╝ ██║██║  ██║██║      "
    echo "╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝      "
    echo -e "${RESET}"
    echo -e "${AMARILLO}  Subdomain Reconnaissance Tool  |  By Adrian Martinez  |  HAAK Cybersec${RESET}"
    echo -e "${GRIS}  v2.0${RESET}\n"
}

# -----------------------------------------------------------------------------
# Uso
# -----------------------------------------------------------------------------
mostrar_uso() {
    echo -e "${BLANCO}${NEGRITA}USO:${RESET}"
    echo -e "  $0 -d dominio.com [opciones]"
    echo -e "  $0 -L lista.txt  [opciones]"
    echo ""
    echo -e "${BLANCO}${NEGRITA}OPCIONES:${RESET}"
    echo -e "  ${VERDE}-d${RESET} DOMINIO        Dominio objetivo"
    echo -e "  ${VERDE}-L${RESET} ARCHIVO        Archivo con lista de dominios (uno por línea)"
    echo -e "  ${VERDE}-f${RESET} ARCHIVO        Archivo anterior para comparación (muestra nuevos/caídos)"
    echo -e "  ${VERDE}-o${RESET} DIRECTORIO     Directorio de salida (default: resultados/)"
    echo -e "  ${VERDE}-t${RESET} HILOS          Hilos para httpx (default: 50)"
    echo -e "  ${VERDE}--quick${RESET}            Modo rápido: solo subfinder + crt.sh (omite amass)"
    echo -e "  ${VERDE}--full${RESET}             Modo completo: incluye naabu, gowitness, katana y nuclei"
    echo -e "  ${VERDE}--resolve-only${RESET}     Solo resolver DNS, sin probing HTTP"
    echo -e "  ${VERDE}--no-nuclei${RESET}        En modo --full, omitir la fase de nuclei"
    echo -e "  ${VERDE}-h${RESET}                 Mostrar esta ayuda"
    echo ""
    echo -e "${BLANCO}${NEGRITA}EJEMPLOS:${RESET}"
    echo -e "  $0 -d example.com"
    echo -e "  $0 -d example.com -f resultados/example.com/example.com_2024-01-01.txt"
    echo -e "  $0 -d example.com --quick -t 100"
    echo -e "  $0 -d example.com --full"
    echo -e "  $0 -d example.com --full --no-nuclei"
    echo -e "  $0 -L dominios.txt -o /tmp/recon --resolve-only"
}

# -----------------------------------------------------------------------------
# Verificación de dependencias
# -----------------------------------------------------------------------------
HERRAMIENTAS_CRITICAS=("curl" "jq" "sort")
HERRAMIENTAS_OPCIONALES=("assetfinder" "amass" "subfinder" "httpx" "httprobe" "dnsx" "waybackurls" "gau" "naabu" "gowitness" "katana" "nuclei")

HERRAMIENTAS_DISPONIBLES=()
HERRAMIENTAS_FALTANTES=()

verificar_dependencias() {
    seccion "Verificando herramientas"

    local fallo=0
    for cmd in "${HERRAMIENTAS_CRITICAS[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            msg_ok "  $cmd"
        else
            msg_err "  $cmd  (REQUERIDO — no encontrado)"
            fallo=1
        fi
    done

    for cmd in "${HERRAMIENTAS_OPCIONALES[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            msg_ok "  $cmd"
            HERRAMIENTAS_DISPONIBLES+=("$cmd")
        else
            msg_warn "  $cmd  (no disponible, se omitirá)"
            HERRAMIENTAS_FALTANTES+=("$cmd")
        fi
    done

    if [[ $fallo -eq 1 ]]; then
        msg_err "Faltan herramientas críticas. Abortando."
        exit 1
    fi

    # Necesitamos al menos una fuente de subdominios
    local tiene_fuente=0
    for f in assetfinder amass subfinder; do
        command -v "$f" &>/dev/null && tiene_fuente=1 && break
    done
    # crt.sh siempre disponible si hay curl+jq
    if command -v curl &>/dev/null && command -v jq &>/dev/null; then
        tiene_fuente=1
    fi

    if [[ $tiene_fuente -eq 0 ]]; then
        msg_err "No hay ninguna fuente de subdominios disponible (assetfinder/amass/subfinder/crt.sh). Abortando."
        exit 1
    fi

    echo ""
}

herramienta_disponible() {
    printf '%s\n' "${HERRAMIENTAS_DISPONIBLES[@]}" | grep -qx "$1"
}

# -----------------------------------------------------------------------------
# Filtros de basura
# -----------------------------------------------------------------------------
SEGMENTOS_A_OMITIR="104\.21\.|108\.162\.|13335|162\.159\.|172\.64\.|172\.67\.|173\.245\.58\.|2606:4700|2803:f800|2a06:98c1|398101|72\.167\."
PATRONES_A_OMITIR="^0$|^\*\.|^\*$|^aida\.ns\.cloudflare\.com$|^ruben\.ns\.cloudflare\.com$"

aplicar_filtros() {
    local archivo=$1
    local dominio=$2
    # Eliminar líneas vacías, wildcards, IPs conocidas de CDN, patrones de basura
    # Forzar que todos los resultados sean subdominios del dominio objetivo
    grep -Ev "$SEGMENTOS_A_OMITIR" "$archivo" \
        | grep -Ev "$PATRONES_A_OMITIR" \
        | grep -v '^\s*$' \
        | grep -E "\.${dominio}$|^${dominio}$" \
        | sed 's/\*\.//' \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u
}

# -----------------------------------------------------------------------------
# Clasificación de riesgo por subdomain
# -----------------------------------------------------------------------------
clasificar_riesgo() {
    local subdominio=$1
    local host_lower
    host_lower=$(echo "$subdominio" | tr '[:upper:]' '[:lower:]')

    if echo "$host_lower" | grep -qiE "(admin|panel|dashboard|manage|console|phpmyadmin|cpanel|webmail)"; then
        echo "critical"
    elif echo "$host_lower" | grep -qiE "(dev|staging|test|uat|qa|debug|internal|api-dev|stg)"; then
        echo "high"
    elif echo "$host_lower" | grep -qiE "(api|gateway|auth|login|sso|vpn|remote|ftp|ssh)"; then
        echo "medium"
    elif echo "$host_lower" | grep -qiE "(www|cdn|static|assets|img|media|blog|docs)"; then
        echo "low"
    else
        echo "info"
    fi
}

# -----------------------------------------------------------------------------
# Fuentes de subdominios
# -----------------------------------------------------------------------------
correr_assetfinder() {
    local dominio=$1
    local salida=$2
    msg_info "  [assetfinder] Iniciando..."
    if assetfinder --subs-only "$dominio" > "$salida" 2>/dev/null; then
        local n
        n=$(wc -l < "$salida")
        msg_ok "  [assetfinder] $n resultados"
    else
        msg_warn "  [assetfinder] Error o sin resultados"
        touch "$salida"
    fi
}

correr_amass() {
    local dominio=$1
    local salida=$2
    msg_info "  [amass] Iniciando (puede tardar varios minutos)..."
    if amass enum -passive -d "$dominio" -o "$salida" 2>/dev/null; then
        local n
        n=$(wc -l < "$salida")
        msg_ok "  [amass] $n resultados"
    else
        msg_warn "  [amass] Error o sin resultados"
        touch "$salida"
    fi
}

correr_subfinder() {
    local dominio=$1
    local salida=$2
    msg_info "  [subfinder] Iniciando..."
    if subfinder -silent -d "$dominio" -o "$salida" 2>/dev/null; then
        local n
        n=$(wc -l < "$salida")
        msg_ok "  [subfinder] $n resultados"
    else
        msg_warn "  [subfinder] Error o sin resultados"
        touch "$salida"
    fi
}

correr_crtsh() {
    local dominio=$1
    local salida=$2
    msg_info "  [crt.sh] Consultando..."
    local respuesta
    respuesta=$(curl -s --max-time 30 "https://crt.sh/?q=%25.${dominio}&output=json" 2>/dev/null || true)
    if [[ -n "$respuesta" ]] && echo "$respuesta" | jq -e '.' &>/dev/null; then
        echo "$respuesta" | jq -r '.[].name_value' 2>/dev/null | tr ',' '\n' > "$salida"
        local n
        n=$(wc -l < "$salida")
        msg_ok "  [crt.sh] $n resultados"
    else
        msg_warn "  [crt.sh] Sin respuesta o error de parsing"
        touch "$salida"
    fi
}

correr_waybackurls() {
    local dominio=$1
    local salida=$2
    msg_info "  [waybackurls] Extrayendo dominios históricos..."
    if waybackurls "$dominio" 2>/dev/null \
        | grep -oP '(?<=://)[^/]+' \
        | sort -u > "$salida"; then
        local n
        n=$(wc -l < "$salida")
        msg_ok "  [waybackurls] $n resultados"
    else
        msg_warn "  [waybackurls] Sin resultados"
        touch "$salida"
    fi
}

correr_gau() {
    local dominio=$1
    local salida=$2
    msg_info "  [gau] Extrayendo dominios históricos..."
    if gau --subs "$dominio" 2>/dev/null \
        | grep -oP '(?<=://)[^/]+' \
        | sort -u > "$salida"; then
        local n
        n=$(wc -l < "$salida")
        msg_ok "  [gau] $n resultados"
    else
        msg_warn "  [gau] Sin resultados"
        touch "$salida"
    fi
}

# -----------------------------------------------------------------------------
# Resolución DNS con dnsx
# -----------------------------------------------------------------------------
resolver_dns() {
    local entrada=$1
    local salida=$2
    msg_info "Resolviendo DNS con dnsx..."
    if dnsx -silent -l "$entrada" -o "$salida" 2>/dev/null; then
        local n
        n=$(wc -l < "$salida")
        msg_ok "  $n subdominios con respuesta DNS"
    else
        msg_warn "  dnsx falló, usando lista sin filtrar"
        cp "$entrada" "$salida"
    fi
}

# -----------------------------------------------------------------------------
# Fase: Port Scanning con naabu
# -----------------------------------------------------------------------------
fase_ports() {
    local entrada=$1        # archivo con hosts resueltos
    local salida_ports=$2   # archivo de salida con host:port
    local carpeta=$3

    seccion "Port Scanning — naabu"

    if ! herramienta_disponible "naabu"; then
        msg_warn "  naabu no disponible. Saltando port scanning."
        cp "$entrada" "$salida_ports"
        return 0
    fi

    msg_info "Escaneando puertos top-1000 con naabu..."
    if naabu -list "$entrada" -top-ports 1000 -silent -o "$salida_ports" 2>/dev/null; then
        local n
        n=$(wc -l < "$salida_ports")
        msg_ok "  $n combinaciones host:puerto encontradas"
    else
        msg_warn "  naabu falló o sin resultados. Usando hosts sin puertos."
        cp "$entrada" "$salida_ports"
    fi
}

# -----------------------------------------------------------------------------
# Probing HTTP con httpx o httprobe (fallback) — salida JSONL
# -----------------------------------------------------------------------------
probe_http() {
    local entrada=$1
    local salida_limpia=$2   # solo URLs vivas
    local salida_full=$3     # JSONL con detalles
    local hilos=$4

    if herramienta_disponible "httpx"; then
        msg_info "Probando HTTP/HTTPS con httpx (hilos: $hilos)..."
        httpx -silent -l "$entrada" \
              -threads "$hilos" \
              -status-code -title -tech-detect -ip -content-length \
              -json -o "$salida_full" 2>/dev/null || true

        # Extraer URLs del JSONL
        if [[ -s "$salida_full" ]]; then
            jq -r '.url // empty' "$salida_full" 2>/dev/null | sort -u > "$salida_limpia" || \
                awk '{print $1}' "$salida_full" | sort -u > "$salida_limpia"
        else
            touch "$salida_limpia"
        fi

        local n
        n=$(wc -l < "$salida_limpia")
        msg_ok "  $n hosts vivos detectados"

    elif herramienta_disponible "httprobe"; then
        msg_info "Probando HTTP/HTTPS con httprobe (hilos: $hilos)..."
        httprobe -c "$hilos" < "$entrada" > "$salida_full" 2>/dev/null || true

        # httprobe devuelve URLs — priorizar https
        awk '
        {
            sub = $0
            gsub("https://", "", sub)
            gsub("http://", "", sub)
            if (!seen[sub]++) {
                urls[sub] = $0
            } else if ($0 ~ /^https:\/\//) {
                urls[sub] = $0
            }
        }
        END {
            for (s in urls) { print urls[s] }
        }' "$salida_full" | sort -u > "$salida_limpia"

        local n
        n=$(wc -l < "$salida_limpia")
        msg_ok "  $n hosts vivos detectados (httprobe)"
    else
        msg_warn "  Ni httpx ni httprobe disponibles. Saltando probing HTTP."
        cp "$entrada" "$salida_limpia"
        touch "$salida_full"
    fi
}

# -----------------------------------------------------------------------------
# Fase: Screenshots con gowitness
# -----------------------------------------------------------------------------
fase_screenshots() {
    local urls_file=$1    # archivo con URLs vivas
    local carpeta=$2      # carpeta base del dominio

    seccion "Screenshots — gowitness"

    if ! herramienta_disponible "gowitness"; then
        msg_warn "  gowitness no disponible. Saltando screenshots."
        return 0
    fi

    local dir_screens="$carpeta/screenshots"
    mkdir -p "$dir_screens"

    msg_info "Capturando screenshots con gowitness..."
    if gowitness scan file -f "$urls_file" \
        --screenshot-path "$dir_screens" \
        --timeout 10 2>/dev/null; then
        local n
        n=$(find "$dir_screens" -name "*.png" 2>/dev/null | wc -l)
        msg_ok "  $n screenshots capturados en $dir_screens"
    else
        msg_warn "  gowitness falló o sin resultados."
    fi
}

# -----------------------------------------------------------------------------
# Fase: Crawling con katana
# -----------------------------------------------------------------------------
fase_crawl() {
    local urls_file=$1    # archivo con URLs vivas
    local salida=$2       # archivo de salida con endpoints

    seccion "Crawling — katana"

    if ! herramienta_disponible "katana"; then
        msg_warn "  katana no disponible. Saltando crawling."
        touch "$salida"
        return 0
    fi

    msg_info "Crawleando con katana (depth 2)..."
    if katana -list "$urls_file" -d 2 -jc -kf -silent -o "$salida" 2>/dev/null; then
        local n
        n=$(wc -l < "$salida")
        msg_ok "  $n endpoints descubiertos"
    else
        msg_warn "  katana falló o sin resultados."
        touch "$salida"
    fi
}

# -----------------------------------------------------------------------------
# Fase: Vulnerabilidades rápidas con nuclei
# -----------------------------------------------------------------------------
fase_nuclei() {
    local urls_file=$1    # archivo con URLs vivas
    local salida=$2       # archivo JSONL de salida

    seccion "Vulnerability Scanning — nuclei"

    if ! herramienta_disponible "nuclei"; then
        msg_warn "  nuclei no disponible. Saltando vuln scanning."
        touch "$salida"
        return 0
    fi

    msg_info "Escaneando vulnerabilidades con nuclei (medium/high/critical)..."
    if nuclei -l "$urls_file" \
        -severity medium,high,critical \
        -t exposures/ -t misconfiguration/ \
        -jsonl -o "$salida" -silent 2>/dev/null; then
        local n
        n=$(wc -l < "$salida")
        msg_ok "  $n findings nuclei encontrados"
    else
        msg_warn "  nuclei falló o sin resultados."
        touch "$salida"
    fi
}

# -----------------------------------------------------------------------------
# Comparación con scan anterior
# -----------------------------------------------------------------------------
comparar_scans() {
    local archivo_anterior=$1
    local archivo_actual=$2
    local carpeta_salida=$3
    local dominio=$4

    seccion "Comparación con scan anterior"

    local nuevos="$carpeta_salida/nuevos_subdominios_${dominio}.txt"
    local inactivos="$carpeta_salida/subdominios_inactivos_${dominio}.txt"
    local activos_comunes="$carpeta_salida/subdominios_activos_comunes_${dominio}.txt"

    # Nuevos: en actual pero no en anterior
    comm -23 <(sort "$archivo_actual") <(sort "$archivo_anterior") > "$nuevos"
    # Inactivos (caídos): en anterior pero no en actual
    comm -23 <(sort "$archivo_anterior") <(sort "$archivo_actual") > "$inactivos"
    # Siguen activos: en ambos
    comm -12 <(sort "$archivo_actual") <(sort "$archivo_anterior") > "$activos_comunes"

    local n_nuevos n_inactivos n_comunes
    n_nuevos=$(wc -l < "$nuevos")
    n_inactivos=$(wc -l < "$inactivos")
    n_comunes=$(wc -l < "$activos_comunes")

    echo ""
    echo -e "  ${VERDE}Nuevos subdominios    :${RESET} $n_nuevos"
    echo -e "  ${ROJO}Caídos/Inactivos      :${RESET} $n_inactivos"
    echo -e "  ${CIAN}Siguen activos        :${RESET} $n_comunes"
    echo ""

    if [[ $n_nuevos -gt 0 ]]; then
        echo -e "${VERDE}${NEGRITA}  -- NUEVOS --${RESET}"
        cat "$nuevos" | sed 's/^/  /'
        echo ""
    fi

    if [[ $n_inactivos -gt 0 ]]; then
        echo -e "${ROJO}${NEGRITA}  -- INACTIVOS / CAÍDOS --${RESET}"
        cat "$inactivos" | sed 's/^/  /'
        echo ""
    fi

    msg_ok "Archivos de diff guardados en: $carpeta_salida"
}

# -----------------------------------------------------------------------------
# Tabla de resumen final
# -----------------------------------------------------------------------------
mostrar_resumen() {
    local dominio=$1
    local n_total=$2
    local n_unicos=$3
    local n_resueltos=$4
    local n_vivos=$5
    local n_nuevos=$6
    local n_inactivos=$7
    local carpeta=$8
    local archivo_principal=$9
    local n_vulns=${10:-0}
    local n_endpoints=${11:-0}

    local tiempo_fin
    tiempo_fin=$(date +%s)
    local elapsed=$(( tiempo_fin - TIEMPO_INICIO ))
    local mins=$(( elapsed / 60 ))
    local segs=$(( elapsed % 60 ))

    seccion "Resumen — $dominio"
    echo ""
    printf "  ${BLANCO}%-30s${RESET} ${VERDE}%s${RESET}\n"  "Subdominios encontrados:"     "$n_total"
    printf "  ${BLANCO}%-30s${RESET} ${VERDE}%s${RESET}\n"  "Subdominios únicos:"           "$n_unicos"
    printf "  ${BLANCO}%-30s${RESET} ${VERDE}%s${RESET}\n"  "Con respuesta DNS:"            "$n_resueltos"
    printf "  ${BLANCO}%-30s${RESET} ${VERDE}%s${RESET}\n"  "Hosts vivos (HTTP/HTTPS):"     "$n_vivos"
    [[ $n_vulns -gt 0 ]] && \
    printf "  ${BLANCO}%-30s${RESET} ${ROJO}%s${RESET}\n"   "Vulnerabilidades (nuclei):"   "$n_vulns"
    [[ $n_endpoints -gt 0 ]] && \
    printf "  ${BLANCO}%-30s${RESET} ${CIAN}%s${RESET}\n"   "Endpoints (katana):"           "$n_endpoints"
    [[ $n_nuevos -ge 0 ]] && \
    printf "  ${BLANCO}%-30s${RESET} ${AMARILLO}%s${RESET}\n" "Nuevos (vs scan anterior):"   "$n_nuevos"
    [[ $n_inactivos -ge 0 ]] && \
    printf "  ${BLANCO}%-30s${RESET} ${ROJO}%s${RESET}\n"   "Caídos (vs scan anterior):"   "$n_inactivos"
    echo ""
    printf "  ${BLANCO}%-30s${RESET} ${CIAN}%s${RESET}\n"   "Directorio de resultados:"    "$carpeta"
    printf "  ${BLANCO}%-30s${RESET} ${CIAN}%s${RESET}\n"   "Archivo principal:"           "$archivo_principal"
    printf "  ${BLANCO}%-30s${RESET} ${GRIS}%s${RESET}\n"   "Tiempo total:"                "${mins}m ${segs}s"
    echo ""
}

# -----------------------------------------------------------------------------
# Generación del JSON de salida
# -----------------------------------------------------------------------------
generar_json() {
    local dominio=$1
    local carpeta=$2
    local perfil=$3           # "full" o "quick"
    local fases_completadas=$4  # array serializado como string JSON
    local n_total=$5
    local n_unicos=$6
    local n_resueltos=$7
    local n_vivos=$8
    local n_nuevos=$9
    local n_inactivos=${10}
    local count_subfinder=${11}
    local count_amass=${12}
    local count_crtsh=${13}
    local count_assetfinder=${14}
    local count_wayback=${15}
    local count_gau=${16}
    local archivo_httpx_jsonl=${17}    # JSONL de httpx
    local archivo_ports=${18}          # host:port de naabu
    local archivo_nuclei_jsonl=${19}   # JSONL de nuclei
    local archivo_endpoints=${20}      # endpoints de katana
    local archivo_anterior=${21}       # para comparación
    local archivo_vivos=${22}          # URLs vivas (para comparar)

    local json_out="$carpeta/scan_data.json"
    local fecha
    fecha=$(date +"%Y-%m-%d")
    local tiempo_fin
    tiempo_fin=$(date +%s)
    local duracion=$(( tiempo_fin - TIEMPO_INICIO ))

    msg_info "Generando scan_data.json..."

    # ------------------------------------------------------------------
    # Construir arrays JSON desde archivos
    # ------------------------------------------------------------------

    # Assets desde httpx JSONL
    local assets_json="[]"
    if [[ -s "$archivo_httpx_jsonl" ]]; then
        assets_json=$(jq -s '
            map(
                . as $row |
                {
                    subdomain: (($row.input // $row.url // "") | gsub("https?://"; "") | split(":")[0] | split("/")[0]),
                    ip: (if ($row.a // []) | length > 0 then ($row.a // [])[0] else "" end),
                    ports: [],
                    status_code: ($row.status_code // 0),
                    title: ($row.title // ""),
                    technologies: ($row.tech // []),
                    content_length: ($row.content_length // 0),
                    screenshot: "",
                    risk: "info",
                    is_new: false
                }
            )
        ' "$archivo_httpx_jsonl" 2>/dev/null || echo "[]")
    fi

    # Enriquecer assets con puertos de naabu
    if [[ -s "$archivo_ports" ]]; then
        # Construir mapa host -> [ports] desde archivo host:port
        local ports_map
        ports_map=$(awk -F: '{print $1, $2}' "$archivo_ports" 2>/dev/null | \
            jq -Rn '
                [inputs | split(" ") | {host: .[0], port: (.[1] | tonumber? // 0)}] |
                group_by(.host) |
                map({key: .[0].host, value: map(.port)}) |
                from_entries
            ' 2>/dev/null || echo "{}")

        # Fusionar puertos en assets
        assets_json=$(echo "$assets_json" | jq --argjson pm "$ports_map" '
            map(. as $a |
                if $pm[$a.subdomain] then
                    $a + {ports: $pm[$a.subdomain]}
                else
                    $a
                end
            )
        ' 2>/dev/null || echo "$assets_json")
    fi

    # Agregar clasificacion de riesgo e is_new a cada asset
    local assets_final="[]"
    if [[ "$assets_json" != "[]" ]]; then
        # Crear lista de nuevos subdominios si existe comparación
        local nuevos_list="[]"
        if [[ -n "$archivo_anterior" && -f "$archivo_anterior" && -s "$archivo_vivos" ]]; then
            nuevos_list=$(comm -23 <(sort "$archivo_vivos") <(sort "$archivo_anterior") 2>/dev/null | \
                jq -Rn '[inputs]' 2>/dev/null || echo "[]")
        fi

        assets_final=$(echo "$assets_json" | jq --argjson nl "$nuevos_list" '
            map(. as $a |
                $a + {
                    is_new: (($nl | map(select(. == $a.subdomain)) | length) > 0)
                }
            )
        ' 2>/dev/null || echo "$assets_json")
    fi

    # Ports summary desde naabu
    local ports_summary="{}"
    if [[ -s "$archivo_ports" ]]; then
        ports_summary=$(awk -F: '{print $2}' "$archivo_ports" 2>/dev/null | \
            sort | uniq -c | \
            jq -Rn '
                [inputs | gsub("^\\s+"; "") | split(" ") | {count: (.[0] | tonumber? // 0), port: .[1]}] |
                map(select(.port != null and .port != "")) |
                map({key: .port, value: .count}) |
                from_entries
            ' 2>/dev/null || echo "{}")
    fi

    # Technologies summary desde httpx JSONL
    local tech_summary="{}"
    local tech_count=0
    if [[ -s "$archivo_httpx_jsonl" ]]; then
        tech_summary=$(jq -r '.tech // [] | .[]' "$archivo_httpx_jsonl" 2>/dev/null | \
            sort | uniq -c | \
            jq -Rn '
                [inputs | gsub("^\\s+"; "") | split(" ") | {count: (.[0] | tonumber? // 0), tech: (.[1:] | join(" "))}] |
                map(select(.tech != null and .tech != "")) |
                map({key: .tech, value: .count}) |
                from_entries
            ' 2>/dev/null || echo "{}")
        tech_count=$(echo "$tech_summary" | jq 'keys | length' 2>/dev/null || echo 0)
    fi

    # Vulnerabilidades desde nuclei JSONL
    local vulns_json="[]"
    local n_vulns=0
    if [[ -s "$archivo_nuclei_jsonl" ]]; then
        vulns_json=$(jq -s '
            map({
                host: (.host // ""),
                template: (.template_id // ""),
                severity: (.info.severity // ""),
                name: (.info.name // ""),
                url: (.matched_at // ""),
                matched_at: (.matched_at // "")
            })
        ' "$archivo_nuclei_jsonl" 2>/dev/null || echo "[]")
        n_vulns=$(echo "$vulns_json" | jq 'length' 2>/dev/null || echo 0)
    fi

    # Endpoints desde katana
    local endpoints_json="[]"
    local n_endpoints=0
    if [[ -s "$archivo_endpoints" ]]; then
        endpoints_json=$(jq -Rn '[inputs]' < "$archivo_endpoints" 2>/dev/null || echo "[]")
        n_endpoints=$(wc -l < "$archivo_endpoints")
    fi

    # Comparación
    local comp_new="[]" comp_removed="[]" comp_persistent="[]"
    local n_new_comp=0 n_removed_comp=0
    if [[ -n "$archivo_anterior" && -f "$archivo_anterior" && -s "$archivo_vivos" ]]; then
        comp_new=$(comm -23 <(sort "$archivo_vivos") <(sort "$archivo_anterior") 2>/dev/null | \
            jq -Rn '[inputs]' 2>/dev/null || echo "[]")
        comp_removed=$(comm -23 <(sort "$archivo_anterior") <(sort "$archivo_vivos") 2>/dev/null | \
            jq -Rn '[inputs]' 2>/dev/null || echo "[]")
        comp_persistent=$(comm -12 <(sort "$archivo_vivos") <(sort "$archivo_anterior") 2>/dev/null | \
            jq -Rn '[inputs]' 2>/dev/null || echo "[]")
        n_new_comp=$(echo "$comp_new" | jq 'length' 2>/dev/null || echo 0)
        n_removed_comp=$(echo "$comp_removed" | jq 'length' 2>/dev/null || echo 0)
    fi

    # Puertos abiertos totales
    local n_ports_open=0
    if [[ -s "$archivo_ports" ]]; then
        n_ports_open=$(wc -l < "$archivo_ports")
    fi

    # ------------------------------------------------------------------
    # Escribir JSON final
    # ------------------------------------------------------------------
    jq -n \
        --arg tool "AttackMap" \
        --arg version "2.0" \
        --arg date "$fecha" \
        --arg target "$dominio" \
        --argjson duration "$duracion" \
        --arg profile "$perfil" \
        --argjson fases "$fases_completadas" \
        --argjson subs_total "$n_total" \
        --argjson subs_unique "$n_unicos" \
        --argjson dns_resolved "$n_resueltos" \
        --argjson hosts_live "$n_vivos" \
        --argjson ports_open "$n_ports_open" \
        --argjson vulns_found "$n_vulns" \
        --argjson tech_count "$tech_count" \
        --argjson endpoints_found "$n_endpoints" \
        --argjson new_since "$n_new_comp" \
        --argjson removed_since "$n_removed_comp" \
        --argjson src_subfinder "$count_subfinder" \
        --argjson src_amass "$count_amass" \
        --argjson src_crtsh "$count_crtsh" \
        --argjson src_assetfinder "$count_assetfinder" \
        --argjson src_wayback "$count_wayback" \
        --argjson src_gau "$count_gau" \
        --argjson assets "$assets_final" \
        --argjson ports_summary "$ports_summary" \
        --argjson technologies "$tech_summary" \
        --argjson vulnerabilities "$vulns_json" \
        --argjson endpoints "$endpoints_json" \
        --argjson comp_new "$comp_new" \
        --argjson comp_removed "$comp_removed" \
        --argjson comp_persistent "$comp_persistent" \
        '{
            meta: {
                tool: $tool,
                version: $version,
                date: $date,
                target: $target,
                duration_seconds: $duration,
                profile: $profile,
                phases_completed: $fases
            },
            stats: {
                subdomains_total: $subs_total,
                subdomains_unique: $subs_unique,
                dns_resolved: $dns_resolved,
                hosts_live: $hosts_live,
                ports_open: $ports_open,
                vulns_found: $vulns_found,
                tech_count: $tech_count,
                endpoints_found: $endpoints_found,
                new_since_last: $new_since,
                removed_since_last: $removed_since
            },
            sources: {
                subfinder: $src_subfinder,
                amass: $src_amass,
                crtsh: $src_crtsh,
                assetfinder: $src_assetfinder,
                waybackurls: $src_wayback,
                gau: $src_gau
            },
            assets: $assets,
            ports_summary: $ports_summary,
            technologies: $technologies,
            vulnerabilities: $vulnerabilities,
            endpoints: $endpoints,
            comparison: {
                new: $comp_new,
                removed: $comp_removed,
                persistent: $comp_persistent
            }
        }' > "$json_out" 2>/dev/null || true

    if [[ -f "$json_out" ]]; then
        msg_ok "scan_data.json generado → $json_out"
    else
        msg_warn "No se pudo generar scan_data.json"
    fi
}

# -----------------------------------------------------------------------------
# Procesamiento principal de un dominio
# -----------------------------------------------------------------------------
procesar_dominio() {
    local DOMINIO=$1
    local DIR_SALIDA=$2
    local ARCHIVO_ANTERIOR=$3
    local MODO_QUICK=$4
    local SOLO_DNS=$5
    local HILOS=$6
    local MODO_FULL=$7
    local SIN_NUCLEI=$8

    local FECHA
    FECHA=$(date +"%Y-%m-%d")
    local CARPETA_DOMINIO="$DIR_SALIDA/$DOMINIO"
    mkdir -p "$CARPETA_DOMINIO"

    # Directorio temporal para este dominio
    DIRECTORIO_TEMP=$(mktemp -d)

    local ARCHIVO_FINAL="$CARPETA_DOMINIO/${DOMINIO}_${FECHA}.txt"
    local ARCHIVO_VIVOS="$CARPETA_DOMINIO/${DOMINIO}_${FECHA}_vivos.txt"
    local ARCHIVO_HTTPX="$CARPETA_DOMINIO/${DOMINIO}_${FECHA}_httpx.jsonl"
    local ARCHIVO_RESUELTOS="$CARPETA_DOMINIO/${DOMINIO}_${FECHA}_resueltos.txt"
    local ARCHIVO_PORTS="$CARPETA_DOMINIO/${DOMINIO}_${FECHA}_ports.txt"
    local ARCHIVO_ENDPOINTS="$CARPETA_DOMINIO/${DOMINIO}_${FECHA}_endpoints.txt"
    local ARCHIVO_NUCLEI="$CARPETA_DOMINIO/${DOMINIO}_${FECHA}_nuclei.jsonl"

    # Perfil para el JSON
    local PERFIL="quick"
    $MODO_FULL && PERFIL="full"
    ! $MODO_QUICK && PERFIL="full"

    seccion "Recolección de subdominios — $DOMINIO"

    # ----------------------------------------------------------------
    # Paso 1: Ejecutar fuentes (paralelo donde es posible)
    # ----------------------------------------------------------------
    local pids=()

    if ! $MODO_QUICK && herramienta_disponible "assetfinder"; then
        correr_assetfinder "$DOMINIO" "$DIRECTORIO_TEMP/assetfinder.txt" &
        pids+=($!)
    fi

    if ! $MODO_QUICK && herramienta_disponible "amass"; then
        correr_amass "$DOMINIO" "$DIRECTORIO_TEMP/amass.txt" &
        pids+=($!)
    fi

    if herramienta_disponible "subfinder"; then
        correr_subfinder "$DOMINIO" "$DIRECTORIO_TEMP/subfinder.txt" &
        pids+=($!)
    fi

    # crt.sh siempre (si hay curl+jq, ya validado)
    correr_crtsh "$DOMINIO" "$DIRECTORIO_TEMP/crtsh.txt" &
    pids+=($!)

    if herramienta_disponible "waybackurls"; then
        correr_waybackurls "$DOMINIO" "$DIRECTORIO_TEMP/waybackurls.txt" &
        pids+=($!)
    fi

    if herramienta_disponible "gau"; then
        correr_gau "$DOMINIO" "$DIRECTORIO_TEMP/gau.txt" &
        pids+=($!)
    fi

    # Esperar a que todas las fuentes terminen
    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    # ----------------------------------------------------------------
    # Paso 2: Merge, deduplicación, filtros
    # ----------------------------------------------------------------
    seccion "Procesando resultados — $DOMINIO"
    msg_info "Mergeando y deduplicando..."

    # Contar por fuente
    local count_assetfinder=0 count_amass=0 count_subfinder=0 count_crtsh=0
    local count_wayback=0 count_gau=0

    [[ -f "$DIRECTORIO_TEMP/assetfinder.txt" ]] && count_assetfinder=$(wc -l < "$DIRECTORIO_TEMP/assetfinder.txt")
    [[ -f "$DIRECTORIO_TEMP/amass.txt"        ]] && count_amass=$(wc -l < "$DIRECTORIO_TEMP/amass.txt")
    [[ -f "$DIRECTORIO_TEMP/subfinder.txt"    ]] && count_subfinder=$(wc -l < "$DIRECTORIO_TEMP/subfinder.txt")
    [[ -f "$DIRECTORIO_TEMP/crtsh.txt"        ]] && count_crtsh=$(wc -l < "$DIRECTORIO_TEMP/crtsh.txt")
    [[ -f "$DIRECTORIO_TEMP/waybackurls.txt"  ]] && count_wayback=$(wc -l < "$DIRECTORIO_TEMP/waybackurls.txt")
    [[ -f "$DIRECTORIO_TEMP/gau.txt"          ]] && count_gau=$(wc -l < "$DIRECTORIO_TEMP/gau.txt")

    local total_raw=$(( count_assetfinder + count_amass + count_subfinder + count_crtsh + count_wayback + count_gau ))

    echo ""
    echo -e "  ${GRIS}Resultados por fuente:${RESET}"
    [[ $count_assetfinder -gt 0 ]] && msg_dim "assetfinder   : $count_assetfinder"
    [[ $count_amass        -gt 0 ]] && msg_dim "amass         : $count_amass"
    [[ $count_subfinder    -gt 0 ]] && msg_dim "subfinder     : $count_subfinder"
    [[ $count_crtsh        -gt 0 ]] && msg_dim "crt.sh        : $count_crtsh"
    [[ $count_wayback      -gt 0 ]] && msg_dim "waybackurls   : $count_wayback"
    [[ $count_gau          -gt 0 ]] && msg_dim "gau           : $count_gau"
    msg_dim "Total bruto   : $total_raw"
    echo ""

    # Merge en un solo archivo temporal
    local merge_tmp="$DIRECTORIO_TEMP/merged_raw.txt"
    cat "$DIRECTORIO_TEMP"/*.txt 2>/dev/null | sort -u > "$merge_tmp" || true

    # Aplicar filtros y guardar resultado limpio
    aplicar_filtros "$merge_tmp" "$DOMINIO" > "$ARCHIVO_FINAL" || true

    local n_unicos
    n_unicos=$(wc -l < "$ARCHIVO_FINAL")
    msg_ok "$n_unicos subdominios únicos después de filtros → $ARCHIVO_FINAL"

    # Fases completadas
    local fases_completadas='"subdomains"'

    # ----------------------------------------------------------------
    # Paso 3: Resolución DNS (opcional, si dnsx disponible)
    # ----------------------------------------------------------------
    local n_resueltos=$n_unicos
    if herramienta_disponible "dnsx"; then
        seccion "Resolución DNS — $DOMINIO"
        resolver_dns "$ARCHIVO_FINAL" "$ARCHIVO_RESUELTOS"
        n_resueltos=$(wc -l < "$ARCHIVO_RESUELTOS")
        fases_completadas="${fases_completadas},\"dns\""
    else
        cp "$ARCHIVO_FINAL" "$ARCHIVO_RESUELTOS"
        msg_warn "  dnsx no disponible, usando todos los subdominios para probing"
    fi

    # ----------------------------------------------------------------
    # Paso 4: Port Scanning con naabu (solo en --full)
    # ----------------------------------------------------------------
    local entrada_httpx="$ARCHIVO_RESUELTOS"
    touch "$ARCHIVO_PORTS"

    if $MODO_FULL && ! $SOLO_DNS; then
        fase_ports "$ARCHIVO_RESUELTOS" "$ARCHIVO_PORTS" "$CARPETA_DOMINIO"
        if [[ -s "$ARCHIVO_PORTS" ]]; then
            # Si naabu encontró puertos, usar host:port como entrada para httpx
            entrada_httpx="$ARCHIVO_PORTS"
            fases_completadas="${fases_completadas},\"ports\""
        fi
    fi

    # ----------------------------------------------------------------
    # Paso 5: Probing HTTP (saltar si --resolve-only)
    # ----------------------------------------------------------------
    local n_vivos=0
    touch "$ARCHIVO_HTTPX"

    if ! $SOLO_DNS; then
        seccion "HTTP Probing — $DOMINIO"
        probe_http "$entrada_httpx" "$ARCHIVO_VIVOS" "$ARCHIVO_HTTPX" "$HILOS"
        n_vivos=$(wc -l < "$ARCHIVO_VIVOS")
        fases_completadas="${fases_completadas},\"http\""
    else
        msg_info "  --resolve-only activo: saltando HTTP probing"
        cp "$ARCHIVO_RESUELTOS" "$ARCHIVO_VIVOS"
        n_vivos=$n_resueltos
    fi

    # ----------------------------------------------------------------
    # Paso 6: Screenshots con gowitness (solo en --full)
    # ----------------------------------------------------------------
    if $MODO_FULL && ! $SOLO_DNS && [[ -s "$ARCHIVO_VIVOS" ]]; then
        fase_screenshots "$ARCHIVO_VIVOS" "$CARPETA_DOMINIO"
        if [[ -d "$CARPETA_DOMINIO/screenshots" ]]; then
            fases_completadas="${fases_completadas},\"screenshots\""
        fi
    fi

    # ----------------------------------------------------------------
    # Paso 7: Crawling con katana (solo en --full)
    # ----------------------------------------------------------------
    touch "$ARCHIVO_ENDPOINTS"
    if $MODO_FULL && ! $SOLO_DNS && [[ -s "$ARCHIVO_VIVOS" ]]; then
        fase_crawl "$ARCHIVO_VIVOS" "$ARCHIVO_ENDPOINTS"
        if [[ -s "$ARCHIVO_ENDPOINTS" ]]; then
            fases_completadas="${fases_completadas},\"crawl\""
        fi
    fi

    # ----------------------------------------------------------------
    # Paso 8: Vuln Scanning con nuclei (solo en --full y sin --no-nuclei)
    # ----------------------------------------------------------------
    touch "$ARCHIVO_NUCLEI"
    local n_vulns=0
    if $MODO_FULL && ! $SIN_NUCLEI && ! $SOLO_DNS && [[ -s "$ARCHIVO_VIVOS" ]]; then
        fase_nuclei "$ARCHIVO_VIVOS" "$ARCHIVO_NUCLEI"
        if [[ -s "$ARCHIVO_NUCLEI" ]]; then
            n_vulns=$(wc -l < "$ARCHIVO_NUCLEI")
            fases_completadas="${fases_completadas},\"vulns\""
        fi
    fi

    # ----------------------------------------------------------------
    # Paso 9: Comparación con scan anterior (si se pasó -f)
    # ----------------------------------------------------------------
    local n_nuevos=-1
    local n_inactivos=-1
    if [[ -n "$ARCHIVO_ANTERIOR" && -f "$ARCHIVO_ANTERIOR" ]]; then
        comparar_scans "$ARCHIVO_ANTERIOR" "$ARCHIVO_VIVOS" "$CARPETA_DOMINIO" "$DOMINIO"
        n_nuevos=$(wc -l < "$CARPETA_DOMINIO/nuevos_subdominios_${DOMINIO}.txt")
        n_inactivos=$(wc -l < "$CARPETA_DOMINIO/subdominios_inactivos_${DOMINIO}.txt")
    elif [[ -n "$ARCHIVO_ANTERIOR" && ! -f "$ARCHIVO_ANTERIOR" ]]; then
        msg_warn "Archivo anterior '$ARCHIVO_ANTERIOR' no encontrado. Omitiendo comparación."
    fi

    # ----------------------------------------------------------------
    # Paso 10: Generar JSON de resultados
    # ----------------------------------------------------------------
    local n_endpoints=0
    [[ -s "$ARCHIVO_ENDPOINTS" ]] && n_endpoints=$(wc -l < "$ARCHIVO_ENDPOINTS")

    local n_new_comp=0 n_removed_comp=0
    [[ $n_nuevos -ge 0 ]] && n_new_comp=$n_nuevos
    [[ $n_inactivos -ge 0 ]] && n_removed_comp=$n_inactivos

    generar_json \
        "$DOMINIO" \
        "$CARPETA_DOMINIO" \
        "$PERFIL" \
        "[${fases_completadas}]" \
        "$total_raw" \
        "$n_unicos" \
        "$n_resueltos" \
        "$n_vivos" \
        "$n_new_comp" \
        "$n_removed_comp" \
        "$count_subfinder" \
        "$count_amass" \
        "$count_crtsh" \
        "$count_assetfinder" \
        "$count_wayback" \
        "$count_gau" \
        "$ARCHIVO_HTTPX" \
        "$ARCHIVO_PORTS" \
        "$ARCHIVO_NUCLEI" \
        "$ARCHIVO_ENDPOINTS" \
        "$ARCHIVO_ANTERIOR" \
        "$ARCHIVO_VIVOS"

    # ----------------------------------------------------------------
    # Limpieza de archivos intermedios de herramientas
    # ----------------------------------------------------------------
    rm -rf "$DIRECTORIO_TEMP"
    DIRECTORIO_TEMP=""

    # ----------------------------------------------------------------
    # Resumen
    # ----------------------------------------------------------------
    mostrar_resumen \
        "$DOMINIO" \
        "$total_raw" \
        "$n_unicos" \
        "$n_resueltos" \
        "$n_vivos" \
        "$n_nuevos" \
        "$n_inactivos" \
        "$CARPETA_DOMINIO" \
        "$(basename "$ARCHIVO_FINAL")" \
        "$n_vulns" \
        "$n_endpoints"

    # ----------------------------------------------------------------
    # Reporte HTML (si existe el script)
    # ----------------------------------------------------------------
    local JSON_SALIDA="$CARPETA_DOMINIO/scan_data.json"
    if [[ -f "$JSON_SALIDA" ]]; then
        local REPORT_SCRIPT
        REPORT_SCRIPT="$(dirname "$0")/attackmap_report.py"
        if [[ -f "$REPORT_SCRIPT" ]] && command -v python3 &>/dev/null; then
            msg_info "Generando reporte HTML..."
            python3 "$REPORT_SCRIPT" "$JSON_SALIDA" "$CARPETA_DOMINIO/report_${DOMINIO}_${FECHA}.html" || true
            if [[ -f "$CARPETA_DOMINIO/report_${DOMINIO}_${FECHA}.html" ]]; then
                msg_ok "Reporte: $CARPETA_DOMINIO/report_${DOMINIO}_${FECHA}.html"
            fi
        fi
    fi
}

# =============================================================================
# MAIN
# =============================================================================

mostrar_banner

# -----------------------------------------------------------------------------
# Parseo de argumentos (incluyendo flags largos)
# -----------------------------------------------------------------------------
DOMINIO=""
LISTA_DOMINIOS=""
ARCHIVO_ANTERIOR=""
DIR_SALIDA="resultados"
HILOS=50
MODO_QUICK=false
SOLO_DNS=false
MODO_FULL=false
SIN_NUCLEI=false

# Procesar flags largos antes de getopts
args=()
for arg in "$@"; do
    case "$arg" in
        --quick)        MODO_QUICK=true ;;
        --resolve-only) SOLO_DNS=true ;;
        --full)         MODO_FULL=true ;;
        --no-nuclei)    SIN_NUCLEI=true ;;
        --help)         mostrar_uso; exit 0 ;;
        *)              args+=("$arg") ;;
    esac
done
set -- "${args[@]+"${args[@]}"}"

while getopts ":d:f:L:o:t:h" opcion; do
    case $opcion in
        d) DOMINIO=$OPTARG ;;
        f) ARCHIVO_ANTERIOR=$OPTARG ;;
        L) LISTA_DOMINIOS=$OPTARG ;;
        o) DIR_SALIDA=$OPTARG ;;
        t) HILOS=$OPTARG ;;
        h) mostrar_uso; exit 0 ;;
        :) msg_err "La opción -$OPTARG requiere un argumento."; mostrar_uso; exit 1 ;;
        *) msg_err "Opción desconocida: -$OPTARG"; mostrar_uso; exit 1 ;;
    esac
done

if [[ -z "$DOMINIO" && -z "$LISTA_DOMINIOS" ]]; then
    msg_err "Debes proporcionar -d dominio.com o -L lista.txt"
    echo ""
    mostrar_uso
    exit 1
fi

# Validar que el directorio de salida exista o se pueda crear
mkdir -p "$DIR_SALIDA" 2>/dev/null || {
    msg_err "No se pudo crear el directorio de salida: $DIR_SALIDA"
    exit 1
}

# -----------------------------------------------------------------------------
# Verificar dependencias
# -----------------------------------------------------------------------------
verificar_dependencias

# Modo quick: asegurarse de que amass no corra aunque esté disponible
if $MODO_QUICK; then
    msg_warn "Modo --quick activo: se omitirá amass y assetfinder"
    echo ""
fi

if $MODO_FULL; then
    msg_info "Modo --full activo: se ejecutarán naabu, gowitness, katana y nuclei si están disponibles"
    $SIN_NUCLEI && msg_warn "  --no-nuclei: se omitirá la fase nuclei"
    echo ""
fi

# -----------------------------------------------------------------------------
# Ejecutar
# -----------------------------------------------------------------------------
if [[ -n "$LISTA_DOMINIOS" ]]; then
    if [[ ! -f "$LISTA_DOMINIOS" ]]; then
        msg_err "No se encontró el archivo de lista: $LISTA_DOMINIOS"
        exit 1
    fi
    while IFS= read -r dominio || [[ -n "$dominio" ]]; do
        # Ignorar líneas vacías y comentarios
        [[ -z "$dominio" || "$dominio" =~ ^# ]] && continue
        procesar_dominio "$dominio" "$DIR_SALIDA" "$ARCHIVO_ANTERIOR" \
                         "$MODO_QUICK" "$SOLO_DNS" "$HILOS" "$MODO_FULL" "$SIN_NUCLEI"
    done < "$LISTA_DOMINIOS"
else
    procesar_dominio "$DOMINIO" "$DIR_SALIDA" "$ARCHIVO_ANTERIOR" \
                     "$MODO_QUICK" "$SOLO_DNS" "$HILOS" "$MODO_FULL" "$SIN_NUCLEI"
fi

echo -e "${AMARILLO}${NEGRITA}  AttackMap finalizado.${RESET}\n"
