#!/bin/bash

# Definir colores optimizados para fondo negro
VERDE="\033[92m"
ROJO="\033[91m"
AMARILLO="\033[93m"
CIAN="\033[96m"
BLANCO="\033[97m"
NEGRITA="\033[1m"
RESET="\033[0m"

# Lista de patrones a omitir (segmentos de red, ASN y otros valores irrelevantes)
SEGMENTOS_A_OMITIR="104.21.|108.162.|13335|162.159.|172.64.|172.67.|173.245.58.|2606:4700|2803:f800|2a06:98c1|398101|72.167."
PATRONES_A_OMITIR="^0$|^\*$|^aida.ns.cloudflare.com$|^ruben.ns.cloudflare.com$"

# Función para mostrar mensajes
mensaje_exito() { echo -e "${VERDE}✅ $1${RESET}"; }
mensaje_error() { echo -e "${ROJO}❌ $1${RESET}"; }
mensaje_info() { echo -e "${CIAN}🔍 $1${RESET}"; }
mensaje_aviso() { echo -e "${AMARILLO}⚠️ $1${RESET}"; }

# Función para mostrar el banner personalizado con el mapa
mostrar_banner() {
    echo -e "${VERDE}${NEGRITA}"
    echo " █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗     "
    echo "██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝████╗ ████║██╔══██╗██╔══██╗    "
    echo "███████║   ██║      ██║   ███████║██║     █████╔╝ ██╔████╔██║███████║██████╔╝    "
    echo "██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ ██║╚██╔╝██║██╔══██║██╔═══╝     "
    echo "██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗██║ ╚═╝ ██║██║  ██║██║         "
    echo "╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         "
    echo ""
    echo -e "${AMARILLO}\nBy Adrian Martinez${RESET}\n"
}

# Validar argumentos
ARCHIVO_ANTERIOR=""
LISTA_DOMINIOS=""

while getopts "d:f:L:" opcion; do
    case $opcion in
        d) DOMINIO=$OPTARG;;
        f) ARCHIVO_ANTERIOR=$OPTARG;;
        L) LISTA_DOMINIOS=$OPTARG;;
        *) echo -e "${ROJO}❌ Uso: $0 -d dominio.com [-f archivo_anterior.txt] | -L lista_de_dominios.txt${RESET}"; exit 1;;
    esac
done

if [ -z "$DOMINIO" ] && [ -z "$LISTA_DOMINIOS" ]; then
    echo -e "${ROJO}❌ Debes proporcionar un dominio con -d dominio.com o una lista con -L lista.txt${RESET}"
    exit 1
fi

# Función para buscar subdominios en crt.sh
buscar_subdominios_crtsh() {
    mensaje_info "Buscando subdominios en certificados SSL (crt.sh)..."
    curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[].name_value' | sort -u > "$2/crtsh_resultados.txt"
    mensaje_exito "Subdominios de certificados guardados."
}

# Función para verificar subdominios con `httprobe`
verificar_protocolo() {
    local archivo_entrada=$1
    local archivo_salida=$2
    local archivo_salida_https=$3
    local carpeta=$(dirname "$archivo_salida")

    mensaje_info "🚀 Verificando protocolo (http/https)..."
    
    # Crear una versión limpia de los subdominios (sin protocolo)
    cat "$archivo_entrada" | sed 's|https\?://||g' | sort -u > "$carpeta/tmp_subs.txt"

    # Ejecutar `httprobe`
    cat "$carpeta/tmp_subs.txt" | httprobe > "$carpeta/tmp_httprobe.txt"

    # Filtrar para priorizar HTTPS si existe y generar el archivo extra con protocolos
    awk '
    {
        subdomain=$0;
        gsub("https://", "", subdomain);
        gsub("http://", "", subdomain);
        if (!seen[subdomain]++) {
            urls[subdomain]=$0;
        } else if ($0 ~ /^https:\/\//) {
            urls[subdomain]=$0;
        }
    }
    END {
        for (s in urls) {
            print urls[s] > "'"$archivo_salida_https"'"; # Guardar con protocolos
            sub("https://", "", urls[s]);
            sub("http://", "", urls[s]);
            print urls[s] > "'"$archivo_salida"'"; # Guardar solo subdominios limpios
        }
    }' "$carpeta/tmp_httprobe.txt"

    rm "$carpeta/tmp_subs.txt" "$carpeta/tmp_httprobe.txt"

    mensaje_exito "✅ Verificación de protocolo completada. Resultados en $archivo_salida y $archivo_salida_https"
}

# Función para procesar un dominio individual
procesar_dominio() {
    local DOMINIO=$1
    mensaje_info "🔍 Buscando subdominios para: $DOMINIO..."

    FECHA=$(date +"%Y-%m-%d")
    CARPETA_DOMINIO="resultados/$DOMINIO"
    mkdir -p "$CARPETA_DOMINIO"

    ARCHIVO_ACTUAL="$CARPETA_DOMINIO/${DOMINIO}_${FECHA}.txt"
    ARCHIVO_HTTPS="$CARPETA_DOMINIO/https_${DOMINIO}_${FECHA}.txt"
    ARCHIVO_LOG="$CARPETA_DOMINIO/log_${DOMINIO}_${FECHA}.txt"

    mensaje_info "[1/4] Ejecutando Assetfinder..."
    assetfinder --subs-only "$DOMINIO" | tee "$CARPETA_DOMINIO/assetfinder_resultados.txt" >> "$ARCHIVO_LOG"
    mensaje_exito "✅ Assetfinder completado."

    mensaje_info "[2/4] Ejecutando Amass..."
    amass enum -passive -d "$DOMINIO" | tee "$CARPETA_DOMINIO/amass_resultados.txt" >> "$ARCHIVO_LOG"
    mensaje_exito "✅ Amass completado."

    mensaje_info "[3/4] Ejecutando Subfinder..."
    subfinder -silent -d "$DOMINIO" | tee "$CARPETA_DOMINIO/subfinder_resultados.txt" >> "$ARCHIVO_LOG"
    mensaje_exito "✅ Subfinder completado."

    mensaje_info "[4/4] Ejecutando búsqueda en crt.sh..."
    buscar_subdominios_crtsh "$DOMINIO" "$CARPETA_DOMINIO"

    verificar_protocolo "$ARCHIVO_ACTUAL" "$ARCHIVO_ACTUAL" "$ARCHIVO_HTTPS"

    rm "$CARPETA_DOMINIO/"*resultados.txt

    mensaje_exito "📁 Resultados guardados en: $CARPETA_DOMINIO"
}

# Ejecutar el script
mostrar_banner

if [ -n "$LISTA_DOMINIOS" ]; then
    while IFS= read -r dominio || [[ -n "$dominio" ]]; do
        procesar_dominio "$dominio"
    done < "$LISTA_DOMINIOS"
else
    procesar_dominio "$DOMINIO"
fi

echo -e "\n🚀 ${AMARILLO}Gracias por usar AttackMap 🕵️‍♂️${RESET}"
