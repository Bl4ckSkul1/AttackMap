# AttackMap
AttackMap 🕵️‍♂️ es una herramienta de reconocimiento de subdominios para pentesters y equipos de seguridad. Usa Assetfinder, Amass, Subfinder y crt.sh, verifica activos con httprobe, prioriza HTTPS y permite comparar escaneos. Soporta análisis de un dominio o lista, organizando resultados en carpetas. 🚀 Visibilidad total de tu perímetro.
🔥 Características Principales

✅ Búsqueda Avanzada de Subdominios: Combina Assetfinder, Amass, Subfinder y crt.sh para obtener la mayor cantidad de información.
✅ Comparación con Análisis Anteriores: Identifica nuevos subdominios, eliminados y activos, útil para monitoreo continuo.
✅ Verificación de Estado: Usa httprobe para detectar subdominios accesibles y prioriza HTTPS si está disponible.
✅ Registro de Resultados: Guarda logs detallados con cada escaneo, asegurando auditoría y análisis posterior.
✅ Análisis por Dominio o Lista de Dominios: Permite escanear un dominio específico (-d) o una lista de dominios (-L) en simultáneo.
✅ Estructura Organizada: Guarda los resultados en carpetas por dominio, generando archivos con la fecha del escaneo.

📌 Instalación
git clone https://github.com/tuusuario/AttackMap.git
cd AttackMap
chmod +x attackmap.sh

📌 Requisitos
sudo apt install assetfinder amass subfinder jq curl httprobe

En MacOS, usa:
brew install assetfinder amass subfinder jq curl
go install github.com/tomnomnom/httprobe@latest

resultados/
 ├── ejemplo.com/
 │   ├── ejemplo.com_2025-03-20.txt  # Subdominios detectados
 │   ├── https_ejemplo.com_2025-03-20.txt  # Solo subdominios con HTTP/HTTPS
 │   ├── log_ejemplo.com_2025-03-20.txt  # Log completo del escaneo
 │   ├── nuevos_subdominios_2025-03-20.txt  # Subdominios nuevos detectados
 │   ├── subdominios_inactivos_2025-03-20.txt  # Subdominios eliminados o inactivos

🎯 Casos de Uso

🔎 Pentesting: Automatiza y Obtén información detallada de activos de un objetivo.
📊 Monitoreo de Superficie de Ataque: Detecta nuevos subdominios de manera periódica.
🔬 Investigación de Seguridad: Identifica activos mal configurados o en riesgo.
🕵️ Ciberinteligencia: Recolecta subdominios de empresas para análisis de amenazas.

⚠️ Disclaimer

Este script es exclusivamente para fines educativos y de auditoría con permiso. El uso indebido de esta herramienta puede estar sujeto a sanciones legales. Usa AttackMap de forma responsable.

⸻

🚀 AttackMap - Ahora tienes visibilidad total de tu perímetro 🛡️
🔗 GitHub Repo: https://github.com/tuusuario/AttackMap
