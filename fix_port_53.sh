#!/bin/bash
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}>>> LIMPIANDO PUERTO 53...${NC}"

# 1. Detener el servicio systemd (para que no se reinicie solo)
echo "Deteniendo servicio slipstream..."
systemctl stop slipstream 2>/dev/null
systemctl disable slipstream 2>/dev/null

# 2. Detener systemd-resolved (dueño por defecto del puerto 53 en Ubuntu)
echo "Deteniendo systemd-resolved..."
systemctl stop systemd-resolved 2>/dev/null
systemctl disable systemd-resolved 2>/dev/null

# 3. Matar cualquier proceso rebelde en el puerto 53
echo "Matando procesos en puerto 53..."
fuser -k 53/udp 2>/dev/null
fuser -k 53/tcp 2>/dev/null

# 4. Asegurar que tenemos DNS (porque al matar systemd-resolved se puede perder)
echo "Restaurando DNS temporal (1.1.1.1)..."
rm -f /etc/resolv.conf
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# 5. Verificación
echo "Verificando puerto..."
sleep 2
if lsof -i :53 >/dev/null; then
    echo -e "${RED}ALERTA: El puerto 53 sigue ocupado por:${NC}"
    lsof -i :53
else
    echo -e "${GREEN}¡PUERTO 53 LIBRE!${NC}"
    echo "Ya puedes ejecutar tu binario manualmente: ./server-linux-amd64"
fi
