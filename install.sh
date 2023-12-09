#!/usr/bin/env bash
# 检测区
# -------------------------------------------------------------
# 检查系统
export LANG=en_US.UTF-8

echoContent() {
    case $1 in
    # 红色
    "red")
        # shellcheck disable=SC2154
        ${echoType} "\033[31m${printN}$2 \033[0m"
        ;;
        # 天蓝色
    "skyBlue")
        ${echoType} "\033[1;36m${printN}$2 \033[0m"
        ;;
        # 绿色
    "green")
        ${echoType} "\033[32m${printN}$2 \033[0m"
        ;;
        # 白色
    "white")
        ${echoType} "\033[37m${printN}$2 \033[0m"
        ;;
    "magenta")
        ${echoType} "\033[31m${printN}$2 \033[0m"
        ;;
        # 黄色
    "yellow")
        ${echoType} "\033[33m${printN}$2 \033[0m"
        ;;
    esac
}

checkCentosSELinux() {
    if [[ -f "/etc/selinux/config" ]] && ! grep -q "SELINUX=disabled" <"/etc/selinux/config"; then
        echoContent yellow "# Notes"
        echoContent yellow "It is detected that SELinux is turned on. Please turn it off manually. The tutorial is as follows"
        echoContent yellow "https://www.v2ray-agent.com/archives/1679931532764#heading-8 "
        exit 0
    fi
}

checkSystem() {
    if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
        mkdir -p /etc/yum.repos.d

        if [[ -f "/etc/centos-release" ]]; then
            centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')

            if [[ -z "${centosVersion}" ]] && grep </etc/centos-release -q -i "release 8"; then
                centosVersion=8
            fi
        fi

        release="centos"
        installType='yum -y install'
        removeType='yum -y remove'
        upgrade="yum update -y --skip-broken"
        checkCentosSELinux
    elif [[ -f "/etc/issue" ]] && grep </etc/issue -q -i "debian" || [[ -f "/proc/version" ]] && grep </etc/issue -q -i "debian" || [[ -f "/etc/os-release" ]] && grep </etc/os-release -q -i "ID=debian"; then
        release="debian"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'

    elif [[ -f "/etc/issue" ]] && grep </etc/issue -q -i "ubuntu" || [[ -f "/proc/version" ]] && grep </etc/issue -q -i "ubuntu"; then
        release="ubuntu"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'
        if grep </etc/issue -q -i "16."; then
            release=
        fi
    fi

if [[ -z ${release} ]]; then
        echoContent red "\nThis script does not support this system, please feedback the following log to the developer\n"
        echoContent yellow "$(cat /etc/issue)"
        echoContent yellow "$(cat /proc/version)"
        exit 0
    fi
}


checkCPUVendor() {
    if [[ -n $(which uname) ]]; then
        if [[ "$(uname)" == "Linux" ]]; then
            case "$(uname -m)" in
            'amd64' | 'x86_64')
                xrayCoreCPUVendor="Xray-linux-64"
                v2rayCoreCPUVendor="v2ray-linux-64"
                hysteriaCoreCPUVendor="hysteria-linux-amd64"
                tuicCoreCPUVendor="-x86_64-unknown-linux-musl"
                warpRegCoreCPUVendor="main-linux-amd64"
                singBoxCoreCPUVendor="-linux-amd64"
                ;;
            'armv8' | 'aarch64')
                cpuVendor="arm"
                xrayCoreCPUVendor="Xray-linux-arm64-v8a"
                v2rayCoreCPUVendor="v2ray-linux-arm64-v8a"
                hysteriaCoreCPUVendor="hysteria-linux-arm64"
                tuicCoreCPUVendor="-aarch64-unknown-linux-musl"
                warpRegCoreCPUVendor="main-linux-arm64"
                singBoxCoreCPUVendor="-linux-arm64"
                ;;
            *)
                echo "This CPU architecture is not supported --->"
                exit 1
                ;;
            esac
        fi
    else
        echoContent red "This CPU architecture cannot be recognized, the default is amd64, x86_64--->"
        xrayCoreCPUVendor="Xray-linux-64"
        v2rayCoreCPUVendor="v2ray-linux-64"
    fi
}


initVar() {
    installType='yum -y install'
    removeType='yum -y remove'
    upgrade="yum -y update"
    echoType='echo -e'
    xrayCoreCPUVendor=""
    v2rayCoreCPUVendor=""
    hysteriaCoreCPUVendor=""
    warpRegCoreCPUVendor=""
    cpuVendor=""


    domain=
    add=
    totalProgress=1
    coreInstallType=
    ctlPath=
    currentInstallProtocolType=
    currentAlpn=
    frontingType=
    selectCustomInstallType=
    configPath=
    realityStatus=
    hysteriaConfigPath=
    singBoxConfigPath=
    portHoppingStart=
    portHoppingEnd=
    portHopping=
    tuicConfigPath=
    tuicAlgorithm=
    tuicPort=
    currentPath=
    currentHost=
    selectCoreType=
    v2rayCoreVersion=
    customPath=
    centosVersion=
    currentUUID=
    currentClients=
    previousClients=
    localIP=
    cronName=$1
    installTLSCount=
    btDomain=
    nginxConfigPath=/etc/nginx/conf.d/
    nginxStaticPath=/usr/share/nginx/html/
    prereleaseStatus=false
    sslType=
    cfAPIToken=
    sslEmail=
    sslRenewalDays=90
    dnsTLSDomain=
    customPort=
    hysteriaPort=
    hysteriaProtocol=
    hysteria2ClientDownloadSpeed=
    hysteria2ClientUploadSpeed=
    realityPrivateKey=
    realityServerNames=
    realityDestDomain=
    wgetShowProgressStatus=
    reservedWarpReg=
    publicKeyWarpReg=
    addressWarpReg=
    secretKeyWarpReg=
}


readAcmeTLS() {
    local readAcmeDomain=
    if [[ -n "${currentHost}" ]]; then
        readAcmeDomain="${currentHost}"
    else
        readAcmeDomain="${domain}"
    fi
    dnsTLSDomain=$(echo "${readAcmeDomain}" | awk -F "." '{$1="";print $0}' | sed 's/^[[:space:]]*//' | sed 's/ /./g')
    if [[ -d "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.key" && -f "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.cer" ]]; then
        installedDNSAPIStatus=true
    fi
}

readCustomPort() {
    if [[ -n "${configPath}" && -z "${realityStatus}" ]]; then
        local port=
        port=$(jq -r .inbounds[0].port "${configPath}${frontingType}.json")
        if [[ "${port}" != "443" ]]; then
            customPort=${port}
        fi
    fi
}

readInstallType() {
    coreInstallType=
    configPath=
    singBoxConfigPath=

    if [[ -d "/etc/v2ray-agent" ]]; then
        if [[ -d "/etc/v2ray-agent/xray" && -f "/etc/v2ray-agent/xray/xray" ]]; then
            if [[ -d "/etc/v2ray-agent/xray/conf" ]] && [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/02_trojan_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/07_VLESS_vision_reality_inbounds.json" ]]; then
                configPath=/etc/v2ray-agent/xray/conf/
                ctlPath=/etc/v2ray-agent/xray/xray
                coreInstallType=1
                if [[ -f "${configPath}07_VLESS_vision_reality_inbounds.json" ]]; then
                    realityStatus=1
                fi
            fi
        fi

        if [[ -d "/etc/v2ray-agent/hysteria" && -f "/etc/v2ray-agent/hysteria/hysteria" ]]; then
            if [[ -d "/etc/v2ray-agent/hysteria/conf" ]] && [[ -f "/etc/v2ray-agent/hysteria/conf/config.json" ]]; then
                hysteriaConfigPath=/etc/v2ray-agent/hysteria/conf/
            fi
        fi

        if [[ -d "/etc/v2ray-agent/tuic" && -f "/etc/v2ray-agent/tuic/tuic" ]]; then
            if [[ -d "/etc/v2ray-agent/tuic/conf" ]] && [[ -f "/etc/v2ray-agent/tuic/conf/config.json" ]]; then
                tuicConfigPath=/etc/v2ray-agent/tuic/conf/
            fi
        fi

        if [[ -d "/etc/v2ray-agent/sing-box" && -f "/etc/v2ray-agent/sing-box/sing-box" ]]; then
            if [[ -d "/etc/v2ray-agent/sing-box/conf" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config/tuic.json" || -f "/etc/v2ray-agent/sing-box/conf/config/hysteria2.json" ]]; then
                singBoxConfigPath=/etc/v2ray-agent/sing-box/conf/
            fi
        fi

    fi
}


readInstallProtocolType() {
    currentInstallProtocolType=
    frontingType=
    while read -r row; do
        if echo "${row}" | grep -q 02_trojan_TCP_inbounds; then
            currentInstallProtocolType=${currentInstallProtocolType}'trojan'
            frontingType=02_trojan_TCP_inbounds
        fi
        if echo "${row}" | grep -q VLESS_TCP_inbounds; then
            currentInstallProtocolType=${currentInstallProtocolType}'0'
            frontingType=02_VLESS_TCP_inbounds
        fi
        if echo "${row}" | grep -q VLESS_WS_inbounds; then
            currentInstallProtocolType=${currentInstallProtocolType}'1'
        fi
        if echo "${row}" | grep -q trojan_gRPC_inbounds; then
            currentInstallProtocolType=${currentInstallProtocolType}'2'
        fi
        if echo "${row}" | grep -q VMess_WS_inbounds; then
            currentInstallProtocolType=${currentInstallProtocolType}'3'
        fi
        if echo "${row}" | grep -q 04_trojan_TCP_inbounds; then
            currentInstallProtocolType=${currentInstallProtocolType}'4'
        fi
        if echo "${row}" | grep -q VLESS_gRPC_inbounds; then
            currentInstallProtocolType=${currentInstallProtocolType}'5'
        fi
        if echo "${row}" | grep -q VLESS_vision_reality_inbounds; then
            currentInstallProtocolType=${currentInstallProtocolType}'7'
        fi
        if echo "${row}" | grep -q VLESS_reality_fallback_grpc_inbounds; then
            currentInstallProtocolType=${currentInstallProtocolType}'8'
        fi

    done < <(find ${configPath} -name "*inbounds.json" | awk -F "[.]" '{print $1}')

    if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config.json" ]] && grep -q 'hysteria2' </etc/v2ray-agent/sing-box/conf/config.json; then
        currentInstallProtocolType=${currentInstallProtocolType}'6'
    fi
    if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config.json" ]] && grep -q 'tuic' </etc/v2ray-agent/sing-box/conf/config.json; then
        currentInstallProtocolType=${currentInstallProtocolType}'9'
    fi
}


checkBTPanel() {
    if [[ -n $(pgrep -f "BT-Panel") ]]; then
        if [[ -d '/www/server/panel/vhost/cert/' && -n $(find /www/server/panel/vhost/cert/*/fullchain.pem) ]]; then
            if [[ -z "${currentHost}" ]]; then
                echoContent skyBlue "\nRead pagoda configuration\n"

                find /www/server/panel/vhost/cert/*/fullchain.pem | awk -F "[/]" '{print $7}' | awk '{print NR""":"$0}'

                read -r -p "Please enter the number to select:" selectBTDomain
            else
                selectBTDomain=$(find /www/server/panel/vhost/cert/*/fullchain.pem | awk -F "[/]" '{print $7}' | awk '{print NR""":"$0}' | grep "${currentHost}" | cut -d ":" -f 1)
            fi

            if [[ -n "${selectBTDomain}" ]]; then
                btDomain=$(find /www/server/panel/vhost/cert/*/fullchain.pem | awk -F "[/]" '{print $7}' | awk '{print NR""":"$0}' | grep "${selectBTDomain}:" | cut -d ":" -f 2)

                if [[ -z "${btDomain}" ]]; then
                    echoContent red " ---> Wrong selection, please select again"
                    checkBTPanel
                else
                    domain=${btDomain}
                    if [[ ! -f "/etc/v2ray-agent/tls/${btDomain}.crt" && ! -f "/etc/v2ray-agent/tls/${btDomain}.key" ]]; then
                        ln -s "/www/server/panel/vhost/cert/${btDomain}/fullchain.pem" "/etc/v2ray-agent/tls/${btDomain}.crt"
                        ln -s "/www/server/panel/vhost/cert/${btDomain}/privkey.pem" "/etc/v2ray-agent/tls/${btDomain}.key"
                    fi

                    nginxStaticPath="/www/wwwroot/${btDomain}/"
                    if [[ -f "/www/wwwroot/${btDomain}/.user.ini" ]]; then
                        chattr -i "/www/wwwroot/${btDomain}/.user.ini"
                    fi
                    nginxConfigPath="/www/server/panel/vhost/nginx/"
                fi
            else
                echoContent red " ---> Wrong selection, please select again"
                checkBTPanel
            fi
        fi
    fi
}


readInstallAlpn() {
    if [[ -n "${currentInstallProtocolType}" && -z "${realityStatus}" ]]; then
        local alpn
        alpn=$(jq -r .inbounds[0].streamSettings.tlsSettings.alpn[0] ${configPath}${frontingType}.json)
        if [[ -n ${alpn} ]]; then
            currentAlpn=${alpn}
        fi
    fi
}


allowPort() {
    local type=$2
    if [[ -z "${type}" ]]; then
        type=tcp
    fi
    if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
        local updateFirewalldStatus=
        if ! iptables -L | grep -q "$1/${type}(mack-a)"; then
            updateFirewalldStatus=true
            iptables -I INPUT -p ${type} --dport "$1" -m comment --comment "allow $1/${type}(mack-a)" -j ACCEPT
        fi

        if echo "${updateFirewalldStatus}" | grep -q "true"; then
            netfilter-persistent save
        fi
    elif systemctl status ufw 2>/dev/null | grep -q "active (exited)"; then
        if ufw status | grep -q "Status: active"; then
            if ! ufw status | grep -q "$1/${type}"; then
                sudo ufw allow "$1/${type}"
                checkUFWAllowPort "$1"
            fi
        fi

    elif systemctl status firewalld 2>/dev/null | grep -q "active (running)"; then
        local updateFirewalldStatus=
        if ! firewall-cmd --list-ports --permanent | grep -qw "$1/${type}"; then
            updateFirewalldStatus=true
            local firewallPort=$1

            if echo "${firewallPort}" | grep ":"; then
                firewallPort=$(echo "${firewallPort}" | awk -F ":" '{print $1-$2}')
            fi

            firewall-cmd --zone=public --add-port="${firewallPort}/${type}" --permanent
            checkFirewalldAllowPort "${firewallPort}"
        fi

        if echo "${updateFirewalldStatus}" | grep -q "true"; then
            firewall-cmd --reload
        fi
    fi
}


getPublicIP() {
    local type=4
    if [[ -n "$1" ]]; then
        type=$1
    fi
    if [[ -n "${currentHost}" && -n "${currentRealityServerNames}" && "${currentRealityServerNames}" == "${currentHost}" && -z "$1" ]]; then
        echo "${currentHost}"
    else
        local currentIP=
        currentIP=$(curl -s "-${type}" http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}')
        if [[ -z "${currentIP}" && -z "$1" ]]; then
            currentIP=$(curl -s "-6" http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | awk -F "[=]" '{print $2}')
        fi
        echo "${currentIP}"
    fi

}


checkUFWAllowPort() {
    if ufw status | grep -q "$1"; then
        echoContent green " ---> $1 port opened successfully"
    else
        echoContent red " ---> $1 port opening failed"
        exit 0
    fi
}

s
checkFirewalldAllowPort() {
    if firewall-cmd --list-ports --permanent | grep -q "$1"; then
        echoContent green " ---> $1 port opened successfully"
    else
        echoContent red " ---> $1 port opening failed"
        exit 0
    fi
}


readHysteriaConfig() {
    if [[ -n "${hysteriaConfigPath}" ]]; then
        hysteriaPort=$(jq -r .listen <"${hysteriaConfigPath}config.json" | awk -F "[:]" '{print $2}')
    fi
}


readSingBoxConfig() {
    if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config.json" ]]; then
        if grep -q 'tuic' </etc/v2ray-agent/sing-box/conf/config.json; then
            tuicPort=$(jq -r '.inbounds[]|select(.type=="tuic")|(.listen_port)' <"${singBoxConfigPath}config.json")
            tuicAlgorithm=$(jq -r '.inbounds[]|select(.type=="tuic")|(.congestion_control)' <"${singBoxConfigPath}config.json")
        fi

        if grep -q 'hysteria2' </etc/v2ray-agent/sing-box/conf/config.json; then
            hysteriaPort=$(jq -r '.inbounds[]|select(.type=="hysteria2")|(.listen_port)' <"${singBoxConfigPath}config.json")
            hysteria2ClientUploadSpeed=$(jq -r '.inbounds[]|select(.type=="hysteria2")|(.down_mbps)' <"${singBoxConfigPath}config.json")
            hysteria2ClientDownloadSpeed=$(jq -r '.inbounds[]|select(.type=="hysteria2")|(.up_mbps)' <"${singBoxConfigPath}config.json")
        fi
    fi
}


unInstallSingBox() {
    local type=$1
    if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config.json" ]]; then
        if grep -q 'tuic' </etc/v2ray-agent/sing-box/conf/config.json && [[ "${type}" == "tuic" ]]; then
            rm "${singBoxConfigPath}config/tuic.json"
            echoContent green " ---> Deletion of sing-box tuic configuration successful"
        fi

        if grep -q 'hysteria2' </etc/v2ray-agent/sing-box/conf/config.json && [[ "${type}" == "hysteria2" ]]; then
            rm "${singBoxConfigPath}config/hysteria2.json"
            echoContent green " ---> Delete sing-box hysteria2 configuration successfully"
        fi
        rm "${singBoxConfigPath}config.json"
    fi

    readInstallType

    if [[ -n "${singBoxConfigPath}" ]]; then
        echoContent yellow " ---> Other configurations are detected and the sing-box core is retained"
        handleSingBox stop
        handleSingBox start
    else
        handleSingBox stop
        rm /etc/systemd/system/sing-box.service
        rm -rf /etc/v2ray-agent/sing-box/*
        echoContent green " ---> sing-box uninstall completed"
    fi
}


readXrayCoreRealityConfig() {
    currentRealityServerNames=
    currentRealityPublicKey=
    currentRealityPrivateKey=
    currentRealityPort=

    if [[ -n "${realityStatus}" ]]; then
        currentRealityServerNames=$(jq -r .inbounds[0].streamSettings.realitySettings.serverNames[0] "${configPath}07_VLESS_vision_reality_inbounds.json")
        currentRealityPublicKey=$(jq -r .inbounds[0].streamSettings.realitySettings.publicKey "${configPath}07_VLESS_vision_reality_inbounds.json")
        currentRealityPrivateKey=$(jq -r .inbounds[0].streamSettings.realitySettings.privateKey "${configPath}07_VLESS_vision_reality_inbounds.json")
        currentRealityPort=$(jq -r .inbounds[0].port "${configPath}07_VLESS_vision_reality_inbounds.json")
    fi
}


readConfigHostPathUUID() {
    currentPath=
    currentDefaultPort=
    currentUUID=
    currentClients=
    currentHost=
    currentPort=
    currentAdd=

    if [[ "${coreInstallType}" == "1" ]]; then

        if [[ -n "${frontingType}" ]]; then
            currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
            currentAdd=$(jq -r .inbounds[0].add ${configPath}${frontingType}.json)

            if [[ "${currentAdd}" == "null" ]]; then
                currentAdd=${currentHost}
            fi
            currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)

            local defaultPortFile=
            defaultPortFile=$(find ${configPath}* | grep "default")

            if [[ -n "${defaultPortFile}" ]]; then
                currentDefaultPort=$(echo "${defaultPortFile}" | awk -F [_] '{print $4}')
            else
                currentDefaultPort=$(jq -r .inbounds[0].port ${configPath}${frontingType}.json)
            fi
            currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
            currentClients=$(jq -r .inbounds[0].settings.clients ${configPath}${frontingType}.json)
        fi

        if [[ -n "${realityStatus}" && -z "${currentClients}" ]]; then
            currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}07_VLESS_vision_reality_inbounds.json)
            currentClients=$(jq -r .inbounds[0].settings.clients ${configPath}07_VLESS_vision_reality_inbounds.json)

        fi
    elif [[ "${coreInstallType}" == "2" ]]; then
        currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
        currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)

        if [[ "${currentAdd}" == "null" ]]; then
            currentAdd=${currentHost}
        fi
        currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
        currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)
    fi

    if [[ -n "${configPath}" && -n "${frontingType}" ]]; then
        local fallback
        fallback=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.path)' ${configPath}${frontingType}.json | head -1)

        local path
        path=$(echo "${fallback}" | jq -r .path | awk -F "[/]" '{print $2}')

        if [[ $(echo "${fallback}" | jq -r .dest) == 31297 ]]; then
            currentPath=$(echo "${path}" | awk -F "[w][s]" '{print $1}')
        elif [[ $(echo "${fallback}" | jq -r .dest) == 31299 ]]; then
            currentPath=$(echo "${path}" | awk -F "[v][w][s]" '{print $1}')
        fi

        if [[ -z "${currentPath}" ]]; then
            dest=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.alpn)|.dest' ${configPath}${frontingType}.json | head -1)
            if [[ "${dest}" == "31302" || "${dest}" == "31304" ]]; then
                checkBTPanel
                if grep -q "trojangrpc {" <${nginxConfigPath}alone.conf; then
                    currentPath=$(grep "trojangrpc {" <${nginxConfigPath}alone.conf | awk -F "[/]" '{print $2}' | awk -F "[t][r][o][j][a][n]" '{print $1}')
                elif grep -q "grpc {" <${nginxConfigPath}alone.conf; then
                    currentPath=$(grep "grpc {" <${nginxConfigPath}alone.conf | head -1 | awk -F "[/]" '{print $2}' | awk -F "[g][r][p][c]" '{print $1}')
                fi
            fi
        fi

    fi
}


showInstallStatus() {
    if [[ -n "${coreInstallType}" ]]; then
        if [[ "${coreInstallType}" == 1 ]]; then
            if [[ -n $(pgrep -f "xray/xray") ]]; then
                echoContent yellow "\nCore: Xray-core[Running]"
            else
                echoContent yellow "\nCore: Xray-core[not running]"
            fi

        elif [[ "${coreInstallType}" == 2 ]]; then
            if [[ -n $(pgrep -f "v2ray/v2ray") ]]; then
                echoContent yellow "\nCore: v2ray-core[Running]"
            else
                echoContent yellow "\nCore: v2ray-core[not running]"
            fi
        fi
      
        readInstallProtocolType

        if [[ -n ${currentInstallProtocolType} ]]; then
            echoContent yellow "已安装协议: \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q 0; then
            if [[ "${coreInstallType}" == 2 ]]; then
                echoContent yellow "VLESS+TCP[TLS] \c"
            else
                echoContent yellow "VLESS+TCP[TLS_Vision] \c"
            fi
        fi

        if echo ${currentInstallProtocolType} | grep -q trojan; then
            if [[ "${coreInstallType}" == 1 ]]; then
                echoContent yellow "Trojan+TCP[TLS_Vision] \c"
            fi
        fi

        if echo ${currentInstallProtocolType} | grep -q 1; then
            echoContent yellow "VLESS+WS[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q 2; then
            echoContent yellow "Trojan+gRPC[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q 3; then
            echoContent yellow "VMess+WS[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q 4; then
            echoContent yellow "Trojan+TCP[TLS] \c"
        fi

        if echo ${currentInstallProtocolType} | grep -q 5; then
            echoContent yellow "VLESS+gRPC[TLS] \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q 6; then
            echoContent yellow "Hysteria2 \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q 7; then
            echoContent yellow "VLESS+Reality+Vision \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q 8; then
            echoContent yellow "VLESS+Reality+gRPC \c"
        fi
        if echo ${currentInstallProtocolType} | grep -q 9; then
            echoContent yellow "Tuic \c"
        fi
    fi
}

cleanUp() {
    if [[ "$1" == "xrayClean" ]]; then
        rm -rf "$(find /etc/v2ray-agent/xray/* | grep -E '(config_full.json|conf)')"
        handleXray stop >/dev/null
        rm -f /etc/systemd/system/xray.service

    elif [[ "$1" == "v2rayDel" ]]; then
        rm -rf /etc/v2ray-agent/v2ray/*

    elif [[ "$1" == "xrayDel" ]]; then
        rm -rf /etc/v2ray-agent/xray/*
    fi
}
initVar "$1"
checkSystem
checkCPUVendor
readInstallType
readInstallProtocolType
readConfigHostPathUUID
readInstallAlpn
readCustomPort
readXrayCoreRealityConfig

mkdirTools() {
    mkdir -p /etc/v2ray-agent/tls
    mkdir -p /etc/v2ray-agent/subscribe_local/default
    mkdir -p /etc/v2ray-agent/subscribe_local/clashMeta

    mkdir -p /etc/v2ray-agent/subscribe_remote/default
    mkdir -p /etc/v2ray-agent/subscribe_remote/clashMeta

    mkdir -p /etc/v2ray-agent/subscribe/default
    mkdir -p /etc/v2ray-agent/subscribe/clashMetaProfiles
    mkdir -p /etc/v2ray-agent/subscribe/clashMeta

    mkdir -p /etc/v2ray-agent/v2ray/conf
    mkdir -p /etc/v2ray-agent/v2ray/tmp
    mkdir -p /etc/v2ray-agent/xray/conf
    mkdir -p /etc/v2ray-agent/xray/reality_scan
    mkdir -p /etc/v2ray-agent/xray/tmp
    mkdir -p /etc/v2ray-agent/hysteria/conf
    mkdir -p /etc/systemd/system/
    mkdir -p /tmp/v2ray-agent-tls/

    mkdir -p /etc/v2ray-agent/warp

    mkdir -p /etc/v2ray-agent/tuic/conf

    mkdir -p /etc/v2ray-agent/sing-box/conf/config
}

installTools() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Installation tools"
    if [[ "${release}" == "ubuntu" ]]; then
        dpkg --configure -a
    fi

    if [[ -n $(pgrep -f "apt") ]]; then
        pgrep -f apt | xargs kill -9
    fi

    echoContent green " ---> Check and install updates [The new machine will be very slow. If there is no response for a long time, please stop it manually and then execute it again]"

    ${upgrade} >/etc/v2ray-agent/install.log 2>&1
    if grep <"/etc/v2ray-agent/install.log" -q "changed"; then
        ${updateReleaseInfoChange} >/dev/null 2>&1
    fi

    if [[ "${release}" == "centos" ]]; then
        rm -rf /var/run/yum.pid
        ${installType} epel-release >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w wget; then
        echoContent green " ---> Install wget"
        ${installType} wget >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w curl; then
        echoContent green " ---> Install curl"
        ${installType} curl >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w unzip; then
        echoContent green " ---> install unzip"
        ${installType} unzip >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w socat; then
        echoContent green " ---> Install socat"
        ${installType} socat >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w tar; then
        echoContent green " ---> Install tar"
        ${installType} tar >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w cron; then
        echoContent green " ---> install crontabs"
        if [[ "${release}" == "ubuntu" ]] || [[ "${release}" == "debian" ]]; then
            ${installType} cron >/dev/null 2>&1
        else
            ${installType} crontabs >/dev/null 2>&1
        fi
    fi
    if ! find /usr/bin /usr/sbin | grep -q -w jq; then
        echoContent green " ---> Install jq"
        ${installType} jq >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w binutils; then
        echoContent green " ---> Install binutils"
        ${installType} binutils >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w ping6; then
        echoContent green " ---> Install ping6"
        ${installType} inetutils-ping >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w qrencode; then
        echoContent green " ---> Install qrencode"
        ${installType} qrencode >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w sudo; then
        echoContent green " ---> install sudo"
        ${installType} sudo >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w lsb-release; then
        echoContent green " ---> install lsb-release"
        ${installType} lsb-release >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w lsof; then
        echoContent green " ---> Install lsof"
        ${installType} lsof >/dev/null 2>&1
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w dig; then
        echoContent green " ---> Install dig"
        if echo "${installType}" | grep -q -w "apt"; then
            ${installType} dnsutils >/dev/null 2>&1
        elif echo "${installType}" | grep -q -w "yum"; then
            ${installType} bind-utils >/dev/null 2>&1
        fi
    fi

    if [[ "${selectCustomInstallType}" == "7" ]]; then
        echoContent green " ---> Detected services that do not depend on Nginx, skip installation"
    else
        if ! find /usr/bin /usr/sbin | grep -q -w nginx; then
            echoContent green " ---> Install nginx"
            installNginxTools
        else
            nginxVersion=$(nginx -v 2>&1)
            nginxVersion=$(echo "${nginxVersion}" | awk -F "[n][g][i][n][x][/]" '{print $2}' | awk -F "[.]" '{print $2}')
            if [[ ${nginxVersion} -lt 14 ]]; then
                read -r -p "Read that the current Nginx version does not support gRPC, which will cause the installation to fail. Do you want to uninstall Nginx and reinstall it? [y/n]:" unInstallNginxStatus
                if [[ "${unInstallNginxStatus}" == "y" ]]; then
                    ${removeType} nginx >/dev/null 2>&1
                    echoContent yellow " ---> nginx uninstall completed"
                    echoContent green " ---> Install nginx"
                    installNginxTools >/dev/null 2>&1
                else
                    exit 0
                fi
            fi
        fi
    fi

    if ! find /usr/bin /usr/sbin | grep -q -w semanage; then
        echoContent green " ---> Install semanage"
        ${installType} bash-completion >/dev/null 2>&1

        if [[ "${centosVersion}" == "7" ]]; then
            policyCoreUtils="policycoreutils-python.x86_64"
        elif [[ "${centosVersion}" == "8" ]]; then
            policyCoreUtils="policycoreutils-python-utils-2.9-9.el8.noarch"
        fi

        if [[ -n "${policyCoreUtils}" ]]; then
            ${installType} ${policyCoreUtils} >/dev/null 2>&1
        fi
        if [[ -n $(which semanage) ]]; then
            semanage port -a -t http_port_t -p tcp 31300

        fi
    fi
    
    if [[ "${selectCustomInstallType}" == "7" ]]; then
        echoContent green " ---> Detected services that do not depend on certificates, skip installation"
    else
        if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh ") ]]; then
            echoContent green " ---> Install acme.sh"
            curl -s https://get.acme.sh | sh >/etc/v2ray-agent/tls/acme.log 2>&1

            if [[ ! -d "$HOME/.acme.sh" ]] || [[ -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
                echoContent red "acme installation failed--->"
                tail -n 100 /etc/v2ray-agent/tls/acme.log
                echoContent yellow "Error troubleshooting:"
                echoContent red " 1. Failed to obtain Github files. Please wait for Github to recover and try again. The recovery progress can be viewed [https://www.githubstatus.com/]"
                echoContent red "2. There is a bug in the acme.sh script, please check [https://github.com/acmesh-official/acme.sh] issues"
                echoContent red " 3. For pure IPv6 machines, please set up NAT64. You can execute the following command. If it still does not work after adding the following command, please try to change to another NAT64"
				
                echoContent skyBlue " sed -i \"1i\\\nameserver 2001:67c:2b0::4\\\nnameserver 2a00:1098:2c::1\" /etc/resolv.conf"
                exit 0
            fi
        fi
    fi

}


installNginxTools() {

    if [[ "${release}" == "debian" ]]; then
        sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
        echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
        curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
        sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "ubuntu" ]]; then
        sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
        echo "deb http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
        curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
        sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "centos" ]]; then
        ${installType} yum-utils >/dev/null 2>&1
        cat <<EOF >/etc/yum.repos.d/nginx.repo
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true

[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=0
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
        sudo yum-config-manager --enable nginx-mainline >/dev/null 2>&1
    fi
    ${installType} nginx >/dev/null 2>&1
    systemctl daemon-reload
    systemctl enable nginx
}

# 安装warp
installWarp() {
    if [[ "${cpuVendor}" == "arm" ]]; then
        echoContent red " ---> 官方WARP客户端不支持ARM架构"
        exit 0
    fi

    ${installType} gnupg2 -y >/dev/null 2>&1
    if [[ "${release}" == "debian" ]]; then
        curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
        echo "deb http://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "ubuntu" ]]; then
        curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
        echo "deb http://pkg.cloudflareclient.com/ focal main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "centos" ]]; then
        ${installType} yum-utils >/dev/null 2>&1
        sudo rpm -ivh "http://pkg.cloudflareclient.com/cloudflare-release-el${centosVersion}.rpm" >/dev/null 2>&1
    fi

    echoContent green " ---> Install WARP"
    ${installType} cloudflare-warp >/dev/null 2>&1
    if [[ -z $(which warp-cli) ]]; then
        echoContent red " ---> Failed to install WARP"
        exit 0
    fi
    systemctl enable warp-svc
    warp-cli --accept-tos register
    warp-cli --accept-tos set-mode proxy
    warp-cli --accept-tos set-proxy-port 31303
    warp-cli --accept-tos connect
    warp-cli --accept-tos enable-always-on

    local warpStatus=
    warpStatus=$(curl -s --socks5 127.0.0.1:31303 https://www.cloudflare.com/cdn-cgi/trace | grep "warp" | cut -d "=" -f 2)

    if [[ "${warpStatus}" == "on" ]]; then
        echoContent green " ---> WARP started successfully"
    fi
}

# 通过dns检查域名的IP
checkDNSIP() {
    local domain=$1
    local dnsIP=
    local type=4
    dnsIP=$(dig @1.1.1.1 +time=2 +short "${domain}" | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    if [[ -z "${dnsIP}" ]]; then
        dnsIP=$(dig @8.8.8.8 +time=2 +short "${domain}" | grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    fi
    if echo "${dnsIP}" | grep -q "timed out" || [[ -z "${dnsIP}" ]]; then
        echo
        echoContent red " ---> Unable to obtain domain name IPv4 address through DNS"
        echoContent green " ---> Try to check domain name IPv6 address"
        dnsIP=$(dig @2606:4700:4700::1111 +time=2 aaaa +short "${domain}")
        type=6
        if echo "${dnsIP}" | grep -q "network unreachable" || [[ -z "${dnsIP}" ]]; then
            echoContent red " ---> Unable to obtain domain name IPv6 address through DNS, exit installation"
            exit 0
        fi
    fi
    local publicIP=

    publicIP=$(getPublicIP "${type}")
    if [[ "${publicIP}" != "${dnsIP}" ]]; then
        echoContent red " ---> The domain name resolution IP is inconsistent with the current server IP\n"
        echoContent yellow " ---> Please check whether the domain name resolution is valid and correct"
        echoContent green " ---> Current VPS IP: ${publicIP}"
        echoContent green " ---> DNS resolution IP: ${dnsIP}"
        exit 0
    else
        echoContent green " ---> Domain name IP verification passed"
    fi
}

checkPortOpen() {

    local port=$1
    local domain=$2
    local checkPortOpenResult=

    allowPort "${port}"

    # 初始化nginx配置
    touch ${nginxConfigPath}checkPortOpen.conf
    cat <<EOF >${nginxConfigPath}checkPortOpen.conf
    server {
        listen ${port};
        listen [::]:${port};
        server_name ${domain};
        location /checkPort {
            return 200 'fjkvymb6len';
        }
        location /ip {
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header REMOTE-HOST \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            default_type text/plain;
            return 200 \$proxy_add_x_forwarded_for;
        }
    }
EOF
    handleNginx start
    checkPortOpenResult=$(curl -s -m 10 "http://${domain}:${port}/checkPort")
    localIP=$(curl -s -m 10 "http://${domain}:${port}/ip")
    rm "${nginxConfigPath}checkPortOpen.conf"
    handleNginx stop
    if [[ "${checkPortOpenResult}" == "fjkvymb6len" ]]; then
        echoContent green " ---> Detected that ${port} port is open"
    else
        echoContent green " ---> No open ${port} port detected, exit installation"
        if echo "${checkPortOpenResult}" | grep -q "cloudflare"; then
            echoContent yellow " ---> Please close the cloud and wait three minutes to try again"
        else
            if [[ -z "${checkPortOpenResult}" ]]; then
                echoContent red " ---> Please check if there is a web firewall, such as Oracle and other cloud service providers"
                echoContent red " ---> Check whether you have installed nginx and there are configuration conflicts. You can try DD pure system and try again"
            else
                echoContent red " ---> Error log: ${checkPortOpenResult}, please submit feedback on this error log through issues"
            fi
        fi
        exit 0
    fi
    checkIP "${localIP}"
}


initTLSNginxConfig() {
    handleNginx stop
    echoContent skyBlue "\nProgress $1/${totalProgress}: Initializing Nginx application certificate configuration"
    if [[ -n "${currentHost}" ]]; then
        echo
        read -r -p "Read the last installation record. Do you want to use the domain name from the last installation? [y/n]:" historyDomainStatus
        if [[ "${historyDomainStatus}" == "y" ]]; then
            domain=${currentHost}
            echoContent yellow "\n ---> Domain name: ${domain}"
        else
            echo
            echoContent yellow "Please enter the domain name to be configured. Example: www.v2ray-agent.com --->"
            read -r -p "domain name:" domain
        fi
    else
        echo
        echoContent yellow "Please enter the domain name to be configured. Example: www.v2ray-agent.com --->"
        read -r -p "domain name:" domain
    fi

    if [[ -z ${domain} ]]; then
        echoContent red "Domain name cannot be empty--->"
        initTLSNginxConfig 3
    else
        dnsTLSDomain=$(echo "${domain}" | awk -F "." '{$1="";print $0}' | sed 's/^[[:space:]]*//' | sed 's / /./g')
        customPortFunction
        handleNginx stop
    fi
}


removeNginxDefaultConf() {
    if [[ -f ${nginxConfigPath}default.conf ]]; then
        if [[ "$(grep -c "server_name" <${nginxConfigPath}default.conf)" == "1" ]] && [[ "$(grep -c "server_name localhost;" <${nginxConfigPath}default. conf)" == "1" ]]; then
            echoContent green " ---> Delete Nginx default configuration"
            rm -rf ${nginxConfigPath}default.conf
        fi
    fi
}

updateRedirectNginxConf() {
    local redirectDomain=
    redirectDomain=${domain}:${port}

    local nginxH2Conf=
    nginxH2Conf="listen 127.0.0.1:31302 http2 so_keepalive=on;"
    nginxVersion=$(nginx -v 2>&1)

    if echo "${nginxVersion}" | grep -q "1.25"; then
        nginxH2Conf="listen 127.0.0.1:31302 so_keepalive=on;http2 on;"
    fi

    cat <<EOF >${nginxConfigPath}alone.conf
    server {
    		listen 127.0.0.1:31300;
    		server_name _;
    		return 403;
    }
EOF

    if echo "${selectCustomInstallType}" | grep -q 2 && echo "${selectCustomInstallType}" | grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then

        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}
	server_name ${domain};
	root ${nginxStaticPath};

	client_header_timeout 1071906480m;
    keepalive_timeout 1071906480m;

	location ~ ^/s/(clashMeta|default|clashMetaProfiles)/(.*) {
        default_type 'text/plain; charset=utf-8';
        alias /etc/v2ray-agent/subscribe/\$1/\$2;
    }

    location /${currentPath}grpc {
    	if (\$content_type !~ "application/grpc") {
    		return 404;
    	}
 		client_max_body_size 0;
		grpc_set_header X-Real-IP \$proxy_add_x_forwarded_for;
		client_body_timeout 1071906480m;
		grpc_read_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}

	location /${currentPath}trojangrpc {
		if (\$content_type !~ "application/grpc") {
            		return 404;
		}
 		client_max_body_size 0;
		grpc_set_header X-Real-IP \$proxy_add_x_forwarded_for;
		client_body_timeout 1071906480m;
		grpc_read_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}
	location / {
    }
}
EOF
    elif echo "${selectCustomInstallType}" | grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then
        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}
	server_name ${domain};
	root ${nginxStaticPath};
	location ~ ^/s/(clashMeta|default|clashMetaProfiles)/(.*) {
        default_type 'text/plain; charset=utf-8';
        alias /etc/v2ray-agent/subscribe/\$1/\$2;
    }
	location /${currentPath}grpc {
		client_max_body_size 0;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
}
EOF

    elif echo "${selectCustomInstallType}" | grep -q 2 || [[ -z "${selectCustomInstallType}" ]]; then
        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}
	server_name ${domain};
	root ${nginxStaticPath};
	location ~ ^/s/(clashMeta|default|clashMetaProfiles)/(.*) {
        default_type 'text/plain; charset=utf-8';
        alias /etc/v2ray-agent/subscribe/\$1/\$2;
    }
	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
}
EOF
    else

        cat <<EOF >>${nginxConfigPath}alone.conf
server {
	${nginxH2Conf}
	server_name ${domain};
	root ${nginxStaticPath};

    location ~ ^/s/(clashMeta|default|clashMetaProfiles)/(.*) {
            default_type 'text/plain; charset=utf-8';
            alias /etc/v2ray-agent/subscribe/\$1/\$2;
        }
	location / {
	}
}
EOF
    fi

    cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31300;
	server_name ${domain};
	root ${nginxStaticPath};
	location ~ ^/s/(clashMeta|default|clashMetaProfiles)/(.*) {
            default_type 'text/plain; charset=utf-8';
            alias /etc/v2ray-agent/subscribe/\$1/\$2;
        }
	location / {
	}
}
EOF
    handleNginx stop
}


checkIP() {
    echoContent skyBlue "\n ---> Check the domain name ip"
    local localIP=$1

    if [[ -z ${localIP} ]] || ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q '\.' && ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q ':'; then
        echoContent red "\n ---> The ip of the current domain name was not detected"
        echoContent skyBlue " ---> Please perform the following checks in order"
        echoContent yellow " ---> 1. Check whether the domain name is written correctly"
        echoContent yellow " ---> 2. Check whether the domain name dns resolution is correct"
        echoContent yellow " ---> 3. If the parsing is correct, please wait for the dns to take effect, which is expected to take effect within three minutes"
        echoContent yellow " ---> 4. If you report Nginx startup problems, please start nginx manually to check the errors. If you cannot handle it yourself, please submit issues"
        echo
        echoContent skyBlue " ---> If the above settings are correct, please reinstall a pure system and try again"

        if [[ -n ${localIP} ]]; then
            echoContent yellow " ---> Detection of abnormal return value, it is recommended to manually uninstall nginx and re-execute the script"
            echoContent red " ---> Exception result: ${localIP}"
        fi
        exit 0
    else
        if echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q "." || echo "${localIP}" | awk -F "[,]" '{ print $2}' | grep -q ":"; then
            echoContent red "\n ---> Multiple IPs were detected, please confirm whether to turn off cloudflare"
            echoContent yellow " ---> Wait three minutes after closing the cloud and try again"
            echoContent yellow " ---> The detected IP is as follows: [${localIP}]"
            exit 0
        fi
        echoContent green " ---> Check that the current domain name IP is correct"
    fi
}


customSSLEmail() {
    if echo "$1" | grep -q "validate email"; then
        read -r -p "Whether to re-enter the email address [y/n]:" sslEmailStatus
        if [[ "${sslEmailStatus}" == "y" ]]; then
            sed '/ACCOUNT_EMAIL/d' /root/.acme.sh/account.conf >/root/.acme.sh/account.conf_tmp && mv /root/.acme.sh/account.conf_tmp /root/.acme.sh /account.conf
        else
            exit 0
        fi
    fi

    if [[ -d "/root/.acme.sh" && -f "/root/.acme.sh/account.conf" ]]; then
        if ! grep -q "ACCOUNT_EMAIL" <"/root/.acme.sh/account.conf" && ! echo "${sslType}" | grep -q "letsencrypt"; then
            read -r -p "Please enter your email address:" sslEmail
            if echo "${sslEmail}" | grep -q "@"; then
                echo "ACCOUNT_EMAIL='${sslEmail}'" >>/root/.acme.sh/account.conf
                echoContent green " ---> Added successfully"
            else
                echoContent yellow "Please re-enter the correct email format [Example: username@example.com]"
                customSSLEmail
            fi
        fi
    fi

}


switchDNSAPI() {
    read -r -p "Do you want to use DNS API to apply for a certificate [support NAT]? [y/n]:" dnsAPIStatus
    if [[ "${dnsAPIStatus}" == "y" ]]; then
        echoContent red "\n================================================ ================="
        echoContent yellow "1.cloudflare[default]"
        echoContent red "================================================== ==============="
        read -r -p "Please select [Enter] to use the default:" selectDNSAPIType
        case ${selectDNSAPIType} in
        1)
            dnsAPIType="cloudflare"
            ;;
        *)
            dnsAPIType="cloudflare"
            ;;
        esac
        initDNSAPIConfig "${dnsAPIType}"
    fi
}


initDNSAPIConfig() {
    if [[ "$1" == "cloudflare" ]]; then
        echoContent yellow "\n CF_Token reference configuration tutorial: https://www.v2ray-agent.com/archives/1701160377972\n"
        read -r -p "Please enter API Token:" cfAPIToken
        if [[ -z "${cfAPIToken}" ]]; then
            echoContent red " ---> The input is empty, please re-enter"
            initDNSAPIConfig "$1"
        else
            echo
            read -r -p "Do you want to use *.${dnsTLSDomain} to apply for a wildcard certificate through API? [y/n]:" dnsAPIStatus
            if [[ "${dnsAPIStatus}" != "y" ]]; then
                exit 0
            fi
        fi
    fi
}


switchSSLType() {
    if [[ -z "${sslType}" ]]; then
        echoContent red "\n================================================ ================="
        echoContent yellow "1.letsencrypt[default]"
        echoContent yellow "2.zerossl"
        echoContent yellow "3.buypass[Does not support DNS application]"
        echoContent red "================================================== ==============="
        read -r -p "Please select [Enter] to use the default:" selectSSLType
        case ${selectSSLType} in
        1)
            sslType="letsencrypt"
            ;;
        2)
            sslType="zerossl"
            ;;
        3)
            sslType="buypass"
            ;;
        *)
            sslType="letsencrypt"
            ;;
        esac
        if [[ -n "${dnsAPIType}" && "${sslType}" == "buypass" ]]; then
            echoContent red " ---> buypass does not support API application for certificates"
            exit 0
        fi
        echo "${sslType}" >/etc/v2ray-agent/tls/ssl_type
    fi
}


selectAcmeInstallSSL() {
    local installSSLIPv6=

    if echo "${localIP}" | grep -q ":"; then
        installSSLIPv6="--listen-v6"
    fi

    acmeInstallSSL

    readAcmeTLS
}


acmeInstallSSL() {
    if [[ -n "${dnsAPIType}" ]]; then
        echoContent green " ---> Generating wildcard certificate"
        sudo CF_Token="${cfAPIToken}" "$HOME/.acme.sh/acme.sh" --issue -d "*.${dnsTLSDomain}" --dns dns_cf -k ec-256 --server "${ sslType}" ${installSSLIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
    else
        echoContent green " ---> Generating certificate"
        sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server "${sslType}" ${installSSLIPv6} 2>&1 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
    fi
}


customPortFunction() {
    local historyCustomPortStatus=
    if [[ -n "${customPort}" || -n "${currentPort}" ]]; then
        echo
        read -r -p "Read the port from the last installation. Do you want to use the port from the last installation? [y/n]:" historyCustomPortStatus
        if [[ "${historyCustomPortStatus}" == "y" ]]; then
            port=${currentPort}
            echoContent yellow "\n ---> Port: ${port}"
        fi
    fi
    if [[ -z "${currentPort}" ]] || [[ "${historyCustomPortStatus}" == "n" ]]; then
        echo

        if [[ -n "${btDomain}" ]]; then
            echoContent yellow "Please enter the port [cannot be the same as the BT Panel port, press Enter to be random]"
            read -r -p "port:" port
            if [[ -z "${port}" ]]; then
                port=$((RANDOM % 20001 + 10000))
            fi
        else
            echo
            echoContent yellow "Please enter the port [default: 443], you can customize the port [press Enter to use the default]"
            read -r -p "port:" port
            if [[ -z "${port}" ]]; then
                port=443
            fi
            if [[ "${port}" == "${currentRealityPort}" ]]; then
                handleXray stop
            fi

            # todo dns api
        fi

        if [[ -n "${port}" ]]; then
            if ((port >= 1 && port <= 65535)); then
                allowPort "${port}"
                echoContent yellow "\n ---> Port: ${port}"
                if [[ -z "${btDomain}" ]]; then
                    checkDNSIP "${domain}"
                    removeNginxDefaultConf
                    checkPortOpen "${port}" "${domain}"
                fi
            else
                echoContent red " ---> Port input error"
                exit 0
            fi
        else
            echoContent red " ---> Port cannot be empty"
            exit 0
        fi
    fi
}


checkPort() {
    if [[ -n "$1" ]] && lsof -i "tcp:$1" | grep -q LISTEN; then
        echoContent red "\n ---> $1 port is occupied, please close it manually and install\n"
        lsof -i "tcp:$1" | grep LISTEN
        exit 0
    fi
}

installTLS() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Apply for TLS certificate\n"
    readAcmeTLS
    local tlsDomain=${domain}

    if [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/ etc/v2ray-agent/tls/${tlsDomain}.crt") ]] || [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh /${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]] || [[ "${installedDNSAPIStatus} " == "true" ]]; then
        echoContent green " ---> Certificate detected"
        renewalTLS

        if [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.crt") ]] || [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.key") ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
            if [[ "${installedDNSAPIStatus}" == "true" ]]; then
                sudo "$HOME/.acme.sh/acme.sh" --installcert -d "*.${dnsTLSDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
            else
                sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/ etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
            fi

        else
            echoContent yellow " ---> If the certificate has not expired or is customized, please select [n]\n"
            read -r -p "Reinstall? [y/n]:" reInstallStatus
            if [[ "${reInstallStatus}" == "y" ]]; then
                rm -rf /etc/v2ray-agent/tls/*
                installTLS "$1"
            fi
        fi

    elif [[ -d "$HOME/.acme.sh" ]] && [[ ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" || ! -f " $HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" ]]; then
        switchDNSAPI
        if [[ -z "${dnsAPIType}" ]]; then
            echoContent yellow "\n ---> Do not use API to apply for certificate"
            echoContent green " ---> Install TLS certificate, need to rely on port 80"
            allowPort 80
        fi

        switchSSLType
        customSSLEmail
        selectAcmeInstallSSL

        if [[ "${installedDNSAPIStatus}" == "true" ]]; then
            sudo "$HOME/.acme.sh/acme.sh" --installcert -d "*.${dnsTLSDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
        else
            sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
        fi

        if [[ ! -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" || ! -f "/etc/v2ray-agent/tls/${tlsDomain}.key" ]] || [ [ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.key") || -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ] ]; then
            tail -n 10 /etc/v2ray-agent/tls/acme.log
            if [[ ${installTLSCount} == "1" ]]; then
                echoContent red " ---> TLS installation failed, please check the acme log"
                exit 0
            fi

            installTLSCount=1
            echo

            if tail -n 10 /etc/v2ray-agent/tls/acme.log | grep -q "Could not validate email address as valid"; then
                echoContent red " ---> The email cannot pass SSL vendor verification, please re-enter"
                echo
                customSSLEmail "validate email"
                installTLS "$1"
            else
                installTLS "$1"
            fi
        fi

        echoContent green " ---> TLS generated successfully"
    else
        echoContent yellow " ---> acme.sh is not installed"
        exit 0
    fi
}


initRandomPath() {
    local chars="abcdefghijklmnopqrtuxyz"
    local initCustomPath=
    for i in {1..4}; do
        echo "${i}" >/dev/null
        initCustomPath+="${chars:RANDOM%${#chars}:1}"
    done
    customPath=${initCustomPath}
}


randomPathFunction() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Generate random path"

    if [[ -n "${currentPath}" ]]; then
        echo
        read -r -p "Read the last installation record. Do you want to use the path from the last installation? [y/n]:" historyPathStatus
        echo
    fi

    if [[ "${historyPathStatus}" == "y" ]]; then
        customPath=${currentPath}
        echoContent green " ---> Used successfully\n"
    else
        echoContent yellow "Please enter a custom path [eg: alone], no slash required, [Enter] random path"
        read -r -p 'path:' customPath
        if [[ -z "${customPath}" ]]; then
            initRandomPath
            currentPath=${customPath}
        else
            if [[ "${customPath: -2}" == "ws" ]]; then
                echo
                echoContent red " ---> The custom path cannot end with ws, otherwise the splitting path cannot be distinguished"
                randomPathFunction "$1"
            else
                currentPath=${customPath}
            fi
        fi
    fi
    echoContent yellow "\n path:${currentPath}"
    echoContent skyBlue "\n----------------------------"
}


nginxBlog() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Add fake site"
    if [[ -d "${nginxStaticPath}" && -f "${nginxStaticPath}/check" ]]; then
        echo
        read -r -p "Detected installation of fake site, do you need to reinstall [y/n]:" nginxBlogInstallStatus
        if [[ "${nginxBlogInstallStatus}" == "y" ]]; then
            rm -rf "${nginxStaticPath}"
            randomNum=$((RANDOM % 6 + 1))
            wget -q -P "${nginxStaticPath}" https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
            unzip -o "${nginxStaticPath}html${randomNum}.zip" -d "${nginxStaticPath}" >/dev/null
            rm -f "${nginxStaticPath}html${randomNum}.zip*"
            echoContent green " ---> Added fake site successfully"
        fi
    else
        randomNum=$((RANDOM % 6 + 1))
        rm -rf "${nginxStaticPath}"
        wget -q -P "${nginxStaticPath}" https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
        unzip -o "${nginxStaticPath}html${randomNum}.zip" -d "${nginxStaticPath}" >/dev/null
        rm -f "${nginxStaticPath}html${randomNum}.zip*"
        echoContent green " ---> Added fake site successfully"
    fi

}


updateSELinuxHTTPPortT() {

    $(find /usr/bin /usr/sbin | grep -w journalctl) -xe >/etc/v2ray-agent/nginx_error.log 2>&1

    if find /usr/bin /usr/sbin | grep -q -w semanage && find /usr/bin /usr/sbin | grep -q -w getenforce && grep -E "31300|31302" </etc/v2ray-agent /nginx_error.log | grep -q "Permission denied"; then
        echoContent red " ---> Check if the SELinux port is open"
        if ! $(find /usr/bin /usr/sbin | grep -w semanage) port -l | grep http_port | grep -q 31300; then
            $(find /usr/bin /usr/sbin | grep -w semanage) port -a -t http_port_t -p tcp 31300
            echoContent green " ---> http_port_t 31300 port opened successfully"
        fi

        if ! $(find /usr/bin /usr/sbin | grep -w semanage) port -l | grep http_port | grep -q 31302; then
            $(find /usr/bin /usr/sbin | grep -w semanage) port -a -t http_port_t -p tcp 31302
            echoContent green " ---> http_port_t 31302 port opened successfully"
        fi
        handleNginx start

    else
        exit 0
    fi
}


handleNginx() {

    if [[ -z $(pgrep -f "nginx") ]] && [[ "$1" == "start" ]]; then
        systemctl start nginx 2>/etc/v2ray-agent/nginx_error.log

        sleep 0.5

        if [[ -z $(pgrep -f "nginx") ]]; then
            echoContent red " ---> Nginx failed to start"
            echoContent red " ---> Please try to install nginx manually and execute the script again"

            if grep -q "journalctl -xe" </etc/v2ray-agent/nginx_error.log; then
                updateSELinuxHTTPPortT
            fi
        else
            echoContent green " ---> Nginx started successfully"
        fi

    elif [[ -n $(pgrep -f "nginx") ]] && [[ "$1" == "stop" ]]; then
        systemctl stop nginx
        sleep 0.5
        if [[ -n $(pgrep -f "nginx") ]]; then
            pgrep -f "nginx" | xargs kill -9
        fi
        echoContent green " ---> Nginx closed successfully"
    fi
}


installCronTLS() {
    if [[ -z "${btDomain}" ]]; then
        echoContent skyBlue "\nProgress $1/${totalProgress}: Add scheduled maintenance certificate"
        crontab -l >/etc/v2ray-agent/backup_crontab.cron
        local historyCrontab
        historyCrontab=$(sed '/v2ray-agent/d;/acme.sh/d' /etc/v2ray-agent/backup_crontab.cron)
        echo "${historyCrontab}" >/etc/v2ray-agent/backup_crontab.cron
        echo "30 1 * * * /bin/bash /etc/v2ray-agent/install.sh RenewTLS >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
        crontab /etc/v2ray-agent/backup_crontab.cron
        echoContent green "\n ---> Add scheduled maintenance certificate successfully"
    fi
}


installCronUpdateGeo() {
    if [[ -n "${configPath}" ]]; then
        if crontab -l | grep -q "UpdateGeo"; then
            echoContent red "\n ---> The automatic update scheduled task has been added, please do not add it repeatedly"
            exit 0
        fi
        echoContent skyBlue "\nProgress 1/1: Add scheduled update geo file"
        crontab -l >/etc/v2ray-agent/backup_crontab.cron
        echo "35 1 * * * /bin/bash /etc/v2ray-agent/install.sh UpdateGeo >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
        crontab /etc/v2ray-agent/backup_crontab.cron
        echoContent green "\n ---> Adding scheduled update geo file successfully"
    fi
}


renewalTLS() {

    if [[ -n $1 ]]; then
        echoContent skyBlue "\nProgress $1/1: Update certificate"
    fi
    readAcmeTLS
    local domain=${currentHost}
    if [[ -z "${currentHost}" && -n "${tlsDomain}" ]]; then
        domain=${tlsDomain}
    fi

    if [[ -f "/etc/v2ray-agent/tls/ssl_type" ]]; then
        if grep -q "buypass" <"/etc/v2ray-agent/tls/ssl_type"; then
            sslRenewalDays=180
        fi
    fi
    if [[ -d "$HOME/.acme.sh/${domain}_ecc" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$ HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]] || [[ "${installedDNSAPIStatus}" == "true" ]]; then
        modifyTime=

        if [[ "${installedDNSAPIStatus}" == "true" ]]; then
            modifyTime=$(stat --format=%z "$HOME/.acme.sh/*.${dnsTLSDomain}_ecc/*.${dnsTLSDomain}.cer")
        else
            modifyTime=$(stat --format=%z "$HOME/.acme.sh/${domain}_ecc/${domain}.cer")
        fi

        modifyTime=$(date +%s -d "${modifyTime}")
        currentTime=$(date +%s)
        ((stampDiff = currentTime - modifyTime))
        ((days = stampDiff / 86400))
        ((remainingDays = sslRenewalDays - days))

        tlsStatus=${remainingDays}
        if [[ ${remainingDays} -le 0 ]]; then
            tlsStatus="Expired"
        fi

        echoContent skyBlue " ---> Certificate check date:$(date "+%F %H:%M:%S")"
        echoContent skyBlue " ---> Certificate generation date: $(date -d @"${modifyTime}" +"%F %H:%M:%S")"
        echoContent skyBlue " ---> Certificate generation days: ${days}"
        echoContent skyBlue " ---> Number of days remaining on the certificate: "${tlsStatus}
        echoContent skyBlue " ---> The certificate will be automatically updated on the last day before it expires. If the update fails, please update manually"

        if [[ ${remainingDays} -le 1 ]]; then
            echoContent yellow " ---> Regenerate certificate"
            handleNginx stop

            if [[ "${coreInstallType}" == "1" ]]; then
                handleXray stop
            elif [[ "${coreInstallType}" == "2" ]]; then
                handleV2Ray stop
            fi

            sudo "$HOME/.acme.sh/acme.sh" --cron --home "$HOME/.acme.sh"
            sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${domain}" --fullchainpath /etc/v2ray-agent/tls/"${domain}.crt" --keypath /etc /v2ray-agent/tls/"${domain}.key" --ecc
            reloadCore
            handleNginx start
        else
            echoContent green " ---> The certificate is valid"
        fi
    else
        echoContent red " ---> not installed"
    fi
}


checkTLStatus() {

    if [[ -d "$HOME/.acme.sh/${currentHost}_ecc" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.key" ] ] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" ]]; then
        modifyTime=$(stat "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" " $5}')

        modifyTime=$(date +%s -d "${modifyTime}")
        currentTime=$(date +%s)
        ((stampDiff = currentTime - modifyTime))
        ((days = stampDiff / 86400))
        ((remainingDays = sslRenewalDays - days))

        tlsStatus=${remainingDays}
        if [[ ${remainingDays} -le 0 ]]; then
            tlsStatus="Expired"
        fi

        echoContent skyBlue " ---> Certificate generation date: $(date -d "@${modifyTime}" +"%F %H:%M:%S")"
        echoContent skyBlue " ---> Certificate generation days: ${days}"
        echoContent skyBlue " ---> Number of days remaining on the certificate:${tlsStatus}"
    fi
}


installV2Ray() {
    readInstallType
    echoContent skyBlue "\n进度  $1/${totalProgress} : 安装V2Ray"

    if [[ "${coreInstallType}" != "2" && "${coreInstallType}" != "3" ]]; then
        if [[ "${selectCoreType}" == "2" ]]; then

            version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases?per_page=10 | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -1)
        else
            version=${v2rayCoreVersion}
        fi

        echoContent green " ---> v2ray-core版本:${version}"
        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
        unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
        rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
    else
        if [[ "${selectCoreType}" == "3" ]]; then
            echoContent green " ---> Lock v2ray-core version to v4.32.1"
            rm -f /etc/v2ray-agent/v2ray/v2ray
            rm -f /etc/v2ray-agent/v2ray/v2ctl
            installV2Ray "$1"
        else
            echoContent green " ---> v2ray-core version:$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
            read -r -p "Update or upgrade? [y/n]:" reInstallV2RayStatus
            if [[ "${reInstallV2RayStatus}" == "y" ]]; then
                rm -f /etc/v2ray-agent/v2ray/v2ray
                rm -f /etc/v2ray-agent/v2ray/v2ctl
                installV2Ray "$1"
            fi
        fi
    fi
}


installHysteria() {
    readInstallType
    echoContent skyBlue "\nProgress $1/${totalProgress}: Installing Hysteria"

    if [[ -z "${hysteriaConfigPath}" ]]; then

        version=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases?per_page=10" | jq -r ".[]|select (.prerelease==${prereleaseStatus}) |.tag_name" | grep "app/" | head -1)

        echoContent green " ---> Hysteria version:${version}"
        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/hysteria/ "https://github.com/apernet/hysteria/releases/download/${version}/${hysteriaCoreCPUVendor}"
        mv "/etc/v2ray-agent/hysteria/${hysteriaCoreCPUVendor}" /etc/v2ray-agent/hysteria/hysteria
        chmod 655 /etc/v2ray-agent/hysteria/hysteria
    else
        echoContent green " ---> Hysteria version:$(/etc/v2ray-agent/hysteria/hysteria version | grep "Version:" | awk '{print $2}')"
        read -r -p "Would you like to update or upgrade? [y/n]:" reInstallHysteriaStatus
        if [[ "${reInstallHysteriaStatus}" == "y" ]]; then
            rm -f /etc/v2ray-agent/hysteria/hysteria
            installHysteria "$1"
        fi
    fi

}


installSingBox() {
    readInstallType
    echoContent skyBlue "\nProgress $1/${totalProgress}: Install sing-box"

    if [[ -z "${singBoxConfigPath}" ]]; then

        version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=10" | jq -r ".[]|select (.prerelease==${prereleaseStatus })|.tag_name" | head -1)

        echoContent green " ---> sing-box version: ${version}"

        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/sing-box/ "https://github.com/SagerNet/sing-box/releases/download/${version}/sing- box-${version/v/}${singBoxCoreCPUVendor}.tar.gz"

        tar zxvf "/etc/v2ray-agent/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}.tar.gz" -C "/etc/v2ray-agent/sing-box/" > /dev/null 2>&1

        mv "/etc/v2ray-agent/sing-box/sing-box-${version/v/}${singBoxCoreCPUVendor}/sing-box" /etc/v2ray-agent/sing-box/sing-box
        rm -rf /etc/v2ray-agent/sing-box/sing-box-*
        chmod 655 /etc/v2ray-agent/sing-box/sing-box

    else
        echoContent green " ---> sing-box version: v$(/etc/v2ray-agent/sing-box/sing-box version | grep "sing-box version" | awk '{print $3}')"
        read -r -p "Would you like to update or upgrade? [y/n]:" reInstallSingBoxStatus
        if [[ "${reInstallSingBoxStatus}" == "y" ]]; then
            rm -f /etc/v2ray-agent/sing-box/sing-box
            installSingBox "$1"
        fi
    fi

}


installTuic() {
    readInstallType
    echoContent skyBlue "\nProgress $1/${totalProgress}: Install Tuic"

    if [[ -z "${tuicConfigPath}" ]]; then

        version=$(curl -s "https://api.github.com/repos/EAimTY/tuic/releases?per_page=1" | jq -r '.[]|select (.prerelease==false)|.tag_name ')

        echoContent green " ---> Tuic version:${version}"
        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/tuic/ "https://github.com/EAimTY/tuic/releases/download/${version}/${version}${ tuicCoreCPUVendor}"
        mv "/etc/v2ray-agent/tuic/${version}${tuicCoreCPUVendor}" /etc/v2ray-agent/tuic/tuic
        chmod 655 /etc/v2ray-agent/tuic/tuic
    else
        echoContent green " ---> Tuic version:$(/etc/v2ray-agent/tuic/tuic -v)"
        read -r -p "Would you like to update or upgrade? [y/n]:" reInstallTuicStatus
        if [[ "${reInstallTuicStatus}" == "y" ]]; then
            rm -f /etc/v2ray-agent/tuic/tuic
            tuicConfigPath=
            installTuic "$1"
        fi
    fi

}


checkWgetShowProgress() {
    if find /usr/bin /usr/sbin | grep -q -w wget && wget --help | grep -q show-progress; then
        wgetShowProgressStatus="--show-progress"
    fi
}


installXray() {
    readInstallType
    local prereleaseStatus=false
    if [[ "$2" == "true" ]]; then
        prereleaseStatus=true
    fi

    echoContent skyBlue "\nProgress $1/${totalProgress}: Install Xray"

    if [[ "${coreInstallType}" != "1" ]]; then

        version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=1" | jq -r ".[].tag_name")

        echoContent green " ---> Xray-core version:${version}"

        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor} .zip"
        if [[ ! -f "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" ]]; then
            echoContent red " ---> Core download failed, please try installation again"
            exit 0
        fi

        unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
        rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"

        version=$(curl -s https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases?per_page=1 | jq -r '.[]|.tag_name')
        echoContent skyBlue "------------------------Version---------------------- ---------"
        echo "version:${version}"
        rm /etc/v2ray-agent/xray/geo* >/dev/null 2>&1

        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/xray/ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geosite. dat"
        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/xray/ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geoip. dat"

        chmod 655 /etc/v2ray-agent/xray/xray
    else
        echoContent green " ---> Xray-core version:$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
        read -r -p "Would you like to update or upgrade? [y/n]:" reInstallXrayStatus
        if [[ "${reInstallXrayStatus}" == "y" ]]; then
            rm -f /etc/v2ray-agent/xray/xray
            installXray "$1" "$2"
        fi
    fi
}

v2rayVersionManageMenu() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: V2Ray version management"
    if [[ ! -d "/etc/v2ray-agent/v2ray/" ]]; then
        echoContent red " ---> The installation directory is not detected, please execute the script to install the content"
        menu
        exit 0
    fi
    echoContent red "\n================================================ ================="
    echoContent yellow "1.Upgrade v2ray-core"
    echoContent yellow "2. Fallback v2ray-core"
    echoContent yellow "3. Close v2ray-core"
    echoContent yellow "4.Open v2ray-core"
    echoContent yellow "5. Restart v2ray-core"
    echoContent yellow "6. Update geosite, geoip"
    echoContent yellow "7. Set up automatic update of geo files [updated every morning]"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" selectV2RayType
    if [[ "${selectV2RayType}" == "1" ]]; then
        updateV2Ray
    elif [[ "${selectV2RayType}" == "2" ]]; then
        echoContent yellow "\n1. Only the last five versions can be rolled back"
        echoContent yellow "2. There is no guarantee that it will be able to be used normally after the rollback"
        echoContent yellow "3. If the rolled-back version does not support the current config, it will be unable to connect, so operate with caution"
        echoContent skyBlue "------------------------Version-------------------------------"
        curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -5 | awk '{print ""NR""":"$0}'

        echoContent skyBlue "------------------------------------------------- ---------------"
        read -r -p "Please enter the version to be rolled back:" selectV2rayVersionType
        version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep - v 'v5' | head -5 | awk '{print ""NR""":"$0}' | grep "${selectV2rayVersionType}:" | awk -F "[:]" '{print $2}')
        if [[ -n "${version}" ]]; then
            updateV2Ray "${version}"
        else
            echoContent red "\n ---> Incorrect input, please re-enter"
            v2rayVersionManageMenu 1
        fi
    elif [[ "${selectV2RayType}" == "3" ]]; then
        handleV2Ray stop
    elif [[ "${selectV2RayType}" == "4" ]]; then
        handleV2Ray start
    elif [[ "${selectV2RayType}" == "5" ]]; then
        reloadCore
    elif [[ "${selectXrayType}" == "6" ]]; then
        updateGeoSite
    elif [[ "${selectXrayType}" == "7" ]]; then
        installCronUpdateGeo
    fi
}


xrayVersionManageMenu() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Xray version management"
    if [[ ! -d "/etc/v2ray-agent/xray/" ]]; then
        echoContent red " ---> The installation directory is not detected, please execute the script to install the content"
        menu
        exit 0
    fi
    echoContent red "\n================================================ ================="
    echoContent yellow "1.Upgrade Xray-core"
    echoContent yellow "2. Upgrade Xray-core preview version"
    echoContent yellow "3. Fallback Xray-core"
    echoContent yellow "4. Close Xray-core"
    echoContent yellow "5.Open Xray-core"
    echoContent yellow "6. Restart Xray-core"
    echoContent yellow "7. Update geosite, geoip"
    echoContent yellow "8. Set up automatic update of geo files [updated every morning]"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" selectXrayType
    if [[ "${selectXrayType}" == "1" ]]; then
        prereleaseStatus=false
        updateXray
    elif [[ "${selectXrayType}" == "2" ]]; then
        prereleaseStatus=true
        updateXray
    elif [[ "${selectXrayType}" == "3" ]]; then
        echoContent yellow "\n1. Only the last five versions can be rolled back"
        echoContent yellow "2. There is no guarantee that it will be able to be used normally after the rollback"
        echoContent yellow "3. If the rolled-back version does not support the current config, it will be unable to connect, so operate with caution"
        echoContent skyBlue "------------------------Version-------------------------------"
        curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5" | jq -r ".[]|select (.prerelease==false)|.tag_name" | awk '{print ""NR""":"$0}'
        echoContent skyBlue "--------------------------------------------------------------"
        read -r -p "Please enter the version you want to roll back:" selectXrayVersionType
        version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5" | jq -r ".[]|select (.prerelease==false)| .tag_name" | awk '{print ""NR""":"$0}' | grep "${selectXrayVersionType}:" | awk -F "[:]" '{print $2}')
        if [[ -n "${version}" ]]; then
            updateXray "${version}"
        else
            echoContent red "\n ---> Incorrect input, please re-enter"
            xrayVersionManageMenu 1
        fi
    elif [[ "${selectXrayType}" == "4" ]]; then
        handleXray stop
    elif [[ "${selectXrayType}" == "5" ]]; then
        handleXray start
    elif [[ "${selectXrayType}" == "6" ]]; then
        reloadCore
    elif [[ "${selectXrayType}" == "7" ]]; then
        updateGeoSite
    elif [[ "${selectXrayType}" == "8" ]]; then
        installCronUpdateGeo
    fi
}

updateGeoSite() {
    echoContent yellow "\nSource https://github.com/Loyalsoldier/v2ray-rules-dat"

    version=$(curl -s https://api.github.com/repos/Loyalsoldier/v2ray-rules-dat/releases?per_page=1 | jq -r '.[]|.tag_name')
    echoContent skyBlue "------------------------Version---------------------- ---------"
    echo "version:${version}"
    rm ${configPath}../geo* >/dev/null
    wget -c -q "${wgetShowProgressStatus}" -P ${configPath}../ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geosite.dat"
    wget -c -q "${wgetShowProgressStatus}" -P ${configPath}../ "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/${version}/geoip.dat"
    reloadCore
    echoContent green " ---> Update completed"

}

updateV2Ray() {
    readInstallType
    if [[ -z "${coreInstallType}" ]]; then

        if [[ -n "$1" ]]; then
            version=$1
        else
            version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -1)
        fi
        if [[ -n "${v2rayCoreVersion}" ]]; then
            version=${v2rayCoreVersion}
        fi
        echoContent green " ---> v2ray-core版本:${version}"
        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
        unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
        rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
        handleV2Ray stop
        handleV2Ray start
    else
        echoContent green " ---> Current v2ray-core version: $(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"

        if [[ -n "$1" ]]; then
            version=$1
        else
            version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | grep -v 'v5' | head -1)
        fi

        if [[ -n "${v2rayCoreVersion}" ]]; then
            version=${v2rayCoreVersion}
        fi
        if [[ -n "$1" ]]; then
            read -r -p "The rollback version is ${version}, do you want to continue? [y/n]:" rollbackV2RayStatus
            if [[ "${rollbackV2RayStatus}" == "y" ]]; then
                if [[ "${coreInstallType}" == "2" ]]; then
                    echoContent green " ---> Current v2ray-core version: $(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
                elif [[ "${coreInstallType}" == "1" ]]; then
                    echoContent green " ---> Current Xray-core version: $(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
                fi

                handleV2Ray stop
                rm -f /etc/v2ray-agent/v2ray/v2ray
                rm -f /etc/v2ray-agent/v2ray/v2ctl
                updateV2Ray "${version}"
            else
                echoContent green " ---> Abandon the rollback version"
            fi
        elif [[ "${version}" == "v$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)" ]]; then
            read -r -p "The current version is the same as the latest version. Do you want to reinstall? [y/n]:" reInstallV2RayStatus
            if [[ "${reInstallV2RayStatus}" == "y" ]]; then
                handleV2Ray stop
                rm -f /etc/v2ray-agent/v2ray/v2ray
                rm -f /etc/v2ray-agent/v2ray/v2ctl
                updateV2Ray
            else
                echoContent green " ---> Give up and reinstall"
            fi
        else
            read -r -p "The latest version is: ${version}, do you want to update? [y/n]:" installV2RayStatus
            if [[ "${installV2RayStatus}" == "y" ]]; then
                rm -f /etc/v2ray-agent/v2ray/v2ray
                rm -f /etc/v2ray-agent/v2ray/v2ctl
                updateV2Ray
            else
                echoContent green " ---> Abort update"
            fi

        fi
    fi
}


updateXray() {
    readInstallType
    if [[ -z "${coreInstallType}" ]]; then
        if [[ -n "$1" ]]; then
            version=$1
        else
            version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5" | jq -r ".[]|select (.prerelease==${prereleaseStatus})|.tag_name" | head -1)
        fi

        echoContent green " ---> Xray-core版本:${version}"

        wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"

        unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
        rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
        chmod 655 /etc/v2ray-agent/xray/xray
        handleXray stop
        handleXray start
    else
        echoContent green " ---> Current Xray-core version: $(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

        if [[ -n "$1" ]]; then
            version=$1
        else
            version=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=5" | jq -r ".[]|select (.prerelease==${prereleaseStatus })|.tag_name" | head -1)
        fi

        if [[ -n "$1" ]]; then
            read -r -p "The rollback version is ${version}, do you want to continue? [y/n]:" rollbackXrayStatus
            if [[ "${rollbackXrayStatus}" == "y" ]]; then
                echoContent green " ---> Current Xray-core version: $(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

                handleXray stop
                rm -f /etc/v2ray-agent/xray/xray
                updateXray "${version}"
            else
                echoContent green " ---> Abandon the rollback version"
            fi
        elif [[ "${version}" == "v$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)" ]]; then
            read -r -p "The current version is the same as the latest version. Do you want to reinstall? [y/n]:" reInstallXrayStatus
            if [[ "${reInstallXrayStatus}" == "y" ]]; then
                handleXray stop
                rm -f /etc/v2ray-agent/xray/xray
                rm -f /etc/v2ray-agent/xray/xray
                updateXray
            else
                echoContent green " ---> Give up and reinstall"
            fi
        else
            read -r -p "The latest version is: ${version}, is it updated? [y/n]:" installXrayStatus
            if [[ "${installXrayStatus}" == "y" ]]; then
                rm -f /etc/v2ray-agent/xray/xray
                updateXray
            else
                echoContent green " ---> Abort update"
            fi

        fi
    fi
}


checkGFWStatue() {
    readInstallType
    echoContent skyBlue "\nProgress $1/${totalProgress}: Verify service startup status"
    if [[ "${coreInstallType}" == "1" ]] && [[ -n $(pgrep -f "xray/xray") ]]; then
        echoContent green " ---> Service started successfully"
    elif [[ "${coreInstallType}" == "2" ]] && [[ -n $(pgrep -f "v2ray/v2ray") ]]; then
        echoContent green " ---> Service started successfully"
    else
        echoContent red " ---> Service startup failed, please check if there are logs printed in the terminal"
        exit 0
    fi

}

installHysteriaService() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Configure Hysteria to start automatically at boot"
    if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
        rm -rf /etc/systemd/system/hysteria.service
        touch /etc/systemd/system/hysteria.service
        execStart='/etc/v2ray-agent/hysteria/hysteria server -c /etc/v2ray-agent/hysteria/conf/config.json --log-level debug'
        cat <<EOF >/etc/systemd/system/hysteria.service
[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/etc/v2ray-agent/hysteria/hysteria server -c /etc/v2ray-agent/hysteria/conf/config.json --log-level debug
Restart=on-failure
RestartSec=10
LimitNPROC=512
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable hysteria.service
        echoContent green " ---> Configure Hysteria to start automatically at boot"
    fi
}

installSingBoxService() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: configure sing-box to start automatically at boot"
    if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
        rm -rf /etc/systemd/system/sing-box.service
        touch /etc/systemd/system/sing-box.service
        execStart='/etc/v2ray-agent/sing-box/sing-box run -c /etc/v2ray-agent/sing-box/conf/config.json'
        cat <<EOF >/etc/systemd/system/sing-box.service
[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=${execStart}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
LimitNPROC=512
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable sing-box.service
        echoContent green " ---> Configure sing-box to start automatically at boot"
    fi
}


installXrayService() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Configure Xray to start automatically at boot"
    if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
        rm -rf /etc/systemd/system/xray.service
        touch /etc/systemd/system/xray.service
        execStart='/etc/v2ray-agent/xray/xray run -confdir /etc/v2ray-agent/xray/conf'
        cat <<EOF >/etc/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target
[Service]
User=root
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable xray.service
        echoContent green " ---> Configure Xray to start automatically at boot"
    fi
}

handleHysteria() {
    # shellcheck disable=SC2010
    if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q hysteria.service; then
        if [[ -z $(pgrep -f "hysteria/hysteria") ]] && [[ "$1" == "start" ]]; then
            systemctl start hysteria.service
        elif [[ -n $(pgrep -f "hysteria/hysteria") ]] && [[ "$1" == "stop" ]]; then
            systemctl stop hysteria.service
        fi
    fi
    sleep 0.8

    if [[ "$1" == "start" ]]; then
        if [[ -n $(pgrep -f "hysteria/hysteria") ]]; then
            echoContent green " ---> Hysteria启动成功"
        else
            echoContent red "Hysteria启动失败"
            echoContent red "请手动执行【/etc/v2ray-agent/hysteria/hysteria --log-level debug -c /etc/v2ray-agent/hysteria/conf/config.json server】，查看错误日志"
            exit 0
        fi
    elif [[ "$1" == "stop" ]]; then
        if [[ -z $(pgrep -f "hysteria/hysteria") ]]; then
            echoContent green " ---> Hysteria关闭成功"
        else
            echoContent red "Hysteria关闭失败"
            echoContent red "请手动执行【ps -ef|grep -v grep|grep hysteria|awk '{print \$2}'|xargs kill -9】"
            exit 0
        fi
    fi
}


handleTuic() {
    if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q tuic.service; then
        if [[ -z $(pgrep -f "tuic/tuic") ]] && [[ "$1" == "start" ]]; then
            singBoxMergeConfig
            systemctl start tuic.service
        elif [[ -n $(pgrep -f "tuic/tuic") ]] && [[ "$1" == "stop" ]]; then
            systemctl stop tuic.service
        fi
    fi
    sleep 0.8

    if [[ "$1" == "start" ]]; then
        if [[ -n $(pgrep -f "tuic/tuic") ]]; then
            echoContent green " ---> Tuic started successfully"
        else
            echoContent red "Tuic startup failed"
            echoContent red "Please manually execute [/etc/v2ray-agent/tuic/tuic -c /etc/v2ray-agent/tuic/conf/config.json] and check the error log"
            exit 0
        fi
    elif [[ "$1" == "stop" ]]; then
        if [[ -z $(pgrep -f "tuic/tuic") ]]; then
            echoContent green " ---> Tuic closed successfully"
        else
            echoContent red "Tuic failed to close"
            echoContent red "Please execute manually [ps -ef|grep -v grep|grep tuic|awk '{print \$2}'|xargs kill -9]"
            exit 0
        fi
    fi
}


handleSingBox() {
    if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q sing-box.service; then
        if [[ -z $(pgrep -f "sing-box") ]] && [[ "$1" == "start" ]]; then
            singBoxMergeConfig
            systemctl start sing-box.service
        elif [[ -n $(pgrep -f "sing-box") ]] && [[ "$1" == "stop" ]]; then
            systemctl stop sing-box.service
        fi
    fi
    sleep 0.8

    if [[ "$1" == "start" ]]; then
        if [[ -n $(pgrep -f "sing-box") ]]; then
            echoContent green " ---> sing-box started successfully"
        else
            echoContent red "sing-box failed to start"
            echoContent red "Please manually execute [/etc/v2ray-agent/sing-box/sing-box run -c /etc/v2ray-agent/sing-box/conf/config.json] and check the error log"
            exit 0
        fi
    elif [[ "$1" == "stop" ]]; then
        if [[ -z $(pgrep -f "sing-box") ]]; then
            echoContent green " ---> sing-box closed successfully"
        else
            echoContent red " ---> Failed to close sing-box"
            echoContent red "Please execute manually [ps -ef|grep -v grep|grep sing-box|awk '{print \$2}'|xargs kill -9]"
            exit 0
        fi
    fi
}

handleXray() {
    if [[ -n $(find /bin /usr/bin -name "systemctl") ]] && [[ -n $(find /etc/systemd/system/ -name "xray.service") ]]; then
        if [[ -z $(pgrep -f "xray/xray") ]] && [[ "$1" == "start" ]]; then
            systemctl start xray.service
        elif [[ -n $(pgrep -f "xray/xray") ]] && [[ "$1" == "stop" ]]; then
            systemctl stop xray.service
        fi
    fi

    sleep 0.8

    if [[ "$1" == "start" ]]; then
        if [[ -n $(pgrep -f "xray/xray") ]]; then
            echoContent green " ---> Xray started successfully"
        else
            echoContent red "Xray startup failed"
            echoContent red "Please manually execute the following command [/etc/v2ray-agent/xray/xray -confdir /etc/v2ray-agent/xray/conf] and feedback the error log"
            exit 0
        fi
    elif [[ "$1" == "stop" ]]; then
        if [[ -z $(pgrep -f "xray/xray") ]]; then
            echoContent green " ---> Xray closed successfully"
        else
            echoContent red "xray failed to close"
            echoContent red "Please execute manually [ps -ef|grep -v grep|grep xray|awk '{print \$2}'|xargs kill -9]"
            exit 0
        fi
    fi
}

initXrayClients() {
    local type=$1
    local newUUID=$2
    local newEmail=$3
    if [[ -n "${newUUID}" ]]; then
        local newUser=
        newUser="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"${newEmail}-VLESS_TCP/TLS_Vision\"}"
        currentClients=$(echo "${currentClients}" | jq -r ". +=[${newUser}]")
    fi
    local users=
    users=[]
    while read -r user; do
        uuid=$(echo "${user}" | jq -r .id)
        email=$(echo "${user}" | jq -r .email | awk -F "[-]" '{print $1}')
        currentUser=
        if echo "${type}" | grep -q "0"; then
            currentUser="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"${email}-VLESS_TCP/TLS_Vision\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # VLESS WS
        if echo "${type}" | grep -q "1"; then
            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-VLESS_WS\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # trojan grpc
        if echo "${type}" | grep -q "2"; then
            currentUser="{\"password\":\"${uuid}\",\"email\":\"${email}-Trojan_gRPC\"}"
            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # VMess WS
        if echo "${type}" | grep -q "3"; then
            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-VMess_WS\",\"alterId\": 0}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # trojan tcp
        if echo "${type}" | grep -q "4"; then
            currentUser="{\"password\":\"${uuid}\",\"email\":\"${email}-trojan_tcp\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # vless grpc
        if echo "${type}" | grep -q "5"; then
            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-vless_grpc\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # hysteria
        if echo "${type}" | grep -q "6"; then
            currentUser="{\"password\":\"${uuid}\",\"name\":\"${email}-singbox_hysteria2\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # vless reality vision
        if echo "${type}" | grep -q "7"; then
            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-vless_reality_vision\",\"flow\":\"xtls-rprx-vision\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

        # vless reality grpc
        if echo "${type}" | grep -q "8"; then
            currentUser="{\"id\":\"${uuid}\",\"email\":\"${email}-vless_reality_grpc\",\"flow\":\"\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi
        # tuic
        if echo "${type}" | grep -q "9"; then
            currentUser="{\"uuid\":\"${uuid}\",\"password\":\"${uuid}\",\"name\":\"${email}-singbox_tuic\"}"

            users=$(echo "${users}" | jq -r ". +=[${currentUser}]")
        fi

    done < <(echo "${currentClients}" | jq -c '.[]')
    echo "${users}"
}
getClients() {
    local path=$1

    local addClientsStatus=$2
    previousClients=

    if [[ ${addClientsStatus} == "true" ]]; then
        if [[ ! -f "${path}" ]]; then
            echo
            local protocol
            protocol=$(echo "${path}" | awk -F "[_]" '{print $2 $3}')
            echoContent yellow "The configuration file last installed for this protocol [${protocol}] was not read, and the first uuid of the configuration file was used"
        else
            previousClients=$(jq -r ".inbounds[0].settings.clients" "${path}")
        fi

    fi
}

# 添加client配置
addClients() {

    local path=$1
    local addClientsStatus=$2
    if [[ ${addClientsStatus} == "true" && -n "${previousClients}" ]]; then
        config=$(jq -r ".inbounds[0].settings.clients = ${previousClients}" "${path}")
        echo "${config}" | jq . >"${path}"
    fi
}
# 添加hysteria配置
addClientsHysteria() {
    local path=$1
    local addClientsStatus=$2

    if [[ ${addClientsStatus} == "true" && -n "${previousClients}" ]]; then
        local uuids=
        uuids=$(echo "${previousClients}" | jq -r [.[].id])

        if [[ "${frontingType}" == "02_trojan_TCP_inbounds" ]]; then
            uuids=$(echo "${previousClients}" | jq -r [.[].password])
        fi
        config=$(jq -r ".auth.config = ${uuids}" "${path}")
        echo "${config}" | jq . >"${path}"
    fi
}

initHysteriaPort() {
    readSingBoxConfig
    if [[ -n "${hysteriaPort}" ]]; then
        read -r -p "Read the port from the last installation. Do you want to use the port from the last installation? [y/n]:" historyHysteriaPortStatus
        if [[ "${historyHysteriaPortStatus}" == "y" ]]; then
            echoContent yellow "\n ---> Port: ${hysteriaPort}"
        else
            hysteriaPort=
        fi
    fi

    if [[ -z "${hysteriaPort}" ]]; then
        echoContent yellow "Please enter the Hysteria port [enter random 10000-30000], cannot be repeated with other services"
        read -r -p "Port:" hysteriaPort
        if [[ -z "${hysteriaPort}" ]]; then
            hysteriaPort=$((RANDOM % 20001 + 10000))
        fi
    fi
    if [[ -z ${hysteriaPort} ]]; then
        echoContent red " ---> Port cannot be empty"
        initHysteriaPort "$2"
    elif ((hysteriaPort < 1 || hysteriaPort > 65535)); then
        echoContent red " ---> The port is illegal"
        initHysteriaPort "$2"
    fi
    allowPort "${hysteriaPort}"
    allowPort "${hysteriaPort}" "udp"
}

initHysteriaProtocol() {
    echoContent skyBlue "\nPlease select the protocol type"
    echoContent red "================================================== ==============="
    echoContent yellow "1.udp(QUIC)(default)"
    echoContent yellow "2.faketcp"
    echoContent yellow "3.wechat-video"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" selectHysteriaProtocol
    case ${selectHysteriaProtocol} in
    1)
        hysteriaProtocol="udp"
        ;;
    2)
        hysteriaProtocol="faketcp"
        ;;
    3)
        hysteriaProtocol="wechat-video"
        ;;
    *)
        hysteriaProtocol="udp"
        ;;
    esac
    echoContent yellow "\n ---> Protocol: ${hysteriaProtocol}\n"
}

initHysteria2Network() {

    echoContent yellow "Please enter the local bandwidth peak downstream speed (default: 100, unit: Mbps)"
    read -r -p "Download speed:" hysteria2ClientDownloadSpeed
    if [[ -z "${hysteria2ClientDownloadSpeed}" ]]; then
        hysteria2ClientDownloadSpeed=100
        echoContent yellow "\n --->Download speed: ${hysteria2ClientDownloadSpeed}\n"
    fi

    echoContent yellow "Please enter the local bandwidth peak uplink speed (default: 50, unit: Mbps)"
    read -r -p "upload speed:" hysteria2ClientUploadSpeed
    if [[ -z "${hysteria2ClientUploadSpeed}" ]]; then
        hysteria2ClientUploadSpeed=50
        echoContent yellow "\n ---> Upload speed: ${hysteria2ClientUploadSpeed}\n"
    fi
}

hysteriaPortHopping() {
    if [[ -n "${portHoppingStart}" || -n "${portHoppingEnd}" ]]; then
        echoContent red " ---> Already added, cannot be added repeatedly, can be deleted and re-added"
        exit 0
    fi

    echoContent skyBlue "\nProgress 1/1: Port jump"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Notes\n"
    echoContent yellow "Only supports UDP"
    echoContent yellow "The starting position of port jumping is 30000"
    echoContent yellow "The end position of port jumping is 60000"
    echoContent yellow "You can choose a segment in the range of 30000-60000"
    echoContent yellow "Recommend about 1000"

    echoContent yellow "Please enter the port jumping range, for example [30000-31000]"

    read -r -p "Range:" hysteriaPortHoppingRange
    if [[ -z "${hysteriaPortHoppingRange}" ]]; then
        echoContent red " ---> Range cannot be empty"
        hysteriaPort Hopping
    elif echo "${hysteriaPortHoppingRange}" | grep -q "-"; then

        local portStart=
        local portEnd=
        portStart=$(echo "${hysteriaPortHoppingRange}" | awk -F '-' '{print $1}')
        portEnd=$(echo "${hysteriaPortHoppingRange}" | awk -F '-' '{print $2}')

        if [[ -z "${portStart}" || -z "${portEnd}" ]]; then
            echoContent red " ---> The range is illegal"
            hysteriaPort Hopping
        elif ((portStart < 30000 || portStart > 60000 || portEnd < 30000 || portEnd > 60000 || portEnd < portStart)); then
            echoContent red " ---> The range is illegal"
            hysteriaPort Hopping
        else
            echoContent green "\nPort range: ${hysteriaPortHoppingRange}\n"
            iptables -t nat -A PREROUTING -p udp --dport "${portStart}:${portEnd}" -m comment --comment "mack-a_portHopping" -j DNAT --to-destination :${hysteriaPort}

            if iptables-save | grep -q "mack-a_portHopping"; then
                allowPort "${portStart}:${portEnd}" udp
                echoContent green " ---> Port hopping added successfully"
            else
                echoContent red " ---> Failed to add port hopping"
            fi
            #fi
        fi

    fi
}

readHysteriaPortHopping() {
    if [[ -n "${hysteriaPort}" ]]; then
        if iptables-save | grep -q "mack-a_portHopping"; then
            portHopping=
            portHopping=$(iptables-save | grep "mack-a_portHopping" | cut -d " " -f 8)
            portHoppingStart=$(echo "${portHopping}" | cut -d ":" -f 1)
            portHoppingEnd=$(echo "${portHopping}" | cut -d ":" -f 2)
        fi
    fi
}

deleteHysteriaPortHoppingRules() {
    iptables -t nat -L PREROUTING --line-numbers | grep "mack-a_portHopping" | awk '{print $1}' | while read -r line; do
        iptables -t nat -D PREROUTING 1
    done
}

hysteriaPortHoppingMenu() {
    if ! find /usr/bin /usr/sbin | grep -q -w iptables; then
        echoContent red " ---> Unable to recognize iptables tool, unable to use port jump, exit installation"
        exit 0
    fi
    readHysteriaConfig
    readHysteriaPortHopping
    echoContent skyBlue "\nProgress 1/1: Port jump"
    echoContent red "\n================================================ ================="
    echoContent yellow "1. Add port hopping"
    echoContent yellow "2. Delete port hopping"
    echoContent yellow "3. Check port jumping"
    read -r -p "range:" selectPortHoppingStatus
    if [[ "${selectPortHoppingStatus}" == "1" ]]; then
        hysteriaPort Hopping
    elif [[ "${selectPortHoppingStatus}" == "2" ]]; then
        if [[ -n "${portHopping}" ]]; then
            deleteHysteriaPortHoppingRules
            echoContent green " ---> Deletion successful"
        fi
    elif [[ "${selectPortHoppingStatus}" == "3" ]]; then
        echoContent green " ---> The current port hopping range is: ${portHoppingStart}-${portHoppingEnd}"
    else
        hysteriaPortHoppingMenu
    fi
}


initHysteriaConfig() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Initializing Hysteria configuration"

    initHysteriaPort
    local uuid=
    uuid=$(${ctlPath} uuid)
    cat <<EOF >/etc/v2ray-agent/hysteria/conf/config.json
{
    "listen":":${hysteriaPort}",
    "tls":{
        "cert": "/etc/v2ray-agent/tls/${currentHost}.crt",
        "key": "/etc/v2ray-agent/tls/${currentHost}.key"
    },
    "auth":{
        "type": "password",
        "password": "${uuid}"
    },
    "resolver":{
      "type": "https",
      "https":{
        "addr": "1.1.1.1:443",
        "timeout": "10s"
      }
    },
    "outbounds":{
      "name": "socks5_outbound",
        "type": "socks5",
        "socks5":{
            "addr": "127.0.0.1:31295",
            "username": "hysteria_socks5_outbound",
            "password": "${uuid}"
        }
    }
}

EOF


    cat <<EOF >${configPath}/02_socks_inbounds_hysteria.json
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 31295,
      "protocol": "Socks",
      "tag": "socksHysteriaOutbound",
      "settings": {
        "auth": "password",
        "accounts": [
          {
            "user": "hysteria_socks5_outbound",
            "pass": "${uuid}"
          }
        ],
        "udp": true,
        "ip": "127.0.0.1"
      }
    }
  ]
}
EOF
}


initTuicPort() {
    readSingBoxConfig
    if [[ -n "${tuicPort}" ]]; then
        read -r -p "Read the port from the last installation. Do you want to use the port from the last installation? [y/n]:" historyTuicPortStatus
        if [[ "${historyTuicPortStatus}" == "y" ]]; then
            echoContent yellow "\n ---> Port: ${tuicPort}"
        else
            tuicPort=
        fi
    fi

    if [[ -z "${tuicPort}" ]]; then
        echoContent yellow "Please enter the Tuic port [enter random 10000-30000], cannot be repeated with other services"
        read -r -p "Port:" tuicPort
        if [[ -z "${tuicPort}" ]]; then
            tuicPort=$((RANDOM % 20001 + 10000))
        fi
    fi
    if [[ -z ${tuicPort} ]]; then
        echoContent red " ---> Port cannot be empty"
        initTuicPort "$2"
    elif ((tuicPort < 1 || tuicPort > 65535)); then
        echoContent red " ---> The port is illegal"
        initTuicPort "$2"
    fi
    echoContent green "\n ---> Port: ${tuicPort}"
    allowPort "${tuicPort}"
    allowPort "${tuicPort}" "udp"
}


initTuicProtocol() {
    echoContent skyBlue "\nPlease select the algorithm type"
    echoContent red "================================================== ==============="
    echoContent yellow "1.bbr(default)"
    echoContent yellow "2.cubic"
    echoContent yellow "3.new_reno"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" selectTuicAlgorithm
    case ${selectTuicAlgorithm} in
    1)
        tuicAlgorithm="bbr"
        ;;
    2)
        tuicAlgorithm="cubic"
        ;;
    3)
        tuicAlgorithm="new_reno"
        ;;
    *)
        tuicAlgorithm="bbr"
        ;;
    esac
    echoContent yellow "\n ---> Algorithm: ${tuicAlgorithm}\n"
}


initSingBoxTuicConfig() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Initializing Tuic configuration"

    initTuicPort
    initTuicProtocol
    cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/tuic.json
{
     "inbounds": [
    {
        "type": "tuic",
        "listen": "::",
        "tag": "singbox-tuic-in",
        "listen_port": ${tuicPort},
        "users": $(initXrayClients 9),
        "congestion_control": "${tuicAlgorithm}",
        "tls": {
            "enabled": true,
            "server_name":"${currentHost}",
            "alpn": [
                "h3"
            ],
            "certificate_path": "/etc/v2ray-agent/tls/${currentHost}.crt",
            "key_path": "/etc/v2ray-agent/tls/${currentHost}.key"
        }
    }
]
}
EOF
}


initSingBoxRouteConfig() {
    downloadSingBoxGeositeDB
    local outboundTag=$1
    if [[ ! -f "${singBoxConfigPath}config/${outboundTag}_route.json" ]]; then
        cat <<EOF >"${singBoxConfigPath}config/${outboundTag}_route.json"
{
    "route": {
        "geosite": {
            "path": "${singBoxConfigPath}geosite.db"
        },
        "rules": [
            {
                "domain": [
                ],
                "geosite": [
                ],
                "outbound": "${outboundTag}"
            }
        ]
    }
}
EOF
    fi
}


downloadSingBoxGeositeDB() {
    if [[ ! -f "${singBoxConfigPath}geosite.db" ]]; then
        wget -q -P "${singBoxConfigPath}" https://github.com/Johnshall/sing-geosite/releases/latest/download/geosite.db
    fi
}


configurationSingBoxRoute() {
    local type=$1
    local outboundTag=$2
    local content=$3
    if [[ "${type}" == "add" ]]; then
        addSingBoxRouteRule "${outboundTag}" "${content}"
    elif [[ "${type}" == "delete" ]]; then
        if [[ -f "${singBoxConfigPath}config/${outboundTag}_route.json" ]]; then
            rm "${singBoxConfigPath}config/${outboundTag}_route.json"
            echoContent green "\n ---> Deletion successful"
        fi
    fi
}


addSingBoxRouteRule() {
    local outboundTag=$1
    local domainList=$2

    initSingBoxRouteConfig "${outboundTag}"
    local rules

    rules=$(jq -r '.route.rules[]|select(.outbound=="'"${outboundTag}"'")' "${singBoxConfigPath}config/${outboundTag}_route.json")

    while read -r line; do
        if echo "${rules}" | grep -q "${line}"; then
            echoContent yellow " ---> ${line} already exists, skip"
        else
            if echo "${line}" | grep -q "\."; then
                rules=$(echo "${rules}" | jq -r ".domain +=[\"${line}\"]")
            else
                rules=$(echo "${rules}" | jq -r ".geosite +=[\"${line}\"]")
            fi
        fi
    done < <(echo "${domainList}" | tr ',' '\n')

    local delRules
    delRules=$(jq -r 'del(.route.rules[]|select(.outbound=="'"${outboundTag}"'"))' "${singBoxConfigPath}config/${outboundTag}_route.json")
    echo "${delRules}" >"${singBoxConfigPath}config/${outboundTag}_route.json"

    local routeRules
    routeRules=$(jq -r ".route.rules += [${rules}]" "${singBoxConfigPath}config/${outboundTag}_route.json")
    echo "${routeRules}" >"${singBoxConfigPath}config/${outboundTag}_route.json"
}


removeSingBoxRouteRule() {
    local outboundTag=$1
    local delRules
    if [[ -f "${singBoxConfigPath}config/${outboundTag}_route.json" ]]; then
        delRules=$(jq -r 'del(.route.rules[]|select(.outbound=="'"${outboundTag}"'"))' "${singBoxConfigPath}config/${outboundTag}_route.json")
        echo "${delRules}" >"${singBoxConfigPath}config/${outboundTag}_route.json"
    fi
}


addSingBoxOutbound() {
    local tag=$1
    local type="ipv4"
    local detour=$2
    if echo "${tag}" | grep -q "IPv6"; then
        type=ipv6
    fi
    if [[ -n "${detour}" ]]; then
        cat <<EOF >"${singBoxConfigPath}config/${tag}.json"
{
     "outbounds": [
        {
             "type": "direct",
             "tag": "${tag}",
             "detour": "${detour}",
             "domain_strategy": "${type}_only"
        }
    ]
}
EOF
    elif echo "${tag}" | grep -q "direct"; then

        cat <<EOF >"${singBoxConfigPath}config/${tag}.json"
{
     "outbounds": [
        {
             "type": "direct",
             "tag": "${tag}"
        }
    ]
}
EOF
    else
        cat <<EOF >"${singBoxConfigPath}config/${tag}.json"
{
     "outbounds": [
        {
             "type": "direct",
             "tag": "${tag}",
             "domain_strategy": "${type}_only"
        }
    ]
}
EOF
    fi
}


removeSingBoxOutbound() {

    local tag=$1
    if [[ -f "${singBoxConfigPath}config/${tag}.json" ]]; then
        rm "${singBoxConfigPath}config/${tag}.json"
    fi

}


addSingBoxWireGuardOut() {
    readConfigWarpReg
    cat <<EOF >"${singBoxConfigPath}config/wireguard_outbound.json"
{
     "outbounds": [

        {
            "type": "wireguard",
            "tag": "wireguard_out",
            "server": "162.159.192.1",
            "server_port": 2408,
            "local_address": [
                "172.16.0.2/32",
                "${addressWarpReg}/128"
            ],
            "private_key": "${secretKeyWarpReg}",
            "peer_public_key": "${publicKeyWarpReg}",
            "reserved":${reservedWarpReg},
            "mtu": 1280
        }
    ]
}
EOF
}


configurationSingBoxOutbound() {
    local type=$1
    local outboundTag=$2
    local content=$3
    if [[ "${outboundTag}" == "" ]]; then
        echo
    fi
}


initSingBoxSocks5OutboundsConfig() {
    local uuid=
    uuid=$(/etc/v2ray-agent/xray/xray uuid)
    cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/socks5_outbounds.json
{
     "outbounds": [
    {
        "type": "socks",
        "tag": "singBoxSocks5Out",
        "version": "5",
        "server":"127.0.0.1",
        "server_port":31295,
        "username": "singBox_socks5_outbound",
        "password": "${uuid}",
        "network":"udp"
    }
]
}
EOF

    cat <<EOF >${configPath}/02_socks_inbounds_singbox.json
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 31295,
      "protocol": "Socks",
      "tag": "socksSingBoxOutbound",
      "settings": {
        "auth": "password",
        "accounts": [
          {
            "user": "singBox_socks5_outbound",
            "pass": "${uuid}"
          }
        ],
        "udp": true,
        "ip": "127.0.0.1"
      }
    }
  ]
}
EOF
}


initSingBoxHysteria2Config() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Initializing Hysteria2 configuration"

    initHysteriaPort
    initHysteria2Network

    cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/hysteria2.json
{
    "inbounds": [
        {
            "type": "hysteria2",
            "listen": "::",
            "listen_port": ${hysteriaPort},
            "users": $(initXrayClients 6),
            "up_mbps":${hysteria2ClientDownloadSpeed},
            "down_mbps":${hysteria2ClientUploadSpeed},
            "tls": {
                "enabled": true,
                "server_name":"${currentHost}",
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/etc/v2ray-agent/tls/${currentHost}.crt",
                "key_path": "/etc/v2ray-agent/tls/${currentHost}.key"
            }
        }
    ]
}
EOF
}

# sing-box Tuic installation
singBoxTuicInstall() {
    if ! echo "${currentInstallProtocolType}" | grep -q "0" || [[ -z "${coreInstallType}" ]]; then
        echoContent red "\n ---> Due to certificate environment dependencies, if you install Tuic, please install Xray-core's VLESS_TCP_TLS_Vision first"
        exit 0
    fi
    totalProgress=5
    # installTuic 1
    installSingBox 1
    initSingBoxTuicConfig 2
    installSingBoxService 3
    reloadCore
    showAccounts 4
}

# sing-box hy2 installation
singBoxHysteria2Install() {
    if ! echo "${currentInstallProtocolType}" | grep -q "0" || [[ -z "${coreInstallType}" ]]; then
        echoContent red "\n ---> Due to certificate environment dependencies, if you install Hysteria2, please install Xray-core's VLESS_TCP_TLS_Vision first"
        exit 0
    fi
    totalProgress=5
    installSingBox 1
    initSingBoxHysteria2Config 2
    installSingBoxService 3
    reloadCore
    showAccounts 4
}

# 合并config
singBoxMergeConfig() {
    rm /etc/v2ray-agent/sing-box/conf/config.json >/dev/null 2>&1
    /etc/v2ray-agent/sing-box/sing-box merge config.json -C /etc/v2ray-agent/sing-box/conf/config/ -D /etc/v2ray-agent/sing-box/conf/ >/dev/null 2>&1
}

# 初始化V2Ray 配置文件
initV2RayConfig() {
    echoContent skyBlue "\nProgress $2/${totalProgress}: Initializing V2Ray configuration"
    echo

    read -r -p "Do you want to customize the UUID? [y/n]:" customUUIDStatus
    echo
    if [[ "${customUUIDStatus}" == "y" ]]; then
        read -r -p "Please enter a valid UUID:" currentCustomUUID
        if [[ -n "${currentCustomUUID}" ]]; then
            uuid=${currentCustomUUID}
        fi
    fi
    local addClientsStatus=
    if [[ -n "${currentUUID}" && -z "${uuid}" ]]; then
        read -r -p "Read the last installation record. Do you want to use the UUID from the last installation? [y/n]:" historyUUIDStatus
        if [[ "${historyUUIDStatus}" == "y" ]]; then
            uuid=${currentUUID}
            addClientsStatus=true
        else
            uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
        fi
    elif [[ -z "${uuid}" ]]; then
        uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
    fi

    if [[ -z "${uuid}" ]]; then
        addClientsStatus=
        echoContent red "\n ---> uuid reading error, regenerate"
        uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
    fi

    movePreviousConfig
    # log
    cat <<EOF >/etc/v2ray-agent/v2ray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/v2ray/error.log",
    "loglevel": "warning"
  }
}
EOF
    # outbounds
    if [[ -n "${pingIPv6}" ]]; then
        cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

    else
        cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4_out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6_out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole_out"
        }
    ]
}
EOF
    fi

    # dns
    cat <<EOF >/etc/v2ray-agent/v2ray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF


    local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

    if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then

        fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'

        getClients "${configPath}../tmp/04_trojan_TCP_inbounds.json" "${addClientsStatus}"
        cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "default_Trojan_TCP"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
        addClients "/etc/v2ray-agent/v2ray/conf/04_trojan_TCP_inbounds.json" "${addClientsStatus}"
    fi

    # VLESS_WS_TLS
    if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
        fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
        getClients "${configPath}../tmp/03_VLESS_WS_inbounds.json" "${addClientsStatus}"
        cat <<EOF >/etc/v2ray-agent/v2ray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
	  "port": 31297,
	  "listen": "127.0.0.1",
	  "protocol": "vless",
	  "tag":"VLESSWS",
	  "settings": {
		"clients": [
		  {
			"id": "${uuid}",
			"email": "default_VLESS_WS"
		  }
		],
		"decryption": "none"
	  },
	  "streamSettings": {
		"network": "ws",
		"security": "none",
		"wsSettings": {
		  "acceptProxyProtocol": true,
		  "path": "/${customPath}ws"
		}
	  }
	}
]
}
EOF
        addClients "/etc/v2ray-agent/v2ray/conf/03_VLESS_WS_inbounds.json" "${addClientsStatus}"
    fi

    # trojan_grpc
    if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
        if ! echo "${selectCustomInstallType}" | grep -q 5 && [[ -n ${selectCustomInstallType} ]]; then
            fallbacksList=${fallbacksList//31302/31304}
        fi
        getClients "${configPath}../tmp/04_trojan_gRPC_inbounds.json" "${addClientsStatus}"
        cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "default_Trojan_gRPC"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
        addClients "/etc/v2ray-agent/v2ray/conf/04_trojan_gRPC_inbounds.json" "${addClientsStatus}"
    fi

    # VMess_WS
    if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
        fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'

        getClients "${configPath}../tmp/05_VMess_WS_inbounds.json" "${addClientsStatus}"

        cat <<EOF >/etc/v2ray-agent/v2ray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "default_VMess_WS"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
        addClients "/etc/v2ray-agent/v2ray/conf/05_VMess_WS_inbounds.json" "${addClientsStatus}"
    fi

    if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
        getClients "${configPath}../tmp/06_VLESS_gRPC_inbounds.json" "${addClientsStatus}"
        cat <<EOF >/etc/v2ray-agent/v2ray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
                    "email": "default_VLESS_gRPC"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
        addClients "/etc/v2ray-agent/v2ray/conf/06_VLESS_gRPC_inbounds.json" "${addClientsStatus}"
    fi

    # VLESS_TCP
    getClients "${configPath}../tmp/02_VLESS_TCP_inbounds.json" "${addClientsStatus}"
    local defaultPort=443
    if [[ -n "${customPort}" ]]; then
        defaultPort=${customPort}
    fi

    cat <<EOF >/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": ${defaultPort},
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "email": "default_VLESS_TCP"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF
    addClients "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" "${addClientsStatus}"

}


initXrayFrontingConfig() {
    echoContent red " ---> Trojan does not currently support xtls-rprx-vision"
    exit 0
    if [[ -z "${configPath}" ]]; then
        echoContent red " ---> Not installed, please use script to install"
        menu
        exit 0
    fi
    if [[ "${coreInstallType}" != "1" ]]; then
        echoContent red " ---> Available types are not installed"
    fi
    local xtlsType=
    if echo ${currentInstallProtocolType} | grep -q trojan; then
        xtlsType=VLESS
    else
        xtlsType=Trojan

    fi

    echoContent skyBlue "\nFunction 1/${totalProgress}: switch to ${xtlsType}"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Notes\n"
    echoContent yellow "will replace the prefix with ${xtlsType}"
    echoContent yellow "If the prefix is ​​Trojan, two Trojan protocol nodes will appear when viewing the account, and one of them is unavailable xtls"
    echoContent yellow "Execute again to switch to the last prefix\n"

    echoContent yellow "1.Switch to ${xtlsType}"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" selectType
    if [[ "${selectType}" == "1" ]]; then

        if [[ "${xtlsType}" == "Trojan" ]]; then

            local VLESSConfig
            VLESSConfig=$(cat ${configPath}${frontingType}.json)
            VLESSConfig=${VLESSConfig//"id"/"password"}
            VLESSConfig=${VLESSConfig//VLESSTCP/TrojanTCPXTLS}
            VLESSConfig=${VLESSConfig//VLESS/Trojan}
            VLESSConfig=${VLESSConfig//"vless"/"trojan"}
            VLESSConfig=${VLESSConfig//"id"/"password"}

            echo "${VLESSConfig}" | jq . >${configPath}02_trojan_TCP_inbounds.json
            rm ${configPath}${frontingType}.json
        elif [[ "${xtlsType}" == "VLESS" ]]; then

            local VLESSConfig
            VLESSConfig=$(cat ${configPath}02_trojan_TCP_inbounds.json)
            VLESSConfig=${VLESSConfig//"password"/"id"}
            VLESSConfig=${VLESSConfig//TrojanTCPXTLS/VLESSTCP}
            VLESSConfig=${VLESSConfig//Trojan/VLESS}
            VLESSConfig=${VLESSConfig//"trojan"/"vless"}
            VLESSConfig=${VLESSConfig//"password"/"id"}

            echo "${VLESSConfig}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
            rm ${configPath}02_trojan_TCP_inbounds.json
        fi
        reloadCore
    fi

    exit 0
}


movePreviousConfig() {

    if [[ -n "${configPath}" ]]; then
        if [[ -z "${realityStatus}" ]]; then
            rm -rf "${configPath}../tmp/*" 2>/dev/null
            mv ${configPath}[0][2-6]* ${configPath}../tmp/ 2>/dev/null
        else
            rm -rf "${configPath}../tmp/*"
            mv ${configPath}[0][7-8]* ${configPath}../tmp/ 2>/dev/null
            mv ${configPath}[0][2]* ${configPath}../tmp/ 2>/dev/null
        fi

    fi
}


initXrayConfig() {
    echoContent skyBlue "\nProgress $2/${totalProgress}: Initializing Xray configuration"
    echo
    local uuid=
    local addClientsStatus=
    if [[ -n "${currentUUID}" ]]; then
        read -r -p "Read the last user configuration. Do you want to use the last installed configuration? [y/n]:" historyUUIDStatus
        if [[ "${historyUUIDStatus}" == "y" ]]; then
            addClientsStatus=true
            echoContent green "\n ---> Used successfully"
        fi
    fi

    if [[ -z "${addClientsStatus}" ]]; then
        echoContent yellow "Please enter custom UUID [need to be legal], [Enter] random UUID"
        read -r -p 'UUID:' customUUID

        if [[ -n ${customUUID} ]]; then
            uuid=${customUUID}
        else
            uuid=$(/etc/v2ray-agent/xray/xray uuid)
        fi

        echoContent yellow "\nPlease enter a custom username [must be legal], [Enter] a random username"
        read -r -p 'Username:' customEmail
        if [[ -z ${customEmail} ]]; then
            customEmail="$(echo "${uuid}" | cut -d "-" -f 1)-VLESS_TCP/TLS_Vision"
        fi
    fi

    if [[ -z "${addClientsStatus}" && -z "${uuid}" ]]; then
        addClientsStatus=
        echoContent red "\n ---> uuid reading error, randomly generated"
        uuid=$(/etc/v2ray-agent/xray/xray uuid)
    fi

    if [[ -n "${uuid}" ]]; then
        currentClients='[{"id":"'${uuid}'","add":"'${add}'","flow":"xtls-rprx-vision","email":"'$ {customEmail}'"}]'
        echoContent yellow "\n ${customEmail}:${uuid}"
    fi

    # log
    if [[ ! -f "/etc/v2ray-agent/xray/conf/00_log.json" ]]; then

        cat <<EOF >/etc/v2ray-agent/xray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/xray/error.log",
    "loglevel": "warning"
  }
}
EOF
    fi

    if [[ ! -f "/etc/v2ray-agent/xray/conf/12_policy.json" ]]; then

        cat <<EOF >/etc/v2ray-agent/xray/conf/12_policy.json
{
  "policy": {
      "levels": {
          "0": {
              "handshake": $((1 + RANDOM % 4)),
              "connIdle": $((250 + RANDOM % 51))
          }
      }
  }
}
EOF
    fi

    # outbounds
    if [[ ! -f "/etc/v2ray-agent/xray/conf/10_ipv6_outbounds.json" ]]; then
        if [[ -n "${pingIPv6}" ]]; then
            cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

        else
            cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4_out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6_out"
        },
        {
            "protocol":"freedom",
            "settings": {},
            "tag":"direct"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole_out"
        }
    ]
}
EOF
        fi
    fi

    # dns
    if [[ ! -f "/etc/v2ray-agent/xray/conf/11_dns.json" ]]; then
        cat <<EOF >/etc/v2ray-agent/xray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF
    fi
    # routing
    if [[ ! -f "/etc/v2ray-agent/xray/conf/09_routing.json" ]]; then
        cat <<EOF >/etc/v2ray-agent/xray/conf/09_routing.json
{
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": [
          "domain:gstatic.com",
          "domain:googleapis.com"
        ],
        "outboundTag": "direct"
      }
    ]
  }
}
EOF
    fi
    # VLESS_TCP_TLS_Vision
    # 回落nginx
    local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

    # trojan
    if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then
        fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
        cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": $(initXrayClients 4),
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
    else
        rm /etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json >/dev/null 2>&1
    fi

    # VLESS_WS_TLS
    if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
        fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
        cat <<EOF >/etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
	  "port": 31297,
	  "listen": "127.0.0.1",
	  "protocol": "vless",
	  "tag":"VLESSWS",
	  "settings": {
		"clients": $(initXrayClients 1),
		"decryption": "none"
	  },
	  "streamSettings": {
		"network": "ws",
		"security": "none",
		"wsSettings": {
		  "acceptProxyProtocol": true,
		  "path": "/${customPath}ws"
		}
	  }
	}
]
}
EOF
    else
        rm /etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json >/dev/null 2>&1
    fi

    # trojan_grpc
    if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
        if ! echo "${selectCustomInstallType}" | grep -q 5 && [[ -n ${selectCustomInstallType} ]]; then
            fallbacksList=${fallbacksList//31302/31304}
        fi
        cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": $(initXrayClients 2),
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
    else
        rm /etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json >/dev/null 2>&1
    fi

    # VMess_WS
    if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
        fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
        cat <<EOF >/etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": $(initXrayClients 3)
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
    else
        rm /etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json >/dev/null 2>&1
    fi

    if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
        cat <<EOF >/etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": $(initXrayClients 5),
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
    else
        rm /etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json >/dev/null 2>&1
    fi
    # VLESS Vision
    if echo "${selectCustomInstallType}" | grep -q 0 || [[ "$1" == "all" ]]; then

        cat <<EOF >/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
{
    "inbounds":[
        {
          "port": ${port},
          "protocol": "vless",
          "tag":"VLESSTCP",
          "settings": {
            "clients":$(initXrayClients 0),
            "decryption": "none",
            "fallbacks": [
                ${fallbacksList}
            ]
          },
          "add": "${add}",
          "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
              "rejectUnknownSni": true,
              "minVersion": "1.2",
              "certificates": [
                {
                  "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
                  "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
                  "ocspStapling": 3600
                }
              ]
            }
          }
        }
    ]
}
EOF
    else
        rm /etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json >/dev/null 2>&1
    fi

    # VLESS_TCP/reality
    if echo "${selectCustomInstallType}" | grep -q 7 || [[ "$1" == "all" ]]; then
        echoContent skyBlue "\n===================== 配置VLESS+Reality =====================\n"
        initRealityPort
        initRealityDest
        initRealityClientServersName
        initRealityKey

        cat <<EOF >/etc/v2ray-agent/xray/conf/07_VLESS_vision_reality_inbounds.json
{
  "inbounds": [
    {
      "port": ${realityPort},
      "protocol": "vless",
      "tag": "VLESSReality",
      "settings": {
        "clients": $(initXrayClients 7),
        "decryption": "none",
        "fallbacks":[
            {
                "dest": "31305",
                "xver": 1
            }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "show": false,
            "dest": "${realityDestDomain}",
            "xver": 0,
            "serverNames": [
                ${realityServerNames}
            ],
            "privateKey": "${realityPrivateKey}",
            "publicKey": "${realityPublicKey}",
            "maxTimeDiff": 70000,
            "shortIds": [
                "",
                "6ba85179e30d4fc2"
            ]
        }
      }
    }
  ]
}
EOF

        cat <<EOF >/etc/v2ray-agent/xray/conf/08_VLESS_reality_fallback_grpc_inbounds.json
{
  "inbounds": [
    {
      "port": 31305,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "tag": "VLESSRealityGRPC",
      "settings": {
        "clients": $(initXrayClients 8),
        "decryption": "none"
      },
      "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "grpc",
                "multiMode": true
            },
            "sockopt": {
                "acceptProxyProtocol": true
            }
      }
    }
  ]
}
EOF

    else
        rm /etc/v2ray-agent/xray/conf/07_VLESS_vision_reality_inbounds.json >/dev/null 2>&1
        rm /etc/v2ray-agent/xray/conf/08_VLESS_reality_fallback_grpc_inbounds.json >/dev/null 2>&1
    fi
    installSniffing
}


customCDNIP() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Add cloudflare custom CNAME"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Notes"
    echoContent yellow "\nTutorial address:"
    echoContent skyBlue "https://www.v2ray-agent.com/archives/cloudflarezi-xuan-ip"
    echoContent red "\nIf you don't understand Cloudflare optimization, please do not use it"
    echoContent yellow "\n 1.CNAME www.digitalocean.com"
    echoContent yellow " 2.CNAME who.int"
    echoContent yellow " 3.CNAME blog.hostmonit.com"

    echoContent skyBlue "----------------------------"
    read -r -p "Please select [Enter is not used]:" selectCloudflareType
    case ${selectCloudflareType} in
    1)
        add="www.digitalocean.com"
        ;;
    2)
        add="who.int"
        ;;
    3)
        add="blog.hostmonit.com"
        ;;
    *)
        add="${domain}"
        echoContent yellow "\n ---> Not used"
        ;;
    esac
}


defaultBase64Code() {
    local type=$1
    local email=$2
    local id=$3
    local add=$4
    local user=
    user=$(echo "${email}" | awk -F "[-]" '{print $1}')
    port=${currentDefaultPort}

    if [[ "${type}" == "vlesstcp" ]]; then

        if [[ "${coreInstallType}" == "1" ]] && echo "${currentInstallProtocolType}" | grep -q 0; then
            echoContent yellow " ---> 通用格式(VLESS+TCP+TLS_Vision)"
            echoContent green "    vless://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=tls&fp=chrome&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-vision#${email}\n"

            echoContent yellow " ---> 格式化明文(VLESS+TCP+TLS_Vision)"
            echoContent green "协议类型:VLESS，地址:${currentHost}，端口:${currentDefaultPort}，用户ID:${id}，安全:tls，client-fingerprint: chrome，传输方式:tcp，flow:xtls-rprx-vision，账户名:${email}\n"
            cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=tls&type=tcp&host=${currentHost}&fp=chrome&headerType=none&sni=${currentHost}&flow=xtls-rprx-vision#${email}
EOF
            cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: ${currentHost}
    port: ${currentDefaultPort}
    uuid: ${id}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    client-fingerprint: chrome
EOF
            echoContent yellow " ---> QR code VLESS(VLESS+TCP+TLS_Vision)"
            echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${currentHost}%3A${currentDefaultPort}% 3Fencryption%3Dnone%26fp%3Dchrome%26security%3Dtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-vision%23$ {email}\n"
        elif [[ "${coreInstallType}" == 2 ]]; then
            echoContent yellow " ---> Universal format (VLESS+TCP+TLS)"
            echoContent green " vless://${id}@${currentHost}:${currentDefaultPort}?security=tls&encryption=none&host=${currentHost}&fp=chrome&headerType=none&type=tcp#${email}\n"

            echoContent yellow " ---> Formatted plain text (VLESS+TCP+TLS)"
            echoContent green "Protocol type: VLESS, address: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: tls, client-fingerprint: chrome, transmission method: tcp, account name: ${ email}\n"

            cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${currentHost}:${currentDefaultPort}?security=tls&encryption=none&host=${currentHost}&fp=chrome&headerType=none&type=tcp#${email}
EOF
            echoContent yellow " ---> QR code VLESS(VLESS+TCP+TLS)"
            echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3a%2f%2f${id}%40${currentHost}%3a${currentDefaultPort}% 3fsecurity%3dtls%26encryption%3dnone%26fp%3Dchrome%26host%3d${currentHost}%26headerType%3dnone%26type%3dtcp%23${email}\n"
        fi

    elif [[ "${type}" == "trojanTCPXTLS" ]]; then
        echoContent yellow " ---> Common format (Trojan+TCP+TLS_Vision)"
        echoContent green " trojan://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-vision# ${email}\n"

        echoContent yellow " ---> Formatted plain text (Trojan+TCP+TLS_Vision)"
        echoContent green "Protocol type: Trojan, address: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: xtls, transmission method: tcp, flow: xtls-rprx-vision, account name: ${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
trojan://${id}@${currentHost}:${currentDefaultPort}?encryption=none&security=xtls&type=tcp&host=${currentHost}&headerType=none&sni=${currentHost}&flow=xtls-rprx-vision#${email}
EOF
        echoContent yellow " ---> QR code Trojan(Trojan+TCP+TLS_Vision)"
        echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F${id}%40${currentHost}%3A${currentDefaultPort}% 3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${currentHost}%3D${currentHost}%26headerType%3Dnone%26sni%3D${currentHost}%26flow%3Dxtls-rprx-vision%23${email}\ n"

    elif [[ "${type}" == "vmessws" ]]; then
        qrCodeBase64Default=$(echo -n "{\"port\":${currentDefaultPort},\"ps\":\"${email}\",\"tls\":\"tls\",\"id \":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\ "none\",\"path\":\"/${currentPath}vws\",\"net\":\"ws\",\"add\":\"${add}\",\ "allowInsecure\":0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}" | base64 -w 0)
        qrCodeBase64Default="${qrCodeBase64Default// /}"

        echoContent yellow " ---> Universal json(VMess+WS+TLS)"
        echoContent green " {\"port\":${currentDefaultPort},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\" ${id}\",\"aid\":0,\"v\":2,\"host\":\"${currentHost}\",\"type\":\"none\", \"path\":\"/${currentPath}vws\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\": 0,\"method\":\"none\",\"peer\":\"${currentHost}\",\"sni\":\"${currentHost}\"}\n"
        echoContent yellow " ---> Universal vmess (VMess+WS+TLS) link"
        echoContent green " vmess://${qrCodeBase64Default}\n"
        echoContent yellow " ---> QR code vmess(VMess+WS+TLS)"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vmess://${qrCodeBase64Default}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vmess
    server: ${add}
    port: ${currentDefaultPort}
    uuid: ${id}
    alterId: 0
    cipher: none
    udp: true
    tls: true
    client-fingerprint: chrome
    servername: ${currentHost}
    network: ws
    ws-opts:
      path: /${currentPath}vws
      headers:
        Host: ${currentHost}
EOF
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

    elif [[ "${type}" == "vlessws" ]]; then

        echoContent yellow " ---> Universal format (VLESS+WS+TLS)"
        echoContent green " vless://${id}@${add}:${currentDefaultPort}?encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&fp=chrome&path=/${currentPath}ws #${email}\n"

        echoContent yellow " ---> Formatted plain text (VLESS+WS+TLS)"
        echoContent green "Protocol type: VLESS, address: ${add}, disguised domain name/SNI: ${currentHost}, port: ${currentDefaultPort}, client-fingerprint: chrome, user ID: ${id}, security: tls, Transmission method: ws, path: /${currentPath}ws, account name: ${email}\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${add}:${currentDefaultPort}?encryption=none&security=tls&type=ws&host=${currentHost}&sni=${currentHost}&fp=chrome&path=/${currentPath}ws#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: ${add}
    port: ${currentDefaultPort}
    uuid: ${id}
    udp: true
    tls: true
    network: ws
    client-fingerprint: chrome
    servername: ${currentHost}
    ws-opts:
      path: /${currentPath}ws
      headers:
        Host: ${currentHost}
EOF

        echoContent yellow " ---> 二维码 VLESS(VLESS+WS+TLS)"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${currentDefaultPort}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dws%26host%3D${currentHost}%26fp%3Dchrome%26sni%3D${currentHost}%26path%3D%252f${currentPath}ws%23${email}"

    elif [[ "${type}" == "vlessgrpc" ]]; then

        echoContent yellow " ---> Universal format (VLESS+gRPC+TLS)"
        echoContent green " vless://${id}@${add}:${currentDefaultPort}?encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&fp=chrome&serviceName=${currentPath}grpc&alpn= h2&sni=${currentHost}#${email}\n"

        echoContent yellow " ---> Formatted plain text (VLESS+gRPC+TLS)"
        echoContent green "Protocol type: VLESS, address: ${add}, disguised domain name/SNI: ${currentHost}, port: ${currentDefaultPort}, user ID: ${id}, security: tls, transmission method: gRPC, alpn :h2, client-fingerprint: chrome, serviceName: ${currentPath}grpc, account name: ${email}\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@${add}:${currentDefaultPort}?encryption=none&security=tls&type=grpc&host=${currentHost}&path=${currentPath}grpc&serviceName=${currentPath}grpc&fp=chrome&alpn=h2&sni=${currentHost}#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: ${add}
    port: ${currentDefaultPort}
    uuid: ${id}
    udp: true
    tls: true
    network: grpc
    client-fingerprint: chrome
    servername: ${currentHost}
    grpc-opts:
      grpc-service-name: ${currentPath}grpc
EOF
        echoContent yellow " ---> QR code VLESS(VLESS+gRPC+TLS)"
        echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${currentDefaultPort}% 3Fencryption%3Dnone%26security%3Dtls%26type%3Dgrpc%26host%3D${currentHost}%26serviceName%3D${currentPath}grpc%26fp%3Dchrome%26path%3D${currentPath}grpc%26sni%3D${currentHost}% 26alpn%3Dh2%23${email}"

    elif [[ "${type}" == "trojan" ]]; then
        # URLEncode
        echoContent yellow " ---> Trojan(TLS)"
        echoContent green " trojan://${id}@${currentHost}:${currentDefaultPort}?peer=${currentHost}&fp=chrome&sni=${currentHost}&alpn=http/1.1#${currentHost}_Trojan\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
trojan://${id}@${currentHost}:${currentDefaultPort}?peer=${currentHost}&fp=chrome&sni=${currentHost}&alpn=http/1.1#${email}_Trojan
EOF

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: trojan
    server: ${currentHost}
    port: ${currentDefaultPort}
    password: ${id}
    client-fingerprint: chrome
    udp: true
    sni: ${currentHost}
EOF
        echoContent yellow " ---> QR code Trojan(TLS)"
        echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${currentHost}%3a${port}% 3fpeer%3d${currentHost}%26fp%3Dchrome%26sni%3d${currentHost}%26alpn%3Dhttp/1.1%23${email}\n"

    elif [[ "${type}" == "trojangrpc" ]]; then
        # URLEncode

        echoContent yellow " ---> Trojan gRPC(TLS)"
        echoContent green " trojan://${id}@${add}:${currentDefaultPort}?encryption=none&peer=${currentHost}&fp=chrome&security=tls&type=grpc&sni=${currentHost}&alpn=h2&path=${currentPath} trojangrpc&serviceName=${currentPath}trojangrpc#${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
trojan://${id}@${add}:${currentDefaultPort}?encryption=none&peer=${currentHost}&security=tls&type=grpc&fp=chrome&sni=${currentHost}&alpn=h2&path=${currentPath}trojangrpc&serviceName=${currentPath}trojangrpc#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    server: ${add}
    port: ${currentDefaultPort}
    type: trojan
    password: ${id}
    network: grpc
    sni: ${currentHost}
    udp: true
    grpc-opts:
      grpc-service-name: ${currentPath}trojangrpc
EOF
        echoContent yellow " ---> QR code Trojan gRPC(TLS)"
        echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${add}%3a${currentDefaultPort}% 3Fencryption%3Dnone%26fp%3Dchrome%26security%3Dtls%26peer%3d${currentHost}%26type%3Dgrpc%26sni%3d${currentHost}%26path%3D${currentPath}trojangrpc%26alpn%3Dh2%26serviceName%3D${ currentPath}trojangrpc%23${email}\n"

    elif [[ "${type}" == "hysteria" ]]; then
        echoContent yellow " ---> Hysteria(TLS)"

        echoContent green " hysteria2://${id}@${currentHost}:${hysteriaPort}?peer=${currentHost}&insecure=0&sni=${currentHost}&alpn=h3#${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
hysteria2://${id}@${currentHost}:${hysteriaPort}?peer=${currentHost}&insecure=0&sni=${currentHost}&alpn=h3#${email}
EOF
        echoContent yellow " ---> v2rayN(hysteria+TLS)"
        echo "{\"server\": \"$(getPublicIP 4):${hysteriaPort}\",\"socks5\": { \"listen\": \"127.0.0.1:7798\", \"timeout\": 300},\"auth\":\"${id}\",\"tls\":{\"sni\":\"${currentHost}\"}}" | jq

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: hysteria2
    server: ${currentHost}
    port: ${hysteriaPort}
    password: ${id}
    alpn:
        - h3
    sni: ${currentHost}
    up: "${hysteria2ClientUploadSpeed} Mbps"
    down: "${hysteria2ClientDownloadSpeed} Mbps"
EOF
        echoContent yellow " ---> QR code Hysteria2(TLS)"
        echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=hysteria2%3A%2F%2F${id}%40${currentHost}%3A${hysteriaPort}% 3Fpeer%3D${currentHost}%26insecure%3D0%26sni%3D${currentHost}%26alpn%3Dh3%23${email}\n"

    elif [[ "${type}" == "vlessReality" ]]; then
        echoContent yellow " ---> Universal format (VLESS+reality+uTLS+Vision)"
        echoContent green " vless://${id}@$(getPublicIP):${currentRealityPort}?encryption=none&security=reality&type=tcp&sni=${currentRealityServerNames}&fp=chrome&pbk=${currentRealityPublicKey}&sid=6ba85179e30d4fc2&flow=xtls-rprx- vision#${email}\n"

        echoContent yellow " ---> Formatted plain text (VLESS+reality+uTLS+Vision)"
        echoContent green "Protocol type: VLESS reality, address: $(getPublicIP), publicKey: ${currentRealityPublicKey}, shortId: 6ba85179e30d4fc2, serverNames: ${currentRealityServerNames}, port: ${currentRealityPort}, user ID: ${id}, transmission Method: tcp, account name: ${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@$(getPublicIP):${currentRealityPort}?encryption=none&security=reality&type=tcp&sni=${currentRealityServerNames}&fp=chrome&pbk=${currentRealityPublicKey}&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: $(getPublicIP)
    port: ${currentRealityPort}
    uuid: ${id}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: ${currentRealityServerNames}
    reality-opts:
      public-key: ${currentRealityPublicKey}
      short-id: 6ba85179e30d4fc2
    client-fingerprint: chrome
EOF
        echoContent yellow " ---> QR code VLESS(VLESS+reality+uTLS+Vision)"
        echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40$(getPublicIP)%3A${currentRealityPort}% 3Fencryption%3Dnone%26security%3Dreality%26type%3Dtcp%26sni%3D${currentRealityServerNames}%26fp%3Dchrome%26pbk%3D${currentRealityPublicKey}%26sid%3D6ba85179e30d4fc2%26flow%3Dxtls-rprx-vision%23${email }\ n"

    elif [[ "${type}" == "vlessRealityGRPC" ]]; then
        echoContent yellow " ---> Universal format (VLESS+reality+uTLS+gRPC)"
        echoContent green " vless://${id}@$(getPublicIP):${currentRealityPort}?encryption=none&security=reality&type=grpc&sni=${currentRealityServerNames}&fp=chrome&pbk=${currentRealityPublicKey}&sid=6ba85179e30d4fc2&path=grpc&serviceName=grpc# ${email}\n"

        echoContent yellow " ---> Formatted plain text (VLESS+reality+uTLS+gRPC)"
        echoContent green "Protocol type: VLESS reality, serviceName: grpc, address: $(getPublicIP), publicKey: ${currentRealityPublicKey}, shortId: 6ba85179e30d4fc2, serverNames: ${currentRealityServerNames}, port: ${currentRealityPort}, user ID: ${ id}, transmission method: gRPC, client-fingerprint: chrome, account name: ${email}\n"
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
vless://${id}@$(getPublicIP):${currentRealityPort}?encryption=none&security=reality&type=grpc&sni=${currentRealityServerNames}&fp=chrome&pbk=${currentRealityPublicKey}&sid=6ba85179e30d4fc2&path=grpc&serviceName=grpc#${email}
EOF
        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    type: vless
    server: $(getPublicIP)
    port: ${currentRealityPort}
    uuid: ${id}
    network: grpc
    tls: true
    udp: true
    servername: ${currentRealityServerNames}
    reality-opts:
      public-key: ${currentRealityPublicKey}
      short-id: 6ba85179e30d4fc2
    grpc-opts:
      grpc-service-name: "grpc"
    client-fingerprint: chrome
EOF
        echoContent yellow " ---> QR code VLESS(VLESS+reality+uTLS+gRPC)"
        echoContent green " https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40$(getPublicIP)%3A${currentRealityPort}% 3Fencryption%3Dnone%26security%3Dreality%26type%3Dgrpc%26sni%3D${currentRealityServerNames}%26fp%3Dchrome%26pbk%3D${currentRealityPublicKey}%26pbk%3D6ba85179e30d4fc2%26path%3Dgrpc%26serviceName%3Dgrpc%23$ {email}\ n"
    elif [[ "${type}" == "tuic" ]]; then
        local tuicUUID=
        tuicUUID=$(echo "${id}" | awk -F "[_]" '{print $1}')

        local tuicPassword=
        tuicPassword=$(echo "${id}" | awk -F "[_]" '{print $2}')

        if [[ -z "${email}" ]]; then
            echoContent red " ---> Failed to read configuration, please reinstall"
            exit 0
        fi

        echoContent yellow " ---> Formatted plain text (Tuic+TLS)"
        echoContent green "Protocol type: Tuic, address: ${currentHost}, port: ${tuicPort}, uuid: ${tuicUUID}, password: ${tuicPassword}, ​​congestion-controller:${tuicAlgorithm}, alpn: h3, account Name:${email}\n"

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/default/${user}"
tuic://${tuicUUID}:${tuicPassword}@${currentHost}:${tuicPort}?congestion_control=${tuicAlgorithm}&alpn=h3&sni=${currentHost}&udp_relay_mode=quic&allow_insecure=0#${email}
EOF
        echoContent yellow " ---> v2rayN(Tuic+TLS)"
        echo "{\"relay\": {\"server\": \"${currentHost}:${tuicPort}\",\"uuid\": \"${tuicUUID}\",\"password\": \"${tuicPassword}\",\"ip\": \"$(getPublicIP 4)\",\"congestion_control\": \"${tuicAlgorithm}\",\"alpn\": [\"h3\"]},\"local\": {\"server\": \"127.0.0.1:7798\"},\"log_level\": \"warn\"}" | jq

        cat <<EOF >>"/etc/v2ray-agent/subscribe_local/clashMeta/${user}"
  - name: "${email}"
    server: ${currentHost}
    type: tuic
    port: ${tuicPort}
    uuid: ${tuicUUID}
    password: ${tuicPassword}
    alpn:
     - h3
    congestion-controller: ${tuicAlgorithm}
    disable-sni: true
    reduce-rtt: true
    sni: ${email}
EOF
        echoContent yellow "\n ---> QR code Tuic"
        echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=tuic%3A%2F%2F${tuicUUID}%3A${tuicPassword}%40${currentHost}%3A${tuicPort}%3Fcongestion_control%3D${tuicAlgorithm}%26alpn%3Dh3%26sni%3D${currentHost}%26udp_relay_mode%3Dquic%26allow_insecure%3D0%23${email}\n"
    fi

}


showAccounts() {
    readInstallType
    readInstallProtocolType
    readConfigHostPathUUID
    readSingBoxConfig
    readXrayCoreRealityConfig

    echo
    echoContent skyBlue "\nProgress $1/${totalProgress}: account"
    local show
    # VLESS TCP
    if echo "${currentInstallProtocolType}" | grep -q trojan; then
        echoContent skyBlue "====================== Trojan TCP TLS_Vision[Not recommended] =================== ===\n"
        jq .inbounds[0].settings.clients ${configPath}02_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)
            echoContent skyBlue "\n --->Account:${email}"
            defaultBase64Code trojanTCPXTLS "${email}" "$(echo "${user}" | jq -r .password)"
        done

    elif echo ${currentInstallProtocolType} | grep -q 0; then
        show=1
        echoContent skyBlue "============================= VLESS TCP TLS_Vision ==============================\n"
        jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)

            echoContent skyBlue "\n --->Account:${email}"
            echo
            defaultBase64Code vlesstcp "${email}" "$(echo "${user}" | jq -r .id)"
        done
    fi

    # VLESS WS
    if echo ${currentInstallProtocolType} | grep -q 1; then
        echoContent skyBlue "\n================================ VLESS WS TLS [CDN only not recommended] ==== ============================\n"

        jq .inbounds[0].settings.clients ${configPath}03_VLESS_WS_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)

            echoContent skyBlue "\n --->Account:${email}"
            echo
            local path="${currentPath}ws"
            local count=
            while read -r line; do
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vlessws "${email}${count}" "$(echo "${user}" | jq -r .id)" "${line}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentAdd}" | tr ',' '\n')

        done
    fi

    # VLESS grpc
    if echo ${currentInstallProtocolType} | grep -q 5; then
        echoContent skyBlue "\n================================ VLESS gRPC TLS [CDN only not recommended] ===== ==========================\n"
        jq .inbounds[0].settings.clients ${configPath}06_VLESS_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do

            local email=
            email=$(echo "${user}" | jq -r .email)

            echoContent skyBlue "\n --->Account:${email}"
            echo
            local count=
            while read -r line; do
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vlessgrpc "${email}${count}" "$(echo "${user}" | jq -r .id)" "${line}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentAdd}" | tr ',' '\n')

        done
    fi

    # VMess WS
    if echo ${currentInstallProtocolType} | grep -q 3; then
        echoContent skyBlue "\n================================ VMess WS TLS [CDN only not recommended] ==== ============================\n"
        local path="${currentPath}vws"
        if [[ ${coreInstallType} == "1" ]]; then
            path="${currentPath}vws"
        fi
        jq .inbounds[0].settings.clients ${configPath}05_VMess_WS_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)

            echoContent skyBlue "\n --->Account:${email}"
            echo
            local count=
            while read -r line; do
                if [[ -n "${line}" ]]; then
                    defaultBase64Code vmessws "${email}${count}" "$(echo "${user}" | jq -r .id)" "${line}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentAdd}" | tr ',' '\n')
        done
    fi

    # trojan tcp
    if echo ${currentInstallProtocolType} | grep -q 4; then
        echoContent skyBlue "\n================================== Trojan TLS [Not recommended] ===== =============================\n"
        jq .inbounds[0].settings.clients ${configPath}04_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)
            echoContent skyBlue "\n --->Account:${email}"

            defaultBase64Code trojan "${email}" "$(echo "${user}" | jq -r .password)"
        done
    fi

    if echo ${currentInstallProtocolType} | grep -q 2; then
        echoContent skyBlue "\n================================ Trojan gRPC TLS [CDN only not recommended] ==== ============================\n"
        jq .inbounds[0].settings.clients ${configPath}04_trojan_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)

            echoContent skyBlue "\n --->Account:${email}"
            echo
            local count=
            while read -r line; do
                if [[ -n "${line}" ]]; then
                    defaultBase64Code trojangrpc "${email}${count}" "$(echo "${user}" | jq -r .password)" "${line}"
                    count=$((count + 1))
                fi
            done < <(echo "${currentAdd}" | tr ',' '\n')

        done
    fi
    if echo ${currentInstallProtocolType} | grep -q 6; then
        echoContent skyBlue "\n================================ Hysteria2 TLS [Recommended] ======== ========================\n"
        jq -r -c '.inbounds[]|select(.type=="hysteria2")|.users[]' "${singBoxConfigPath}config.json" | while read -r user; do
            echoContent skyBlue "\n ---> Account:$(echo "${user}" | jq -r .name)"
            echo
            defaultBase64Code hysteria "$(echo "${user}" | jq -r .name)" "$(echo "${user}" | jq -r .password)"
        done

    fi

    # VLESS reality vision
    if echo ${currentInstallProtocolType} | grep -q 7; then
        show=1
        echoContent skyBlue "============================== VLESS reality_vision [Recommended] ============= =================\n"
        jq .inbounds[0].settings.clients ${configPath}07_VLESS_vision_reality_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)

            echoContent skyBlue "\n --->Account:${email}"
            echo
            defaultBase64Code vlessReality "${email}" "$(echo "${user}" | jq -r .id)"
        done
    fi

    # VLESS reality
    if echo ${currentInstallProtocolType} | grep -q 8; then
        show=1
        echoContent skyBlue "============================== VLESS reality_gRPC [Recommended] ============ ===================\n"
        jq .inbounds[0].settings.clients ${configPath}08_VLESS_reality_fallback_grpc_inbounds.json | jq -c '.[]' | while read -r user; do
            local email=
            email=$(echo "${user}" | jq -r .email)

            echoContent skyBlue "\n --->Account:${email}"
            echo
            defaultBase64Code vlessRealityGRPC "${email}" "$(echo "${user}" | jq -r .id)"
        done
    fi
    # tuic
    if echo ${currentInstallProtocolType} | grep -q 9; then
        echoContent skyBlue "\n================================ Tuic TLS [Recommended] ======== ========================\n"
        jq -r -c '.inbounds[]|select(.type=="tuic")|.users[]' "${singBoxConfigPath}config.json" | while read -r user; do
            echoContent skyBlue "\n ---> Account:$(echo "${user}" | jq -r .name)"
            echo
            defaultBase64Code tuic "$(echo "${user}" | jq -r .name)" "$(echo "${user}" | jq -r .uuid)_$(echo "${user}" | jq - r .password)"
        done

    fi

    if [[ -z ${show} ]]; then
        echoContent red " ---> not installed"
    fi
}

removeNginx302() {
    local count=
    grep -n "return 302" <"${nginxConfigPath}alone.conf" | while read -r line; do

        if ! echo "${line}" | grep -q "request_uri"; then
            local removeIndex=
            removeIndex=$(echo "${line}" | awk -F "[:]" '{print $1}')
            removeIndex=$((removeIndex + count))
            sed -i "${removeIndex}d" ${nginxConfigPath}alone.conf
            count=$((count - 1))
        fi
    done
}


checkNginx302() {
    local domain302Status=
    domain302Status=$(curl -s "https://${currentHost}:${currentPort}")
    if echo "${domain302Status}" | grep -q "302"; then
        local domain302Result=
        domain302Result=$(curl -L -s "https://${currentHost}:${currentPort}")
        if [[ -n "${domain302Result}" ]]; then
            echoContent green " ---> 302 redirection set up successfully"
            exit 0
        fi
    fi
    echoContent red " ---> 302 redirection setting failed, please double check whether it is the same as the example"
    backupNginxConfig restoreBackup
}


backupNginxConfig() {
    if [[ "$1" == "backup" ]]; then
        cp ${nginxConfigPath}alone.conf /etc/v2ray-agent/alone_backup.conf
        echoContent green " ---> nginx configuration file backup successful"
    fi

    if [[ "$1" == "restoreBackup" ]] && [[ -f "/etc/v2ray-agent/alone_backup.conf" ]]; then
        cp /etc/v2ray-agent/alone_backup.conf ${nginxConfigPath}alone.conf
        echoContent green " ---> nginx configuration file restoration backup successful"
        rm /etc/v2ray-agent/alone_backup.conf
    fi

}


addNginx302() {

    local count=1
    grep -n "location / {" <"${nginxConfigPath}alone.conf" | while read -r line; do
        if [[ -n "${line}" ]]; then
            local insertIndex=
            insertIndex="$(echo "${line}" | awk -F "[:]" '{print $1}')"
            insertIndex=$((insertIndex + count))
            sed "${insertIndex}i return 302 '$1';" ${nginxConfigPath}alone.conf >${nginxConfigPath}tmpfile && mv ${nginxConfigPath}tmpfile ${nginxConfigPath}alone.conf
            count=$((count + 1))
        else
            echoContent red " ---> 302 Add failed"
            backupNginxConfig restoreBackup
        fi

    done
}


updateNginxBlog() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Change disguise site"

    if ! echo "${currentInstallProtocolType}" | grep -q "0" || [[ -z "${coreInstallType}" ]]; then
        echoContent red "\n ---> Due to environmental dependencies, please install Xray-core's VLESS_TCP_TLS_Vision first"
        exit 0
    fi
    echoContent red "================================================== ==============="
    echoContent yellow "# If you need to customize, please manually copy the template file to ${nginxStaticPath} \n"
    echoContent yellow "1. Newbie guide"
    echoContent yellow "2.Game website"
    echoContent yellow "3.Personal blog 01"
    echoContent yellow "4.Enterprise Station"
    echoContent yellow "5. Unlock encrypted music file template [https://github.com/ix64/unlock-music]"
    echoContent yellow "6.mikutap[https://github.com/HFIProgramming/mikutap]"
    echoContent yellow "7.Enterprise Station 02"
    echoContent yellow "8.Personal blog 02"
    echoContent yellow "9.404 automatically jumps to baidu"
    echoContent yellow "10.302 redirect website"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" selectInstallNginxBlogType

    if [[ "${selectInstallNginxBlogType}" == "10" ]]; then
        echoContent red "\n================================================ ================="
        echoContent yellow "Redirect has a higher priority. If you change the camouflage site after configuring 302, the camouflage site under the root route will not work."
        echoContent yellow "If you want to disguise the site to achieve the function, you need to delete the 302 redirect configuration\n"
        echoContent yellow "1.Add"
        echoContent yellow "2.Delete"
        echoContent red "================================================== ==============="
        read -r -p "Please select:" redirectStatus

        if [[ "${redirectStatus}" == "1" ]]; then
            backupNginxConfig backup
            read -r -p "Please enter the domain name to be redirected, for example https://www.baidu.com:" redirectDomain
            removeNginx302
            addNginx302 "${redirectDomain}"
            handleNginx stop
            handleNginx start
            if [[ -z $(pgrep -f "nginx") ]]; then
                backupNginxConfig restoreBackup
                handleNginx start
                exit 0
            fi
            checkNginx302
            exit 0
        fi
        if [[ "${redirectStatus}" == "2" ]]; then
            removeNginx302
            echoContent green " ---> Removed 302 redirect successfully"
            exit 0
        fi
    fi
    if [[ "${selectInstallNginxBlogType}" =~ ^[1-9]$ ]]; then
        rm -rf "${nginxStaticPath}"

        wget -q -P "${nginxStaticPath}" "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip" >/dev/ null

        unzip -o "${nginxStaticPath}html${selectInstallNginxBlogType}.zip" -d "${nginxStaticPath}" >/dev/null
        rm -f "${nginxStaticPath}html${selectInstallNginxBlogType}.zip*"
        echoContent green " ---> Pseudo site replaced successfully"
    else
        echoContent red " ---> Wrong selection, please select again"
        updateNginxBlog
    fi
}


addCorePort() {
    readHysteriaConfig
    echoContent skyBlue "\nFunction 1/${totalProgress}: Add new port"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Notes\n"
    echoContent yellow "Support batch addition"
    echoContent yellow "Does not affect the use of the default port"
    echoContent yellow "When viewing accounts, only accounts with default ports will be displayed"
    echoContent yellow "No special characters allowed, pay attention to the comma format"
    echoContent yellow "If hysteria is already installed, a new hysteria port will be installed at the same time"
    echoContent yellow "Input example:2053,2083,2087\n"

    echoContent yellow "1. Check the added port"
    echoContent yellow "2.Add port"
    echoContent yellow "3. Delete port"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" selectNewPortType
    if [[ "${selectNewPortType}" == "1" ]]; then
        find ${configPath} -name "*dokodemodoor*" | grep -v "hysteria" | awk -F "[c][o][n][f][/]" '{print $2}' | awk -F "[_]" '{print $4}' | awk -F "[.]" '{print ""NR""":"$1}'
        exit 0
    elif [[ "${selectNewPortType}" == "2" ]]; then
        read -r -p "Please enter the port number:" newPort
        read -r -p "Please enter the default port number. The subscription port and node port will be changed at the same time. [Enter] Default 443:" defaultPort

        if [[ -n "${defaultPort}" ]]; then
            rm -rf "$(find ${configPath}* | grep "default")"
        fi

        if [[ -n "${newPort}" ]]; then

            while read -r port; do
                rm -rf "$(find ${configPath}* | grep "${port}")"

                local fileName=
                local hysteriaFileName=
                if [[ -n "${defaultPort}" && "${port}" == "${defaultPort}" ]]; then
                    fileName="${configPath}02_dokodemodoor_inbounds_${port}_default.json"
                else
                    fileName="${configPath}02_dokodemodoor_inbounds_${port}.json"
                fi

                if [[ -n ${hysteriaPort} ]]; then
                    hysteriaFileName="${configPath}02_dokodemodoor_inbounds_hysteria_${port}.json"
                fi

                allowPort "${port}"
                allowPort "${port}" "udp"

                local settingsPort=443
                if [[ -n "${customPort}" ]]; then
                    settingsPort=${customPort}
                fi

                if [[ -n ${hysteriaFileName} ]]; then
                    cat <<EOF >"${hysteriaFileName}"
{
  "inbounds": [
	{
	  "listen": "0.0.0.0",
	  "port": ${port},
	  "protocol": "dokodemo-door",
	  "settings": {
		"address": "127.0.0.1",
		"port": ${hysteriaPort},
		"network": "udp",
		"followRedirect": false
	  },
	  "tag": "dokodemo-door-newPort-hysteria-${port}"
	}
  ]
}
EOF
                fi
                cat <<EOF >"${fileName}"
{
  "inbounds": [
	{
	  "listen": "0.0.0.0",
	  "port": ${port},
	  "protocol": "dokodemo-door",
	  "settings": {
		"address": "127.0.0.1",
		"port": ${settingsPort},
		"network": "tcp",
		"followRedirect": false
	  },
	  "tag": "dokodemo-door-newPort-${port}"
	}
  ]
}
EOF
            done < <(echo "${newPort}" | tr ',' '\n')

            echoContent green " ---> 添加成功"
            reloadCore
            addCorePort
        fi
    elif [[ "${selectNewPortType}" == "3" ]]; then
        find ${configPath} -name "*dokodemodoor*" | grep -v "hysteria" | awk -F "[c][o][n][f][/]" '{print $2}' | awk -F "[_]" '{print $4}' | awk -F "[.]" '{print ""NR""":"$1}'
        read -r -p "Please enter the port number to be deleted:" portIndex
        local dokoConfig
        dokoConfig=$(find ${configPath} -name "*dokodemodoor*" | grep -v "hysteria" | awk -F "[c][o][n][f][/]" '{print $2}' | awk -F "[_]" '{print $4}' | awk -F "[.]" '{print ""NR""":"$1}' | grep "${portIndex}:")
        if [[ -n "${dokoConfig}" ]]; then
            rm "${configPath}02_dokodemodoor_inbounds_$(echo "${dokoConfig}" | awk -F "[:]" '{print $2}').json"
            local hysteriaDokodemodoorFilePath=

            hysteriaDokodemodoorFilePath="${configPath}02_dokodemodoor_inbounds_hysteria_$(echo "${dokoConfig}" | awk -F "[:]" '{print $2}').json"
            if [[ -f "${hysteriaDokodemodoorFilePath}" ]]; then
                rm "${hysteriaDokodemodoorFilePath}"
            fi

            reloadCore
            addCorePort
        else
            echoContent yellow "\n ---> The number entered is wrong, please choose again"
            addCorePort
        fi
    fi
}



unInstall() {
    read -r -p "Are you sure you want to uninstall the installation content? [y/n]:" unInstallStatus
    if [[ "${unInstallStatus}" != "y" ]]; then
        echoContent green " ---> Give up uninstalling"
        menu
        exit 0
    fi
    echoContent yellow " ---> The script will not delete acme related configurations. To delete, please execute it manually [rm -rf /root/.acme.sh]"
    handleNginx stop
    if [[ -z $(pgrep -f "nginx") ]]; then
        echoContent green " ---> Stop Nginx successfully"
    fi
    if [[ "${coreInstallType}" == "1" ]]; then
        handleXray stop
        rm -rf /etc/systemd/system/xray.service
        echoContent green " ---> Delete Xray and it will start automatically after booting"
    fi

    if [[ -n "${hysteriaConfigPath}" ]]; then
        handleHysteria stop
        rm -rf /etc/systemd/system/hysteria.service
        echoContent green " ---> Delete Hysteria and it will start automatically after booting"
    fi

    if [[ -n "${tuicConfigPath}" ]]; then
        handleTuic stop
        rm -rf /etc/systemd/system/tuic.service
        echoContent green " ---> Delete Tuic and start automatically after booting"
    fi

    if [[ -n "${singBoxConfigPath}" ]]; then
        handleSingBox stop
        rm -rf /etc/systemd/system/sing-box.service
        echoContent green " ---> Delete sing-box and it will start automatically after booting"
    fi

    rm -rf /etc/v2ray-agent
    rm -rf ${nginxConfigPath}alone.conf
    rm -rf ${nginxConfigPath}checkPortOpen.conf >/dev/null 2>&1


    if [[ -d "${nginxStaticPath}" && -f "${nginxStaticPath}/check" ]]; then
        rm -rf "${nginxStaticPath}"
        echoContent green " ---> Deletion of fake website completed"
    fi

    rm -rf /usr/bin/vasma
    rm -rf /usr/sbin/vasma
    echoContent green " ---> Uninstallation of shortcut completed"
    echoContent green " ---> Uninstall v2ray-agent script completed"
}


updateV2RayCDN() {

    echoContent skyBlue "\nProgress $1/${totalProgress}: Modify CDN node"

    if [[ -n "${currentAdd}" ]]; then
        echoContent red "================================================== ==============="
        echoContent yellow "1.CNAME www.digitalocean.com"
        echoContent yellow "2.CNAME who.int"
        echoContent yellow "3.CNAME blog.hostmonit.com"
        echoContent yellow "4. Manual input [can enter multiple, such as: 1.1.1.1,1.1.2.2, cloudflare.com separated by commas]"
        echoContent yellow "5. Remove CDN node"
        echoContent red "================================================== ==============="
        read -r -p "Please select:" selectCDNType
        case ${selectCDNType} in
        1)
            setDomain="www.digitalocean.com"
            ;;
        2)
            setDomain="who.int"
            ;;
        3)
            setDomain="blog.hostmonit.com"
            ;;
        4)
            read -r -p "Please enter the CDN IP or domain name you want to customize:" setDomain
            ;;
        5)
            setDomain=${currentHost}
            ;;
        esac

        if [[ -n "${setDomain}" ]]; then
            local cdnAddressResult=
            cdnAddressResult=$(jq -r ".inbounds[0].add = \"${setDomain}\" " ${configPath}${frontingType}.json)
            echo "${cdnAddressResult}" | jq . >${configPath}${frontingType}.json

        echoContent green " ---> CDN modified successfully"
        fi
    else
        echoContent red " ---> Available types are not installed"
    fi
}


manageUser() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: multi-user management"
    echoContent skyBlue "------------------------------------------------- ------"
    echoContent yellow "1.Add user"
    echoContent yellow "2. Delete user"
    echoContent skyBlue "------------------------------------------------- ------"
    read -r -p "Please select:" manageUserType
    if [[ "${manageUserType}" == "1" ]]; then
        addUser
    elif [[ "${manageUserType}" == "2" ]]; then
        removeUser
    else
        echoContent red " ---> Wrong selection"
    fi
}


customUUID() {
    read -r -p "Please enter a legal UUID, [Enter] random UUID:" currentCustomUUID
    echo
    if [[ -z "${currentCustomUUID}" ]]; then
        currentCustomUUID=$(${ctlPath} uuid)
        echoContent yellow "uuid：${currentCustomUUID}\n"

    else
        jq -r -c '.inbounds[0].settings.clients[].id' ${configPath}${frontingType}.json | while read -r line; do
            if [[ "${line}" == "${currentCustomUUID}" ]]; then
                echo >/tmp/v2ray-agent
            fi
        done
        if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
            echoContent red " ---> UUID cannot be repeated"
            rm /tmp/v2ray-agent
            exit 0
        fi
    fi
}


customUserEmail() {
    read -r -p "Please enter a valid email, [Enter] random email:" currentCustomEmail
    echo
    if [[ -z "${currentCustomEmail}" ]]; then
        currentCustomEmail="${currentCustomUUID}"
        echoContent yellow "email: ${currentCustomEmail}\n"
    else
        local defaultConfig=${frontingType}

        if echo "${currentInstallProtocolType}" | grep -q "7" && [[ -z "${frontingType}" ]]; then
            defaultConfig="07_VLESS_vision_reality_inbounds"
        fi

        jq -r -c '.inbounds[0].settings.clients[].email' ${configPath}${defaultConfig}.json | while read -r line; do
            if [[ "${line}" == "${currentCustomEmail}" ]]; then
                echo >/tmp/v2ray-agent
            fi
        done
        if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
            echoContent red " ---> email cannot be repeated"
            rm /tmp/v2ray-agent
            exit 0
        fi
    fi

}


addUserXray() {
    read -r -p "Please enter the number of users to add:" userNum
    echo
    if [[ -z ${userNum} || ${userNum} -le 0 ]]; then
        echoContent red " ---> 输入有误，请重新输入"
        exit 0
    fi
    while [[ ${userNum} -gt 0 ]]; do
        readConfigHostPathUUID
        local users=
        ((userNum--)) || true

        customUUID
        customUserEmail

        uuid=${currentCustomUUID}
        email=${currentCustomEmail}

        # VLESS TCP
        if echo "${currentInstallProtocolType}" | grep -q 0; then
            local clients=
            clients=$(initXrayClients 0 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].settings.clients = ${clients}" ${configPath}${frontingType}.json)
            echo "${clients}" | jq . >${configPath}${frontingType}.json
        fi

        # VLESS WS
        if echo "${currentInstallProtocolType}" | grep -q 1; then
            local clients=
            clients=$(initXrayClients 1 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].settings.clients = ${clients}" ${configPath}03_VLESS_WS_inbounds.json)
            echo "${clients}" | jq . >${configPath}03_VLESS_WS_inbounds.json
        fi

        # trojan grpc
        if echo "${currentInstallProtocolType}" | grep -q 2; then
            local clients=
            clients=$(initXrayClients 2 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].settings.clients = ${clients}" ${configPath}04_trojan_gRPC_inbounds.json)
            echo "${clients}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
        fi
        # VMess WS
        if echo "${currentInstallProtocolType}" | grep -q 3; then
            local clients=
            clients=$(initXrayClients 3 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].settings.clients = ${clients}" ${configPath}05_VMess_WS_inbounds.json)
            echo "${clients}" | jq . >${configPath}05_VMess_WS_inbounds.json
        fi

        # trojan tcp
        if echo "${currentInstallProtocolType}" | grep -q 4; then
            local clients=
            clients=$(initXrayClients 4 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].settings.clients = ${clients}" ${configPath}04_trojan_TCP_inbounds.json)
            echo "${clients}" | jq . >${configPath}04_trojan_TCP_inbounds.json
        fi

        # vless grpc
        if echo "${currentInstallProtocolType}" | grep -q 5; then
            local clients=
            clients=$(initXrayClients 5 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].settings.clients = ${clients}" ${configPath}06_VLESS_gRPC_inbounds.json)
            echo "${clients}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
        fi

        # vless reality vision
        if echo "${currentInstallProtocolType}" | grep -q 7; then
            local clients=
            clients=$(initXrayClients 7 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].settings.clients = ${clients}" ${configPath}07_VLESS_vision_reality_inbounds.json)
            echo "${clients}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
        fi

        # vless reality grpc
        if echo "${currentInstallProtocolType}" | grep -q 8; then
            local clients=
            clients=$(initXrayClients 8 "${uuid}" "${email}")
            clients=$(jq -r ".inbounds[0].settings.clients = ${clients}" ${configPath}08_VLESS_reality_fallback_grpc_inbounds.json)
            echo "${clients}" | jq . >${configPath}08_VLESS_reality_fallback_grpc_inbounds.json
        fi

        # hysteria2
        if echo ${currentInstallProtocolType} | grep -q 6; then
            local clients=
            clients=$(initXrayClients 6 "${uuid}" "${email}")

            clients=$(jq -r ".inbounds[0].users = ${clients}" "${singBoxConfigPath}config/hysteria2.json")
            echo "${clients}" | jq . >"${singBoxConfigPath}config/hysteria2.json"
        fi

        # tuic
        if echo ${currentInstallProtocolType} | grep -q 9; then
            local clients=
            clients=$(initXrayClients 9 "${uuid}" "${email}")

            clients=$(jq -r ".inbounds[0].users = ${clients}" "${singBoxConfigPath}config/tuic.json")

            echo "${clients}" | jq . >"${singBoxConfigPath}config/tuic.json"
        fi
    done
    reloadCore
    echoContent green " ---> Adding completed"
    manageAccount 1
}


addUser() {

    echoContent yellow "After adding a new user, you need to check the subscription again"
    read -r -p "Please enter the number of users to add:" userNum
    echo
    if [[ -z ${userNum} || ${userNum} -le 0 ]]; then
        echoContent red " ---> Incorrect input, please re-enter"
        exit 0
    fi

    if [[ "${userNum}" == "1" ]]; then
        customUUID
        customUserEmail
    fi

    while [[ ${userNum} -gt 0 ]]; do
        local users=
        ((userNum--)) || true
        if [[ -n "${currentCustomUUID}" ]]; then
            uuid=${currentCustomUUID}
        else
            uuid=$(${ctlPath} uuid)
        fi

        if [[ -n "${currentCustomEmail}" ]]; then
            email=${currentCustomEmail}_${uuid}
        else
            email=${currentHost}_${uuid}
        fi

        users="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"${email}\",\"alterId\":0}"

        if [[ "${coreInstallType}" == "2" ]]; then
            users="{\"id\":\"${uuid}\",\"email\":\"${email}\",\"alterId\":0}"
        fi

        if echo ${currentInstallProtocolType} | grep -q 0; then
            local vlessUsers="${users//\,\"alterId\":0/}"
            vlessUsers="${users//${email}/${email}_VLESS_TCP}"
            local vlessTcpResult
            vlessTcpResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}${frontingType}.json)
            echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
        fi

        if echo ${currentInstallProtocolType} | grep -q trojan; then
            local trojanXTLSUsers="${users//\,\"alterId\":0/}"
            trojanXTLSUsers="${trojanXTLSUsers//${email}/${email}_Trojan_TCP}"
            trojanXTLSUsers=${trojanXTLSUsers//"id"/"password"}

            local trojanXTLSResult
            trojanXTLSResult=$(jq -r ".inbounds[0].settings.clients += [${trojanXTLSUsers}]" ${configPath}${frontingType}.json)
            echo "${trojanXTLSResult}" | jq . >${configPath}${frontingType}.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 1; then
            local vlessUsers="${users//\,\"alterId\":0/}"
            vlessUsers="${vlessUsers//${email}/${email}_VLESS_TCP}"
            vlessUsers="${vlessUsers//\"flow\":\"xtls-rprx-vision\"\,/}"
            local vlessWsResult
            vlessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}03_VLESS_WS_inbounds.json)
            echo "${vlessWsResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 2; then
            local trojangRPCUsers="${users//\"flow\":\"xtls-rprx-vision\"\,/}"
            trojangRPCUsers="${trojangRPCUsers//${email}/${email}_Trojan_gRPC}"
            trojangRPCUsers="${trojangRPCUsers//\,\"alterId\":0/}"
            trojangRPCUsers=${trojangRPCUsers//"id"/"password"}

            local trojangRPCResult
            trojangRPCResult=$(jq -r ".inbounds[0].settings.clients += [${trojangRPCUsers}]" ${configPath}04_trojan_gRPC_inbounds.json)
            echo "${trojangRPCResult}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 3; then
            local vmessUsers="${users//\"flow\":\"xtls-rprx-vision\"\,/}"
            vmessUsers="${vmessUsers//${email}/${email}_VMess_TCP}"
            local vmessWsResult
            vmessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vmessUsers}]" ${configPath}05_VMess_WS_inbounds.json)
            echo "${vmessWsResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 5; then
            local vlessGRPCUsers="${users//\"flow\":\"xtls-rprx-vision\"\,/}"
            vlessGRPCUsers="${vlessGRPCUsers//\,\"alterId\":0/}"
            vlessGRPCUsers="${vlessGRPCUsers//${email}/${email}_VLESS_gRPC}"
            local vlessGRPCResult
            vlessGRPCResult=$(jq -r ".inbounds[0].settings.clients += [${vlessGRPCUsers}]" ${configPath}06_VLESS_gRPC_inbounds.json)
            echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 4; then
            local trojanUsers="${users//\"flow\":\"xtls-rprx-vision\"\,/}"
            trojanUsers="${trojanUsers//id/password}"
            trojanUsers="${trojanUsers//\,\"alterId\":0/}"
            trojanUsers="${trojanUsers//${email}/${email}_Trojan_TCP}"

            local trojanTCPResult
            trojanTCPResult=$(jq -r ".inbounds[0].settings.clients += [${trojanUsers}]" ${configPath}04_trojan_TCP_inbounds.json)
            echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
        fi
        # hysteria2
        if echo ${currentInstallProtocolType} | grep -q 6; then
            local hysteriaResult
            users="{\"password\":\"${uuid}\",\"name\":\"${email}_singbox_hysteria2\"}"
            hysteriaResult=$(jq -r ".inbounds[0].users += [${users}]" "${singBoxConfigPath}config/hysteria2.json")
            echo "${hysteriaResult}" | jq . >"${hysteriaConfigPath}config/hysteria2.json"
        fi

        # tuic
        if echo ${currentInstallProtocolType} | grep -q 9; then
            local hysteriaResult
            users="{\"password\":\"${uuid}\",\"uuid\":\"${uuid}\",\"name\":\"${email}_singbox_tuic\"}"
            hysteriaResult=$(jq -r ".inbounds[0].users += [\"${uuid}\"]" "${hysteriaConfigPath}config/tuic.json")
            echo "${hysteriaResult}" | jq . >"${hysteriaConfigPath}config/tuic.json"
        fi
    done

    reloadCore
    echoContent green " ---> Adding completed"
    manageAccount 1
}


removeUser() {
    local uuid=
    if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan; then
        jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
        read -r -p "Please select the user number to delete [only supports single deletion]:" delUserIndex
        if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${delUserIndex} ]]; then
            echoContent red " ---> Wrong selection"
        else
            delUserIndex=$((delUserIndex - 1))
            local vlessTcpResult
            uuid=$(jq -r ".inbounds[0].settings.clients[${delUserIndex}].id" ${configPath}${frontingType}.json)
            vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}${frontingType}.json)
            echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
        fi
    elif [[ -n "${realityStatus}" ]]; then
        jq -r -c .inbounds[0].settings.clients[].email ${configPath}07_VLESS_vision_reality_inbounds.json | awk '{print NR""":"$0}'
        read -r -p "Please select the user number to delete [only supports single deletion]:" delUserIndex
        if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}07_VLESS_vision_reality_inbounds.json) -lt ${delUserIndex} ]]; then
            echoContent red " ---> Wrong selection"
        else
            delUserIndex=$((delUserIndex - 1))
            local vlessRealityResult
            uuid=$(jq -r ".inbounds[0].settings.clients[${delUserIndex}].id" ${configPath}${frontingType}.json)
            vlessRealityResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}07_VLESS_vision_reality_inbounds.json)
            echo "${vlessRealityResult}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
        fi
    fi

    if [[ -n "${delUserIndex}" ]]; then
        if echo ${currentInstallProtocolType} | grep -q 1; then
            local vlessWSResult
            vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
            echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 2; then
            local trojangRPCUsers
            trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
            echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 3; then
            local vmessWSResult
            vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
            echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 5; then
            local vlessGRPCResult
            vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
            echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 4; then
            local trojanTCPResult
            trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
            echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 7; then
            local vlessRealityResult
            vlessRealityResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}07_VLESS_vision_reality_inbounds.json)
            echo "${vlessRealityResult}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
        fi
        if echo ${currentInstallProtocolType} | grep -q 8; then
            local vlessRealityGRPCResult
            vlessRealityGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}08_VLESS_reality_fallback_grpc_inbounds.json)
            echo "${vlessRealityGRPCResult}" | jq . >${configPath}08_VLESS_reality_fallback_grpc_inbounds.json
        fi

        if echo ${currentInstallProtocolType} | grep -q 6; then
            local hysteriaResult
            hysteriaResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}config/hysteria2.json")
            echo "${hysteriaResult}" | jq . >"${singBoxConfigPath}config/hysteria2.json"
        fi
        if echo ${currentInstallProtocolType} | grep -q 9; then
            local tuicResult
            tuicResult=$(jq -r 'del(.inbounds[0].users['${delUserIndex}'])' "${singBoxConfigPath}config/tuic.json")
            echo "${tuicResult}" | jq . >"${singBoxConfigPath}config/tuic.json"
        fi
        reloadCore
    fi
    manageAccount 1
}


updateV2RayAgent() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Update v2ray-agent script"
    rm -rf /etc/v2ray-agent/install.sh
    wget -c -q "${wgetShowProgressStatus}" -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
    sudo chmod 700 /etc/v2ray-agent/install.sh
    local version
    version=$(grep '当前版本：v' "/etc/v2ray-agent/install.sh" | awk -F "[v]" '{print $2}' | tail -n +2 | head -n 1 | awk -F "[\"]" '{print $1}')
    echoContent green "\n ---> Update completed"
    echoContent yellow " ---> Please manually execute [vasma] to open the script"
    echoContent green " ---> Current version: ${version}\n"
    echoContent yellow "If the update fails, please manually execute the following command\n"
    echoContent skyBlue "wget ​​-P /root -N --no-check-certificate https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh && chmod 700 /root/install.sh && /root/install.sh"
    echo
    exit 0
}


handleFirewall() {
    if systemctl status ufw 2>/dev/null | grep -q "active (exited)" && [[ "$1" == "stop" ]]; then
        systemctl stop ufw >/dev/null 2>&1
        systemctl disable ufw >/dev/null 2>&1
        echoContent green " ---> ufw closed successfully"

    fi

    if systemctl status firewalld 2>/dev/null | grep -q "active (running)" && [[ "$1" == "stop" ]]; then
        systemctl stop firewalld >/dev/null 2>&1
        systemctl disable firewalld >/dev/null 2>&1
        echoContent green " ---> firewalld closed successfully"
    fi
}


bbrInstall() {
    echoContent red "\n================================================ ================="
    echoContent green "The mature works of [ylx2016] used for BBR and DD scripts, the address [https://github.com/ylx2016/Linux-NetSpeed], please be familiar with it"
    echoContent yellow "1. Installation script [recommended original BBR+FQ]"
    echoContent yellow "2.Return to the home directory"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" installBBRStatus
    if [[ "${installBBRStatus}" == "1" ]]; then
        wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
    else
        menu
    fi
}


checkLog() {
    if [[ -z "${configPath}" && -z "${realityStatus}" ]]; then
        echoContent red " ---> The installation directory is not detected, please execute the script to install the content"
        exit 0
    fi
    local realityLogShow=
    local logStatus=false
    if grep -q "access" ${configPath}00_log.json; then
        logStatus=true
    fi

    echoContent skyBlue "\nFunction $1/${totalProgress}: View log"
    echoContent red "\n================================================ ================="
    echoContent yellow "# It is recommended to only open the access log during debugging\n"

    if [[ "${logStatus}" == "false" ]]; then
        echoContent yellow "1.Open access log"
    else
        echoContent yellow "1. Close access log"
    fi

    echoContent yellow "2. Monitor access log"
    echoContent yellow "3. Monitor error log"
    echoContent yellow "4. View certificate scheduled task log"
    echoContent yellow "5. View certificate installation log"
    echoContent yellow "6.Clear the log"
    echoContent red "================================================== ==============="

    read -r -p "Please select:" selectAccessLogType
    local configPathLog=${configPath//conf\//}

    case ${selectAccessLogType} in
    1)
        if [[ "${logStatus}" == "false" ]]; then
            realityLogShow=true
            cat <<EOF >${configPath}00_log.json
{
  "log": {
  	"access":"${configPathLog}access.log",
    "error": "${configPathLog}error.log",
    "loglevel": "debug"
  }
}
EOF
        elif [[ "${logStatus}" == "true" ]]; then
            realityLogShow=false
            cat <<EOF >${configPath}00_log.json
{
  "log": {
    "error": "${configPathLog}error.log",
    "loglevel": "warning"
  }
}
EOF
        fi

        if [[ -n ${realityStatus} ]]; then
            local vlessVisionRealityInbounds
            vlessVisionRealityInbounds=$(jq -r ".inbounds[0].streamSettings.realitySettings.show=${realityLogShow}" ${configPath}07_VLESS_vision_reality_inbounds.json)
            echo "${vlessVisionRealityInbounds}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
        fi
        reloadCore
        checkLog 1
        ;;
    2)
        tail -f ${configPathLog}access.log
        ;;
    3)
        tail -f ${configPathLog}error.log
        ;;
    4)
        if [[ ! -f "/etc/v2ray-agent/crontab_tls.log" ]]; then
            touch /etc/v2ray-agent/crontab_tls.log
        fi
        tail -n 100 /etc/v2ray-agent/crontab_tls.log
        ;;
    5)
        tail -n 100 /etc/v2ray-agent/tls/acme.log
        ;;
    6)
        echo >${configPathLog}access.log
        echo >${configPathLog}error.log
        ;;
    esac
}


aliasInstall() {

    if [[ -f "$HOME/install.sh" ]] && [[ -d "/etc/v2ray-agent" ]] && grep <"$HOME/install.sh" -q "Author:mack-a" ; then
        mv "$HOME/install.sh" /etc/v2ray-agent/install.sh
        local vasmaType=
        if [[ -d "/usr/bin/" ]]; then
            if [[ ! -f "/usr/bin/vasma" ]]; then
                ln -s /etc/v2ray-agent/install.sh /usr/bin/vasma
                chmod 700 /usr/bin/vasma
                vasmaType=true
            fi

            rm -rf "$HOME/install.sh"
        elif [[ -d "/usr/sbin" ]]; then
            if [[ ! -f "/usr/sbin/vasma" ]]; then
                ln -s /etc/v2ray-agent/install.sh /usr/sbin/vasma
                chmod 700 /usr/sbin/vasma
                vasmaType=true
            fi
            rm -rf "$HOME/install.sh"
        fi
        if [[ "${vasmaType}" == "true" ]]; then
            echoContent green "The shortcut is created successfully, you can execute [vasma] to reopen the script"
        fi
    fi
}


checkIPv6() {
    currentIPv6IP=$(curl -s -6 http://www.cloudflare.com/cdn-cgi/trace | grep "ip" | cut -d "=" -f 2)

    if [[ -z "${currentIPv6IP}" ]]; then
        echoContent red " ---> does not support ipv6"
        exit 0
    fi
}


ipv6Routing() {
    if [[ -z "${configPath}" ]]; then
        echoContent red " ---> Not installed, please use script to install"
        menu
        exit 0
    fi

    checkIPv6
    echoContent skyBlue "\nFunction 1/${totalProgress}: IPv6 offload"
    echoContent red "\n================================================ ================="
    echoContent yellow "1. View the diverted domain name"
    echoContent yellow "2.Add domain name"
    echoContent yellow "3. Set IPv6 global"
    echoContent yellow "4. Uninstall IPv6 offloading"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" ipv6Status
    if [[ "${ipv6Status}" == "1" ]]; then

        jq -r -c '.routing.rules[]|select (.outboundTag=="IPv6_out")|.domain' ${configPath}09_routing.json | jq -r
        exit 0
    elif [[ "${ipv6Status}" == "2" ]]; then
        echoContent red "================================================== ==============="
        echoContent yellow "# Notes\n"
        echoContent yellow "# Notes"
        echoContent yellow "# Tutorial: https://www.v2ray-agent.com/archives/ba-he-yi-jiao-ben-yu-ming-fen-liu-jiao-cheng \n"

        read -r -p "Please enter the domain name according to the above example:" domainList
        addInstallRouting IPv6_out outboundTag "${domainList}"

        unInstallOutbounds IPv6_out

        outbounds=$(jq -r '.outbounds += [{"protocol":"freedom","settings":{"domainStrategy":"UseIPv6"},"tag":"IPv6_out"}]' ${configPath}10_ipv4_outbounds.json)

        echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

        configurationSingBoxRoute add IPv6_out "${domainList}"
        addSingBoxOutbound IPv6_out
        addSingBoxOutbound IPv4_out
        echoContent green " ---> Added successfully"

    elif [[ "${ipv6Status}" == "3" ]]; then

        echoContent red "================================================== ==============="
        echoContent yellow "# Notes\n"
        echoContent yellow "1. All diversion rules set will be deleted"
        echoContent yellow "2. All outbound rules except IPv6 will be deleted"
        read -r -p "Confirm settings? [y/n]:" IPv6OutStatus

        if [[ "${IPv6OutStatus}" == "y" ]]; then
            cat <<EOF >${configPath}10_ipv4_outbounds.json
            {
                "outbounds":[
                    {
                        "protocol":"freedom",
                        "settings":{
                            "domainStrategy":"UseIPv6"
                        },
                        "tag":"IPv6_out"
                    }
                ]
            }
EOF
            rm ${configPath}09_routing.json >/dev/null 2>&1
            echoContent green " ---> IPv6 global outbound setting successful"

            configurationSingBoxRoute delete wireguard_out_IPv4
            configurationSingBoxRoute delete wireguard_out_IPv6
            removeSingBoxOutbound IPv4_out
            removeSingBoxOutbound wireguard_out_IPv4
            removeSingBoxOutbound wireguard_outbound

            addSingBoxOutbound IPv6_out

        else
            
        echoContent green " ---> Abandon settings"
            exit 0
        fi

    elif [[ "${ipv6Status}" == "4" ]]; then

        unInstallRouting IPv6_out outboundTag

        unInstallOutbounds IPv6_out

        configurationSingBoxRoute delete IPv6_out

        if ! grep -q "IPv4_out" <"${configPath}10_ipv4_outbounds.json"; then
            outbounds=$(jq -r '.outbounds += [{"protocol":"freedom","settings": {"domainStrategy": "UseIPv4"},"tag":"IPv4_out"}]' ${configPath}10_ipv4_outbounds.json)

            echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json
        fi
        echoContent green " ---> IPv6 offload uninstall successful"
    else
        echoContent red " ---> Wrong selection"
        exit 0
    fi

    reloadCore
}


btTools() {
    if [[ -z "${configPath}" ]]; then
        echoContent red " ---> Not installed, please use script to install"
        menu
        exit 0
    fi

    echoContent skyBlue "\nFunction 1/${totalProgress}: bt download management"
    echoContent red "\n================================================ ================="

    if [[ -f ${configPath}09_routing.json ]] && grep -q bittorrent <${configPath}09_routing.json; then
        echoContent yellow "Current status: disabled"
    else
        echoContent yellow "Current status: not disabled"
    fi

    echoContent yellow "1.Disable"
    echoContent yellow "2.Open"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" btStatus
    if [[ "${btStatus}" == "1" ]]; then

        if [[ -f "${configPath}09_routing.json" ]]; then

            unInstallRouting blackhole_out outboundTag

            routing=$(jq -r '.routing.rules += [{"type":"field","outboundTag":"blackhole_out","protocol":["bittorrent"]}]' ${configPath}09_routing.json)

            echo "${routing}" | jq . >${configPath}09_routing.json

        else
            cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "outboundTag": "blackhole_out",
            "protocol": [ "bittorrent" ]
          }
        ]
  }
}
EOF
        fi

        installSniffing

        unInstallOutbounds blackhole_out

        outbounds=$(jq -r '.outbounds += [{"protocol":"blackhole","tag":"blackhole_out"}]' ${configPath}10_ipv4_outbounds.json)

        echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

        echoContent green " ---> BT download disabled successfully"

    elif [[ "${btStatus}" == "2" ]]; then

        unInstallSniffing

        unInstallRouting blackhole_out outboundTag bittorrent

        # unInstallOutbounds blackhole_out

        echoContent green " ---> BT download opened successfully"
    else
        echoContent red " ---> Wrong selection"
        exit 0
    fi

    reloadCore
}


blacklist() {
    if [[ -z "${configPath}" ]]; then
        echoContent red " ---> Not installed, please use script to install"
        menu
        exit 0
    fi

    echoContent skyBlue "\nProgress $1/${totalProgress}: Domain name blacklist"
    echoContent red "\n================================================ ================="
    echoContent yellow "1. View blocked domain names"
    echoContent yellow "2.Add domain name"
    echoContent yellow "3. Block domestic domain names"
    echoContent yellow "4. Delete blacklist"
    echoContent red "================================================== ==============="

    read -r -p "Please select:" blacklistStatus
    if [[ "${blacklistStatus}" == "1" ]]; then
        jq -r -c '.routing.rules[]|select (.outboundTag=="blackhole_out")|.domain' ${configPath}09_routing.json | jq -r
        exit 0
    elif [[ "${blacklistStatus}" == "2" ]]; then
        echoContent red "================================================== ==============="
        echoContent yellow "# Notes\n"
        echoContent yellow "1. Rules support predefined domain name list [https://github.com/v2fly/domain-list-community]"
        echoContent yellow "2. Rules support custom domain names"
        echoContent yellow "3. Input example: speedtest, facebook, cn, example.com"
        echoContent yellow "4. If the domain name exists in the predefined domain name list, use geosite:xx. If it does not exist, the entered domain name will be used by default."
        echoContent yellow "5. Add rules as incremental configuration and will not delete previously set content\n"
        read -r -p "Please enter the domain name according to the above example:" domainList

        if [[ -f "${configPath}09_routing.json" ]]; then
            addInstallRouting blackhole_out outboundTag "${domainList}"
        fi
        unInstallOutbounds blackhole_out

        outbounds=$(jq -r '.outbounds += [{"protocol":"blackhole","tag":"blackhole_out"}]' ${configPath}10_ipv4_outbounds.json)

        echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

        echoContent green " ---> Added successfully"

    elif [[ "${blacklistStatus}" == "3" ]]; then
        addInstallRouting blackhole_out outboundTag "cn"

        unInstallOutbounds blackhole_out

        outbounds=$(jq -r '.outbounds += [{"protocol":"blackhole","tag":"blackhole_out"}]' ${configPath}10_ipv4_outbounds.json)

        echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

        echoContent green " ---> Domestic domain name blocked successfully"

    elif [[ "${blacklistStatus}" == "4" ]]; then

        unInstallRouting blackhole_out outboundTag

        echoContent green " ---> Domain name blacklist deleted successfully"
    else
        echoContent red " ---> Wrong selection"
        exit 0
    fi
    reloadCore
}


addInstallRouting() {

    local tag=$1    # warp-socks
    local type=$2   # outboundTag/inboundTag
    local domain=$3 # 域名

    if [[ -z "${tag}" || -z "${type}" || -z "${domain}" ]]; then
        echoContent red " ---> 参数错误"
        exit 0
    fi

    local routingRule=
    if [[ ! -f "${configPath}09_routing.json" ]]; then
        cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "type": "field",
        "rules": [
            {
                "type": "field",
                "domain": [
                ],
            "outboundTag": "${tag}"
          }
        ]
  }
}
EOF
    fi
    local routingRule=
    routingRule=$(jq -r '.routing.rules[]|select(.outboundTag=="'"${tag}"'")' ${configPath}09_routing.json)
    if [[ -z "${routingRule}" ]]; then
        if [[ "${tag}" == "dokodemoDoor-80" ]]; then
            routingRule="{\"type\": \"field\",\"port\": 80,\"domain\": [],\"outboundTag\": \"${tag}\"}"
        elif [[ "${tag}" == "dokodemoDoor-443" ]]; then
            routingRule="{\"type\": \"field\",\"port\": 443,\"domain\": [],\"outboundTag\": \"${tag}\"}"
        else
            routingRule="{\"type\": \"field\",\"domain\": [],\"outboundTag\": \"${tag}\"}"
        fi
    fi

    while read -r line; do
        if echo "${routingRule}" | grep -q "${line}"; then
            echoContent yellow " ---> ${line} already exists, skip"
        else
            local geositeStatus
            geositeStatus=$(curl -s "https://api.github.com/repos/v2fly/domain-list-community/contents/data/${line}" | jq .message)

            if [[ "${geositeStatus}" == "null" ]]; then
                routingRule=$(echo "${routingRule}" | jq -r '.domain += ["geosite:'"${line}"'"]')
            else
                routingRule=$(echo "${routingRule}" | jq -r '.domain += ["domain:'"${line}"'"]')
            fi
        fi
    done < <(echo "${domain}" | tr ',' '\n')

    unInstallRouting "${tag}" "${type}"
    if ! grep -q "gstatic.com" ${configPath}09_routing.json && [[ "${tag}" == "blackhole_out" ]]; then
        local routing=
        routing=$(jq -r ".routing.rules += [{\"type\": \"field\",\"domain\": [\"gstatic.com\"],\"outboundTag\": \"direct\"}]" ${configPath}09_routing.json)
        echo "${routing}" | jq . >${configPath}09_routing.json
    fi

    routing=$(jq -r ".routing.rules += [${routingRule}]" ${configPath}09_routing.json)
    echo "${routing}" | jq . >${configPath}09_routing.json
}


unInstallRouting() {
    local tag=$1
    local type=$2
    local protocol=$3

    if [[ -f "${configPath}09_routing.json" ]]; then
        local routing
        if grep -q "${tag}" ${configPath}09_routing.json && grep -q "${type}" ${configPath}09_routing.json; then

            jq -c .routing.rules[] ${configPath}09_routing.json | while read -r line; do
                local index=$((index + 1))
                local delStatus=0
                if [[ "${type}" == "outboundTag" ]] && echo "${line}" | jq .outboundTag | grep -q "${tag}"; then
                    delStatus=1
                elif [[ "${type}" == "inboundTag" ]] && echo "${line}" | jq .inboundTag | grep -q "${tag}"; then
                    delStatus=1
                fi

                if [[ -n ${protocol} ]] && echo "${line}" | jq .protocol | grep -q "${protocol}"; then
                    delStatus=1
                elif [[ -z ${protocol} ]] && [[ $(echo "${line}" | jq .protocol) != "null" ]]; then
                    delStatus=0
                fi

                if [[ ${delStatus} == 1 ]]; then
                    routing=$(jq -r 'del(.routing.rules['$((index - 1))'])' ${configPath}09_routing.json)
                    echo "${routing}" | jq . >${configPath}09_routing.json
                fi
            done
        fi
    fi
}


unInstallOutbounds() {
    local tag=$1

    if grep -q "${tag}" ${configPath}10_ipv4_outbounds.json; then
        local ipv6OutIndex
        ipv6OutIndex=$(jq .outbounds[].tag ${configPath}10_ipv4_outbounds.json | awk '{print ""NR""":"$0}' | grep "${tag}" | awk -F "[:]" '{print $1}' | head -1)
        if [[ ${ipv6OutIndex} -gt 0 ]]; then
            routing=$(jq -r 'del(.outbounds['$((ipv6OutIndex - 1))'])' ${configPath}10_ipv4_outbounds.json)
            echo "${routing}" | jq . >${configPath}10_ipv4_outbounds.json
        fi
    fi

}


unInstallSniffing() {

    find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
        if grep -q "destOverride" <"${configPath}${inbound}"; then
            sniffing=$(jq -r 'del(.inbounds[0].sniffing)' "${configPath}${inbound}")
            echo "${sniffing}" | jq . >"${configPath}${inbound}"
        fi
    done

}


installSniffing() {
    readInstallType
    find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
        if ! grep -q "destOverride" <"${configPath}${inbound}"; then
            sniffing=$(jq -r '.inbounds[0].sniffing = {"enabled":true,"destOverride":["http","tls","quic"]}' "${configPath}${inbound}")
            echo "${sniffing}" | jq . >"${configPath}${inbound}"
        fi
    done
}


warpRouting() {
    echoContent skyBlue "\nProgress $1/${totalProgress} : WARP offload"
    echoContent red "================================================== ==============="
    if [[ -z $(which warp-cli) ]]; then
        echo
        read -r -p "WARP is not installed, do you want to install it? [y/n]:" installCloudflareWarpStatus
        if [[ "${installCloudflareWarpStatus}" == "y" ]]; then
            installWarp
        else
            echoContent yellow " ---> Abort installation"
            exit 0
        fi
    fi

    echoContent red "\n================================================ ================="
    echoContent yellow "1. View the diverted domain name"
    echoContent yellow "2.Add domain name"
    echoContent yellow "3. Set WARP global"
    echoContent yellow "4. Uninstall WARP distribution"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" warpStatus
    if [[ "${warpStatus}" == "1" ]]; then
        jq -r -c '.routing.rules[]|select (.outboundTag=="warp-socks-out")|.domain' ${configPath}09_routing.json | jq -r
        exit 0
    elif [[ "${warpStatus}" == "2" ]]; then
        echoContent yellow "# Notes"
        echoContent yellow "# Tutorial: https://www.v2ray-agent.com/archives/ba-he-yi-jiao-ben-yu-ming-fen-liu-jiao-cheng \n"

        read -r -p "Please enter the domain name according to the above example:" domainList

        addInstallRouting warp-socks-out outboundTag "${domainList}"

        unInstallOutbounds warp-socks-out

        local outbounds
        outbounds=$(jq -r '.outbounds += [{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":31303}] },"tag":"warp-socks-out"}]' ${configPath}10_ipv4_outbounds.json)

        echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

        echoContent green " ---> Added successfully"

    elif [[ "${warpStatus}" == "3" ]]; then

        echoContent red "=============================================================="
        echoContent yellow "# Notes\n"
        echoContent yellow "1. All diversion rules set will be deleted"
        echoContent yellow "2. All outbound rules except WARP will be deleted"
        read -r -p "Confirm settings? [y/n]:" warpOutStatus

        if [[ "${warpOutStatus}" == "y" ]]; then
            cat <<EOF >${configPath}10_ipv4_outbounds.json
{
    "outbounds":[
        {
          "protocol": "socks",
          "settings": {
            "servers": [
              {
                "address": "127.0.0.1",
                "port": 31303
              }
            ]
          },
          "tag": "warp-socks-out"
        }
    ]
}
EOF
            rm ${configPath}09_routing.json >/dev/null 2>&1
            echoContent green " ---> WARP global outbound setting successful"
        else
            echoContent green " ---> Abandon settings"
            exit 0
        fi

    elif [[ "${warpStatus}" == "4" ]]; then


        unInstallRouting warp-socks-out outboundTag

        unInstallOutbounds warp-socks-out

        if ! grep -q "IPv4_out" <"${configPath}10_ipv4_outbounds.json"; then
            outbounds=$(jq -r '.outbounds += [{"protocol":"freedom","settings": {"domainStrategy": "UseIPv4"},"tag":"IPv4_out"}]' ${configPath} 10_ipv4_outbounds.json)

            echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json
        fi

        echoContent green " ---> WARP offload uninstall successful"
    else
        echoContent red " ---> Wrong selection"
        exit 0
    fi
    reloadCore
}


readConfigWarpReg() {
    if [[ ! -f "/etc/v2ray-agent/warp/config" ]]; then
        /etc/v2ray-agent/warp/warp-reg >/etc/v2ray-agent/warp/config
    fi

    secretKeyWarpReg=$(grep <"/etc/v2ray-agent/warp/config" private_key | awk '{print $2}')

    addressWarpReg=$(grep <"/etc/v2ray-agent/warp/config" v6 | awk '{print $2}')

    publicKeyWarpReg=$(grep <"/etc/v2ray-agent/warp/config" public_key | awk '{print $2}')

    reservedWarpReg=$(grep <"/etc/v2ray-agent/warp/config" reserved | awk -F "[:]" '{print $2}')

}


installWarpReg() {
    if [[ ! -f "/etc/v2ray-agent/warp/warp-reg" ]]; then
        echo
        echoContent yellow "# Notes"
        echoContent yellow "# relies on third-party programs, please be aware of the risks"
        echoContent yellow "# Project address: https://github.com/badafans/warp-reg \n"

        read -r -p "warp-reg is not installed, do you want to install it? [y/n]:" installWarpRegStatus

        if [[ "${installWarpRegStatus}" == "y" ]]; then

            curl -sLo /etc/v2ray-agent/warp/warp-reg "https://github.com/badafans/warp-reg/releases/download/v1.0/${warpRegCoreCPUVendor}"
            chmod 655 /etc/v2ray-agent/warp/warp-reg

        else
            echoContent yellow " ---> Abort installation"
            exit 0
        fi
    fi
}


showWireGuardDomain() {
    if [[ -f "${configPath}09_routing.json" ]]; then
        echoContent yellow "Xray-core"
        jq -r -c '.routing.rules[]|select (.outboundTag=="wireguard_out_'"${type}"'")|.domain' ${configPath}09_routing.json | jq -r
    fi

    if [[ -f "${singBoxConfigPath}config/wireguard_out_${type}_route.json" ]]; then
        echoContent yellow "sing-box"
        jq -r -c '.route.rules[]|select (.outbound=="wireguard_out_'"${type}"'")|.geosite' "${singBoxConfigPath}config/wireguard_out_${type}_route.json" | jq -r
    fi
}

addWireGuardRoute() {
    local type=$1
    local tag=$2
    local domainList=$3
    # xray
    if [[ -n "${configPath}" ]]; then

        addInstallRouting wireguard_out_"${type}" "${tag}" "${domainList}"
        unInstallOutbounds wireguard_out_"${type}"
        local outbounds
        outbounds=$(jq -r '.outbounds += [{"protocol":"wireguard","settings":{"secretKey":"'"${secretKeyWarpReg}"'","address":["'"${address}"'"],"peers":[{"publicKey":"'"${publicKeyWarpReg}"'","allowedIPs":["0.0.0.0/0","::/0"],"endpoint":"162.159.192.1:2408"}],"reserved":'"${reservedWarpReg}"',"mtu":1280},"tag":"wireguard_out_'"${type}"'"}]' ${configPath}10_ipv4_outbounds.json)

        echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json
    fi
    if [[ -n "${singBoxConfigPath}" ]]; then

        addSingBoxRouteRule "wireguard_out_${type}" "${domainList}"
        addSingBoxOutbound "wireguard_out_${type}" "wireguard_out"
        addSingBoxOutbound direct
        addSingBoxWireGuardOut
    fi
}

unInstallWireGuard() {
    local type=$1
    if [[ -n "${configPath}" ]]; then

        if [[ "${type}" == "IPv4" ]]; then
            if ! grep -q "wireguard_out_IPv6" <${configPath}10_ipv4_outbounds.json; then
                rm -rf /etc/v2ray-agent/warp/config >/dev/null 2>&1
            fi
        elif [[ "${type}" == "IPv6" ]]; then
            if ! grep -q "wireguard_out_IPv4" <${configPath}10_ipv4_outbounds.json; then
                rm -rf /etc/v2ray-agent/warp/config >/dev/null 2>&1
            fi
        fi
    fi

    if [[ -n "${singBoxConfigPath}" ]]; then
        if [[ ! -f "${singBoxConfigPath}config/wireguard_out_IPv6_route.json" && ! -f "${singBoxConfigPath}config/wireguard_out_IPv4_route.json" ]]; then
            rm ${singBoxConfigPath}config/wireguard_outbound.json >/dev/null 2>&1
            rm -rf /etc/v2ray-agent/warp/config >/dev/null 2>&1
        fi
    fi
}


removeWireGuardRoute() {
    local type=$1
    if [[ -n "${configPath}" ]]; then

        unInstallRouting wireguard_out_"${type}" outboundTag

        unInstallOutbounds wireguard_out_"${type}"

        if ! grep -q "IPv4_out" <"${configPath}10_ipv4_outbounds.json"; then

            cat <<EOF >${configPath}10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4_out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6_out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole_out"
        }
    ]
}
EOF
        fi

        echoContent green " ---> WARP offload uninstall successful"
    fi
    if [[ -n "${singBoxConfigPath}" ]]; then
        removeSingBoxRouteRule "wireguard_out_${type}"
    fi

    unInstallWireGuard "${type}"
}


warpRoutingReg() {
    local type=$2
    echoContent skyBlue "\nProgress $1/${totalProgress}: WARP offload [third party]"
    echoContent red "================================================== ==============="

    echoContent yellow "1. View the diverted domain name"
    echoContent yellow "2.Add domain name"
    echoContent yellow "3. Set WARP global"
    echoContent yellow "4. Uninstall WARP distribution"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" warpStatus
    installWarpReg
    readConfigWarpReg
    local address=
    if [[ ${type} == "IPv4" ]]; then
        address="172.16.0.2/32"
    elif [[ ${type} == "IPv6" ]]; then
        address="${addressWarpReg}/128"
    else
        echoContent red " ---> IP acquisition failed, exit installation"
    fi

    if [[ "${warpStatus}" == "1" ]]; then
        showWireGuardDomain
        exit 0
    elif [[ "${warpStatus}" == "2" ]]; then
        echoContent yellow "# Notes"
        echoContent yellow "# Support sing-box, Xray-core"
        echoContent yellow "# Tutorial: https://www.v2ray-agent.com/archives/ba-he-yi-jiao-ben-yu-ming-fen-liu-jiao-cheng \n"

        read -r -p "Please enter the domain name according to the above example:" domainList
        addWireGuardRoute "${type}" outboundTag "${domainList}"
        echoContent green " ---> Added successfully"

    elif [[ "${warpStatus}" == "3" ]]; then

        echoContent red "================================================== ==============="
        echoContent yellow "# Notes\n"
        echoContent yellow "1. All diversion rules set will be deleted"
        echoContent yellow "2. All outbound rules except WARP [third party] will be deleted"
        read -r -p "Confirm settings? [y/n]:" warpOutStatus

        if [[ "${warpOutStatus}" == "y" ]]; then
            readConfigWarpReg

            cat <<EOF >${configPath}10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol": "wireguard",
            "settings": {
                "secretKey": "${secretKeyWarpReg}",
                "address": [
                    "${address}"
                ],
                "peers": [
                    {
                        "publicKey": "${publicKeyWarpReg}",
                        "allowedIPs": [
                            "0.0.0.0/0",
                             "::/0"
                        ],
                        "endpoint": "162.159.192.1:2408"
                    }
                ],
                "reserved": ${reservedWarpReg},
                "mtu": 1280
            },
            "tag": "wireguard_out_${type}"
        }
    ]
}
EOF
            rm ${configPath}09_routing.json >/dev/null 2>&1

            configurationSingBoxRoute delete IPv4
            configurationSingBoxRoute delete IPv6

            removeSingBoxOutbound direct

            removeSingBoxOutbound IPv4_out
            removeSingBoxOutbound IPv6_out

            configurationSingBoxRoute delete wireguard_out_IPv4
            configurationSingBoxRoute delete wireguard_out_IPv6

            if [[ "${type}" == "IPv4" ]]; then
                removeSingBoxOutbound wireguard_out_IPv6
            else
                removeSingBoxOutbound wireguard_out_IPv4
            fi

            # outbound
            addSingBoxOutbound "wireguard_out_${type}" "wireguard_out"
            addSingBoxWireGuardOut
            echoContent green " ---> WARP global outbound setting successful"
        else
            echoContent green " ---> Abandon settings"
            exit 0
        fi

    elif [[ "${warpStatus}" == "4" ]]; then

        removeWireGuardRoute "${type}"
        removeSingBoxOutbound "wireguard_out_${type}"
    else
        echoContent red " ---> Wrong selection"
        exit 0
    fi
    reloadCore
}


routingToolsMenu() {
    echoContent skyBlue "\nFunction 1/${totalProgress}: Diversion tool"
    echoContent red "\n================================================ ================="
    echoContent yellow "1.WARP diversion [Third-party IPv4]"
    echoContent yellow "2.WARP diversion [Third-party IPv6]"
    echoContent yellow "3.IPv6 offload"
    echoContent yellow "4. Any door diversion"
    echoContent yellow "5.DNS divert"
    echoContent yellow "6.VMess+WS+TLS offload"
    echoContent yellow "7.SNI reverse proxy offload"

    read -r -p "Please select:" selectType

    case ${selectType} in
    1)
        warpRoutingReg 1 IPv4
        ;;
    2)
        warpRoutingReg 1 IPv6
        ;;
    3)
        ipv6Routing 1
        ;;
    4)
        dokodemoDoorRouting 1
        ;;
    5)
        dnsRouting 1
        ;;
    6)
        vmessWSRouting 1
        ;;
    7)
        sniRouting 1
        ;;
    esac

}


streamingToolbox() {
    echoContent skyBlue "\nFunction 1/${totalProgress}: Streaming Media Toolbox"
    echoContent red "\n================================================ ================="
    echoContent yellow "1. Any door floor machine unlocks streaming media"
    echoContent yellow "2.DNS unlock streaming media"
    echoContent yellow "3.VMess+WS+TLS to unlock streaming media"
    read -r -p "Please select:" selectType

    case ${selectType} in
    1)
        dokodemoDoorRouting
        ;;
    2)
        dnsRouting
        ;;
    3)
        vmessWSRouting
        ;;
    esac

}


dokodemoDoorRouting() {
    echoContent skyBlue "\nFunction 1/${totalProgress}: Any door diversion"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Notes"
    echoContent yellow "# Tutorial: https://www.v2ray-agent.com/archives/ba-he-yi-jiao-ben-yu-ming-fen-liu-jiao-cheng \n"

    echoContent yellow "1.Add outbound"
    echoContent yellow "2.Add inbound"
    echoContent yellow "3.Uninstall"
    read -r -p "Please select:" selectType

    case ${selectType} in
    1)
        setDokodemoDoorRoutingOutbounds
        ;;
    2)
        setDokodemoDoorRoutingInbounds
        ;;
    3)
        removeDokodemoDoorRouting
        ;;
    esac
}


vmessWSRouting() {
    echoContent skyBlue "\nFunction 1/${totalProgress}: VMess+WS+TLS offload"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Notes"
    echoContent yellow "# Tutorial: https://www.v2ray-agent.com/archives/ba-he-yi-jiao-ben-yu-ming-fen-liu-jiao-cheng \n"

    echoContent yellow "1.Add outbound"
    echoContent yellow "2.Uninstall"
    read -r -p "Please select:" selectType

    case ${selectType} in
    1)
        setVMessWSRoutingOutbounds
        ;;
    2)
        removeVMessWSRouting
        ;;
    esac
}


setVMessWSRoutingOutbounds() {
    read -r -p "Please enter the address of VMess+WS+TLS:" setVMessWSTLSAddress
    echoContent red "================================================== ==============="
    echoContent yellow "Input example:netflix,openai\n"
    read -r -p "Please enter the domain name according to the above example:" domainList

    if [[ -z ${domainList} ]]; then
        echoContent red " ---> Domain name cannot be empty"
        setVMessWSRoutingOutbounds
    fi

    if [[ -n "${setVMessWSTLSAddress}" ]]; then

        unInstallOutboundsVMess-out

        echo
        read -r -p "Please enter the port of VMess+WS+TLS:" setVMessWSTLSPort
        echo
        if [[ -z "${setVMessWSTLSPort}" ]]; then
            echoContent red " ---> Port cannot be empty"
        fi

        read -r -p "Please enter the UUID of VMess+WS+TLS:" setVMessWSTLSUUID
        echo
        if [[ -z "${setVMessWSTLSUUID}" ]]; then
            echoContent red " ---> UUID cannot be empty"
        fi

        read -r -p "Please enter the Path of VMess+WS+TLS:" setVMessWSTLSPath
        echo
        if [[ -z "${setVMessWSTLSPath}" ]]; then
            echoContent red " ---> The path cannot be empty"
        elif ! echo "${setVMessWSTLSPath}" | grep -q "/"; then
            setVMessWSTLSPath="/${setVMessWSTLSPath}"
        fi

        outbounds=$(jq -r ".outbounds += [{\"tag\":\"VMess-out\",\"protocol\":\"vmess\",\"streamSettings\":{\"network\":\"ws\",\"security\":\"tls\",\"tlsSettings\":{\"allowInsecure\":false},\"wsSettings\":{\"path\":\"${setVMessWSTLSPath}\"}},\"mux\":{\"enabled\":true,\"concurrency\":8},\"settings\":{\"vnext\":[{\"address\":\"${setVMessWSTLSAddress}\",\"port\":${setVMessWSTLSPort},\"users\":[{\"id\":\"${setVMessWSTLSUUID}\",\"security\":\"auto\",\"alterId\":0}]}]}}]" ${configPath}10_ipv4_outbounds.json)

        echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

        addInstallRouting VMess-out outboundTag "${domainList}"
        reloadCore
        echoContent green " ---> Added shunt successfully"
        exit 0
    fi
    echoContent red " ---> The address cannot be empty"
    setVMessWSRoutingOutbounds
}


setDokodemoDoorRoutingOutbounds() {
    read -r -p "Please enter the IP of the target vps:" setIP
    echoContent red "================================================== ==============="
    echoContent yellow "Input example:netflix,openai\n"
    read -r -p "Please enter the domain name according to the above example:" domainList

    if [[ -z ${domainList} ]]; then
        echoContent red " ---> Domain name cannot be empty"
        setDokodemoDoorRoutingOutbounds
    fi

    if [[ -n "${setIP}" ]]; then

        unInstallOutbounds dokodemoDoor-80
        unInstallOutbounds dokodemoDoor-443

        addInstallRouting dokodemoDoor-80 outboundTag "${domainList}"
        addInstallRouting dokodemoDoor-443 outboundTag "${domainList}"

        outbounds=$(jq -r ".outbounds += [{\"tag\":\"dokodemoDoor-80\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22387\"}},{\"tag\":\"dokodemoDoor-443\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22388\"}}]" ${configPath}10_ipv4_outbounds.json)

        echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

        
        reloadCore
        echoContent green " ---> Add any door to divert successfully"
        exit 0
    fi
    echoContent red " ---> ip cannot be empty"
}


setDokodemoDoorRoutingInbounds() {

    echoContent skyBlue "\nFunction 1/${totalProgress}: Add inbound at any door"
    echoContent red "\n================================================ ================="
    echoContent yellow "ip entry example:1.1.1.1,1.1.1.2"
    echoContent yellow "The domain name below must be consistent with the outbound vps"
    echoContent yellow "Example of domain name entry: netflix,openai\n"
    read -r -p "Please enter the IP allowed to access the vps:" setIPs
    if [[ -n "${setIPs}" ]]; then
        read -r -p "Please enter the domain name according to the above example:" domainList
        allowPort 22387
        allowPort 22388

        cat <<EOF >${configPath}01_dokodemoDoor_inbounds.json
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 22387,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 80,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http"
        ]
      },
      "tag": "dokodemoDoor-80"
    },
    {
      "listen": "0.0.0.0",
      "port": 22388,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "tls"
        ]
      },
      "tag": "dokodemoDoor-443"
    }
  ]
}
EOF
        local domains=
        domains=[]
        while read -r line; do
            local geositeStatus
            geositeStatus=$(curl -s "https://api.github.com/repos/v2fly/domain-list-community/contents/data/${line}" | jq .message)

            if [[ "${geositeStatus}" == "null" ]]; then
                domains=$(echo "${domains}" | jq -r '. += ["geosite:'"${line}"'"]')
            else
                domains=$(echo "${domains}" | jq -r '. += ["domain:'"${line}"'"]')
            fi
        done < <(echo "${domainList}" | tr ',' '\n')

        if [[ -f "${configPath}09_routing.json" ]]; then
            unInstallRouting dokodemoDoor-80 inboundTag
            unInstallRouting dokodemoDoor-443 inboundTag

            local routing
            routing=$(jq -r ".routing.rules += [{\"source\":[\"${setIPs//,/\",\"}\"],\"domains\":${domains},\"type\":\"field\",\"inboundTag\":[\"dokodemoDoor-80\",\"dokodemoDoor-443\"],\"outboundTag\":\"direct\"},{\"type\":\"field\",\"inboundTag\":[\"dokodemoDoor-80\",\"dokodemoDoor-443\"],\"outboundTag\":\"blackhole_out\"}]" ${configPath}09_routing.json)
            echo "${routing}" | jq . >${configPath}09_routing.json
        else

            cat <<EOF >${configPath}09_routing.json
{
  "routing": {
    "rules": [
      {
        "source": [
            "${setIPs//,/\",\"}"
        ],
        "domains":${domains},
        "type": "field",
        "inboundTag": [
          "dokodemoDoor-80",
          "dokodemoDoor-443"
        ],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "inboundTag": [
          "dokodemoDoor-80",
          "dokodemoDoor-443"
        ],
        "outboundTag": "blackhole_out"
      }
    ]
  }
}
EOF

        fi

        reloadCore
        echoContent green " ---> Added landing machine inbound traffic successfully"
        exit 0
    fi
    echoContent red " ---> ip cannot be empty"
}


removeDokodemoDoorRouting() {

    unInstallOutbounds dokodemoDoor-80
    unInstallOutbounds dokodemoDoor-443

    unInstallRouting dokodemoDoor-80 inboundTag
    unInstallRouting dokodemoDoor-443 inboundTag

    unInstallRouting dokodemoDoor-80 outboundTag
    unInstallRouting dokodemoDoor-443 outboundTag

    rm -rf ${configPath}01_dokodemoDoor_inbounds.json

    reloadCore
    echoContent green " ---> 卸载成功"
}


removeVMessWSRouting() {

    unInstallOutbounds VMess-out

    unInstallRouting VMess-out outboundTag

    reloadCore
    echoContent green " ---> Uninstall successful"
}


reloadCore() {
    readInstallType

    if [[ "${coreInstallType}" == "1" ]]; then
        handleXray stop
        handleXray start
    fi

    if [[ -n "${singBoxConfigPath}" ]]; then
        handleSingBox stop
        handleSingBox start
    fi
}

dnsRouting() {

    if [[ -z "${configPath}" ]]; then
        echoContent red " ---> 未安装，请使用脚本安装"
        menu
        exit 0
    fi
    echoContent skyBlue "\nFunction 1/${totalProgress}: DNS offload"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Notes"
    echoContent yellow "# Tutorial: https://www.v2ray-agent.com/archives/ba-he-yi-jiao-ben-yu-ming-fen-liu-jiao-cheng \n"

    echoContent yellow "1.Add"
    echoContent yellow "2.Uninstall"
    read -r -p "Please select:" selectType

    case ${selectType} in
    1)
        setUnlockDNS
        ;;
    2)
        removeUnlockDNS
        ;;
    esac}


sniRouting() {

    if [[ -z "${configPath}" ]]; then
        echoContent red " ---> Not installed, please use script to install"
        menu
        exit 0
    fi
    echoContent skyBlue "\nFunction 1/${totalProgress}: SNI reverse proxy offload"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Notes"
    echoContent yellow "# Tutorial: https://www.v2ray-agent.com/archives/ba-he-yi-jiao-ben-yu-ming-fen-liu-jiao-cheng \n"

    echoContent yellow "1.Add"
    echoContent yellow "2.Uninstall"
    read -r -p "Please select:" selectType

    case ${selectType} in
    1)
        setUnlockSNI
        ;;
    2)
        removeUnlockSNI
        ;;
    esac
}

setUnlockSNI() {
    read -r -p "Please enter the SNI IP of the offload:" setSNIP
    if [[ -n ${setSNIP} ]]; then
        echoContent red "================================================== ==============="
        echoContent yellow "Input example: netflix, disney, hulu"
        read -r -p "Please enter the domain name according to the above example:" domainList

        if [[ -n "${domainList}" ]]; then
            local hosts={}
            while read -r domain; do
                hosts=$(echo "${hosts}" | jq -r ".\"geosite:${domain}\"=\"${setSNIP}\"")
            done < <(echo "${domainList}" | tr ',' '\n')
            cat <<EOF >${configPath}11_dns.json
{
    "dns": {
        "hosts":${hosts},
        "servers": [
            "8.8.8.8",
            "1.1.1.1"
        ]
    }
}
EOF
            echoContent red " ---> SNI reverse proxy distribution successful"
            reloadCore
        else
            echoContent red " ---> Domain name cannot be empty"
        fi

    else

        echoContent red " ---> SNI IP cannot be empty"
    fi
    exit 0
}


setUnlockDNS() {
    read -r -p "Please enter the diverted DNS:" setDNS
    if [[ -n ${setDNS} ]]; then
        echoContent red "================================================== ==============="
        echoContent yellow "Input example: netflix, disney, hulu"
        echoContent yellow "Please enter 1 for the default scheme. The default scheme includes the following content"
        echoContent yellow "netflix,bahamut,hulu,hbo,disney,bbc,4chan,fox,abema,dmm,niconico,pixiv,bilibili,viu"
        read -r -p "Please enter the domain name according to the above example:" domainList
        if [[ "${domainList}" == "1" ]]; then
            cat <<EOF >${configPath}11_dns.json
{
    "dns": {
        "servers": [
            {
                "address": "${setDNS}",
                "port": 53,
                "domains": [
                    "geosite:netflix",
                    "geosite:bahamut",
                    "geosite:hulu",
                    "geosite:hbo",
                    "geosite:disney",
                    "geosite:bbc",
                    "geosite:4chan",
                    "geosite:fox",
                    "geosite:abema",
                    "geosite:dmm",
                    "geosite:niconico",
                    "geosite:pixiv",
                    "geosite:bilibili",
                    "geosite:viu"
                ]
            },
        "localhost"
        ]
    }
}
EOF
        elif [[ -n "${domainList}" ]]; then
            cat <<EOF >${configPath}11_dns.json
{
    "dns": {
        "servers": [
            {
                "address": "${setDNS}",
                "port": 53,
                "domains": [
                    "geosite:${domainList//,/\",\"geosite:}"
                ]
            },
        "localhost"
        ]
    }
}
EOF
        fi

        reloadCore

        echoContent yellow "\n ---> If you still can't watch, you can try the following two solutions"
        echoContent yellow " 1. Restart vps"
        echoContent yellow " 2. After uninstalling dns unlocking, modify the local [/etc/resolv.conf] DNS settings and restart vps\n"
    else
        echoContent red " ---> dns cannot be empty"
    fi
    exit 0
}


removeUnlockDNS() {
    cat <<EOF >${configPath}11_dns.json
{
	"dns": {
		"servers": [
			"localhost"
		]
	}
}
EOF
    reloadCore

    echoContent green " ---> Uninstall successful"

    exit 0
}


removeUnlockSNI() {
    cat <<EOF >${configPath}11_dns.json
{
"dns": {
"servers": [
"localhost"
]
}
}
EOF
    reloadCore

    echoContent green " ---> Uninstall successful"

    exit 0
}


customV2RayInstall() {
    echoContent skyBlue "\n========================Personalized installation============================"
    echoContent yellow "VLESS is prefixed and 0 is installed by default. If you only need to install 0, just select 0"
    echoContent yellow "0.VLESS+TLS_Vision+TCP"
    echoContent yellow "1.VLESS+TLS+WS[CDN]"
    echoContent yellow "2.Trojan+TLS+gRPC[CDN]"
    echoContent yellow "3.VMess+TLS+WS[CDN]"
    echoContent yellow "4.Trojan+TLS"
    echoContent yellow "5.VLESS+TLS+gRPC[CDN]"
    read -r -p "Please select [multiple selection], [for example: 123]:" selectCustomInstallType
    echoContent skyBlue "----------------------------------------------------------------"
    if [[ -z ${selectCustomInstallType} ]]; then
        selectCustomInstallType=0
    fi
    if [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
        cleanUp xrayClean
        checkBTPanel
        totalProgress=17
        installTools 1
        initTLSNginxConfig 2
        installTLS 3
        handleNginx stop
        if echo ${selectCustomInstallType} | grep -q 1 || echo ${selectCustomInstallType} | grep -q 3 || echo ${selectCustomInstallType} | grep -q 4; then
            randomPathFunction 5
            customCDNIP 6
        fi
        nginxBlog 7
        updateRedirectNginxConf
        handleNginx start
        installV2Ray 8
        installV2RayService 9
        initV2RayConfig custom 10
        cleanUp xrayDel
        installCronTLS 14
        handleV2Ray stop
        handleV2Ray start
        checkGFWStatue 15
        showAccounts 16
    else
        echoContent red " ---> Input is illegal"
        customV2RayInstall
    fi
}


customXrayInstall() {
    echoContent skyBlue "\n========================Personalized installation================== =========="
    echoContent yellow "VLESS is prefixed and 0 is installed by default. If you only need to install 0, just select 0"
    echoContent yellow "0.VLESS+TLS_Vision+TCP[recommended]"
    echoContent yellow "1.VLESS+TLS+WS[only recommended by CDN]"
    echoContent yellow "2.Trojan+TLS+gRPC[CDN only recommended]"
    echoContent yellow "3.VMess+TLS+WS[CDN only recommended]"
    echoContent yellow "4.Trojan+TLS[Not recommended]"
    echoContent yellow "5.VLESS+TLS+gRPC[CDN only recommended]"
    echoContent yellow "7.VLESS+Reality+uTLS+Vision[recommended]"
    read -r -p "Please select [multiple selection], [for example: 123]:" selectCustomInstallType
    echoContent skyBlue "------------------------------------------------- ---------------"
    if [[ -z ${selectCustomInstallType} ]]; then
        echoContent red " ---> cannot be empty"
        customXrayInstall
    elif [[ "${selectCustomInstallType}" =~ ^[0-7]+$ ]]; then

        if ! echo "${selectCustomInstallType}" | grep -q "0"; then
            selectCustomInstallType="0${selectCustomInstallType}"
        fi
        cleanUp v2rayClean
        checkBTPanel
        totalProgress=12
        installTools 1
        if [[ -n "${btDomain}" ]]; then
            echoContent skyBlue "\nProgress 3/${totalProgress}: Pagoda panel detected, skip applying for TLS"
            handleXray stop
            customPortFunction
        else
            initTLSNginxConfig 2
            handleXray stop
            installTLS 3
        fi

        handleNginx stop
        if echo "${selectCustomInstallType}" | grep -q 1 || echo "${selectCustomInstallType}" | grep -q 2 || echo "${selectCustomInstallType}" | grep -q 3 || echo "${selectCustomInstallType}" | grep -q 5; then
            randomPathFunction 4
            customCDNIP 5
        fi
        if [[ -n "${btDomain}" ]]; then
            echoContent skyBlue "\nProgress 6/${totalProgress}: Pagoda panel detected, skipping fake website"
        else
            nginxBlog 6
        fi
        updateRedirectNginxConf
        handleNginx start

        installXray 7 false
        installXrayService 8
        initXrayConfig custom 9
        cleanUp v2rayDel

        installCronTLS 10
        handleXray stop
        handleXray start
        checkGFWStatue 11
        showAccounts 12
    else
        echoContent red " ---> Input is illegal"
        customXrayInstall
    fi
}

selectCoreInstall() {
    echoContent skyBlue "\nFunction 1/${totalProgress}: Select core installation"
    echoContent red "\n================================================ ================="
    echoContent yellow "1.Xray-core"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" selectCoreType
    case ${selectCoreType} in
    1)
        if [[ "${selectInstallType}" == "2" ]]; then
            customXrayInstall
        else
            xrayCoreInstall
        fi
        ;;
    2)
        v2rayCoreVersion=
        echoContent red " ---> Since v2ray does not support many new features, maintenance is now discontinued in order to reduce development costs. It is recommended to use Xray-core, hysteria, and Tuic"
        exit 0
        if [[ "${selectInstallType}" == "2" ]]; then
            customV2RayInstall
        else
            v2rayCoreInstall
        fi
        ;;
    3)
        v2rayCoreVersion=v4.32.1
        if [[ "${selectInstallType}" == "2" ]]; then
            customV2RayInstall
        else
            v2rayCoreInstall
        fi
        ;;
    *)
        echoContent red ' ---> Wrong selection, select again'
        selectCoreInstall
        ;;
    esac
}

v2rayCoreInstall() {
    cleanUp xrayClean
    checkBTPanel
    selectCustomInstallType=
    totalProgress=13
    installTools 2
    initTLSNginxConfig 3

    handleV2Ray stop
    handleNginx start

    installTLS 4
    handleNginx stop
    randomPathFunction 5
    installV2Ray 6
    installV2RayService 7
    customCDNIP 8
    initV2RayConfig all 9
    cleanUp xrayDel
    installCronTLS 10
    nginxBlog 11
    updateRedirectNginxConf
    handleV2Ray stop
    sleep 2
    handleV2Ray start
    handleNginx start
    checkGFWStatue 12
    showAccounts 13
}

xrayCoreInstall() {
    cleanUp v2rayClean
    checkBTPanel
    selectCustomInstallType=
    totalProgress=13
    installTools 2
    if [[ -n "${btDomain}" ]]; then
        echoContent skyBlue "\nProgress 3/${totalProgress}: Pagoda panel detected, skip applying for TLS"
        handleXray stop
        customPortFunction
    else
        initTLSNginxConfig 3
        handleXray stop

        installTLS 4
    fi

    handleNginx stop
    randomPathFunction 5
    installXray 6 false
    installXrayService 7
    customCDNIP 8
    initXrayConfig all 9
    cleanUp v2rayDel
    installCronTLS 10
    if [[ -n "${btDomain}" ]]; then
        echoContent skyBlue "\nProgress 11/${totalProgress}: Pagoda panel detected, skipping fake website"
    else
        nginxBlog 11
    fi
    updateRedirectNginxConf
    handleXray stop
    sleep 2
    handleXray start

    handleNginx start
    checkGFWStatue 12
    showAccounts 13
}

hysteriaCoreInstall() {
    if ! echo "${currentInstallProtocolType}" | grep -q "0" || [[ -z "${coreInstallType}" ]]; then
        echoContent red "\n ---> 由于环境依赖，如安装hysteria，请先安装Xray-core的VLESS_TCP_TLS_Vision"
        exit 0
    fi
    totalProgress=5
    installHysteria 1
    initHysteriaConfig 2
    installHysteriaService 3
    reloadCore
    showAccounts 4
}


unInstallHysteriaCore() {
    if [[ -n "${hysteriaConfigPath}" ]]; then
        echoContent yellow " ---> The new version depends on sing-box, the old version of hysteria is detected, and the uninstall operation is performed"

        deleteHysteriaPortHoppingRules
        handleHysteria stop
        rm -rf /etc/v2ray-agent/hysteria/*
        rm ${configPath}02_socks_inbounds_hysteria.json
        rm -rf /etc/systemd/system/hysteria.service
        echoContent green " ---> Uninstall completed"
    fi
}


unInstallTuicCore() {

    if [[ -n "${tuicConfigPath}" ]]; then
        echoContent yellow " ---> The new version depends on sing-box, the old version of Tuic is detected, and the uninstall operation is performed"

        handleTuic stop
        rm -rf /etc/v2ray-agent/tuic/*
        rm -rf /etc/systemd/system/tuic.service
        echoContent green " ---> Uninstall completed"
    fi

}


unInstallXrayCoreReality() {

    if [[ -z "${realityStatus}" ]]; then
        echoContent red "\n ---> not installed"
        exit 0
    fi
    echoContent skyBlue "\nFunction 1/1: reality uninstall"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Only delete VLESS Reality related configurations, other content will not be deleted."
    echoContent yellow "# If you need to uninstall other content, please uninstall the script function"
    handleXray stop
    rm /etc/v2ray-agent/xray/conf/07_VLESS_vision_reality_inbounds.json
    rm /etc/v2ray-agent/xray/conf/08_VLESS_reality_fallback_grpc_inbounds.json
    echoContent green " ---> Uninstall completed"
}



coreVersionManageMenu() {

    if [[ -z "${coreInstallType}" ]]; then
        echoContent red "\n >The installation directory is not detected, please execute the script to install the content"
        menu
        exit 0
    fi
    echoContent skyBlue "\nFunction 1/1: Please select core"
    echoContent red "\n================================================ ================="
    echoContent yellow "1.Xray-core"
    echoContent yellow "2.v2ray-core"
    echoContent yellow "3.sing-box"
    echoContent red "================================================== ==============="
    read -r -p "Please enter:" selectCore

    if [[ "${selectCore}" == "1" ]]; then
        xrayVersionManageMenu 1
    elif [[ "${coreInstallType}" == "2" ]]; then
        echoContent red " ---> Pause maintenance"
    elif [[ "${selectCore}" == "3" ]]; then
        singBoxVersionManageMenu 1
    fi
}

cronFunction() {
    if [[ "${cronName}" == "RenewTLS" ]]; then
        renewalTLS
        exit 0
    elif [[ "${cronName}" == "UpdateGeo" ]]; then
        updateGeoSite >>/etc/v2ray-agent/crontab_updateGeoSite.log
        echoContent green " ---> geo update date: $(date "+%F %H:%M:%S")" >>/etc/v2ray-agent/crontab_updateGeoSite.log
        exit 0
    fi
}


manageAccount() {
    echoContent skyBlue "\nFunction 1/${totalProgress}: Account Management"
    if [[ -z "${configPath}" ]]; then
        echoContent red " ---> not installed"
        exit 0
    fi

    echoContent red "\n================================================ ================="
    echoContent yellow "# You can customize email and uuid when adding a single user"
    echoContent yellow "# If Hysteria or Tuic is installed, the account will be added to the corresponding type at the same time\n"
    echoContent yellow "1. Check account"
    echoContent yellow "2. View subscription"
    echoContent yellow "3. Add subscription"
    echoContent yellow "4. Add user"
    echoContent yellow "5. Delete user"
    echoContent red "================================================== ==============="
    read -r -p "Please enter:" manageAccountStatus
    if [[ "${manageAccountStatus}" == "1" ]]; then
        showAccounts 1
    elif [[ "${manageAccountStatus}" == "2" ]]; then
        subscribe
    elif [[ "${manageAccountStatus}" == "3" ]]; then
        addSubscribeMenu 1
    elif [[ "${manageAccountStatus}" == "4" ]]; then
        addUserXray
    elif [[ "${manageAccountStatus}" == "5" ]]; then
        removeUser
    else
        echoContent red " ---> Wrong selection"
    fi
}


addSubscribeMenu() {
    echoContent skyBlue "\n====================== Add other machine subscriptions==================== ==="
    echoContent yellow "1.Add"
    echoContent yellow "2.Remove"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" addSubscribeStatus
    if [[ "${addSubscribeStatus}" == "1" ]]; then
        addOtherSubscribe
    elif [[ "${addSubscribeStatus}" == "2" ]]; then
        rm -rf /etc/v2ray-agent/subscribe_remote/clashMeta/*
        rm -rf /etc/v2ray-agent/subscribe_remote/default/*
        echo >/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl
        echoContent green " ---> Other machine subscriptions were deleted successfully"
        subscribe
    fi
}

addOtherSubscribe() {
    echoContent yellow "#Notes:"
    echoContent yellow "Please read the following article carefully: https://www.v2ray-agent.com/archives/1681804748677"
    echoContent skyBlue "Input example: www.v2ray-agent.com:443:vps1\n"
    read -r -p "Please enter the domain name, port, and machine alias:" remoteSubscribeUrl
    if [[ -z "${remoteSubscribeUrl}" ]]; then
        echoContent red " ---> cannot be empty"
        addSubscribe
    elif ! echo "${remoteSubscribeUrl}" | grep -q ":"; then
        echoContent red " ---> Rule is illegal"
    else
        echo "${remoteSubscribeUrl}" >>/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl
        local remoteUrl=
        remoteUrl=$(echo "${remoteSubscribeUrl}" | awk -F "[:]" '{print $1":"$2}')

        local serverAlias=
        serverAlias=$(echo "${remoteSubscribeUrl}" | awk -F "[:]" '{print $3}')

        if [[ -n $(ls /etc/v2ray-agent/subscribe/clashMeta/) || -n $(ls /etc/v2ray-agent/subscribe/default/) ]]; then
            find /etc/v2ray-agent/subscribe_local/default/* | while read -r email; do
                email=$(echo "${email}" | awk -F "[d][e][f][a][u][l][t][/]" '{print $2}')

                local emailMd5=
                emailMd5=$(echo -n "${email}$(cat "/etc/v2ray-agent/subscribe_local/subscribeSalt")"$'\n' | md5sum | awk '{print $1}')

                local clashMetaProxies=
                clashMetaProxies=$(curl -s -4 "https://${remoteUrl}/s/clashMeta/${emailMd5}" | sed '/proxies:/d' | sed "s/${email}/${email}_${serverAlias}/g")

                local default=
                default=$(curl -s -4 "https://${remoteUrl}/s/default/${emailMd5}" | base64 -d | sed "s/${email}/${email}_${serverAlias}/g")

                if echo "${default}" | grep -q "${email}"; then
                    echo "${default}" >>"/etc/v2ray-agent/subscribe/default/${emailMd5}"
                    echo "${default}" >>"/etc/v2ray-agent/subscribe_remote/default/${email}"

                    echoContent green " ---> Universal subscription ${email} added successfully"
                else
                    echoContent red " ---> Universal subscription ${email} does not exist"
                fi

                if echo "${clashMetaProxies}" | grep -q "${email}"; then
                    echo "${clashMetaProxies}" >>"/etc/v2ray-agent/subscribe/clashMeta/${emailMd5}"
                    echo "${clashMetaProxies}" >>"/etc/v2ray-agent/subscribe_remote/clashMeta/${email}"

                    echoContent green " ---> clashMeta subscription ${email} added successfully"
                else
                    echoContent red " ---> clashMeta subscription ${email} does not exist"
                fi
            done
        else
            echoContent red " ---> Please check the subscription first and then add the subscription"
        fi
    fi
}


clashMetaConfig() {
    local url=$1
    local id=$2
    cat <<EOF >"/etc/v2ray-agent/subscribe/clashMetaProfiles/${id}"
mixed-port: 7890
unified-delay: false
geodata-mode: true
tcp-concurrent: false
find-process-mode: strict
global-client-fingerprint: chrome

allow-lan: true
mode: rule
log-level: info
ipv6: true

external-controller: 127.0.0.1:9090

geox-url:
  geoip: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: false
  sniff:
    TLS:
      ports: [443]
    HTTP:
      ports: [80]
      override-destination: true

tun:
  enable: true
  stack: system
  dns-hijack:
    - 'any:53'
  auto-route: true
  auto-detect-interface: true

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 28.0.0.1/8
  fake-ip-filter:
    - '*'
    - '+.lan'
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - 'tls://8.8.4.4#DNS_Proxy'
    - 'tls://1.0.0.1#DNS_Proxy'
  proxy-server-nameserver:
    - https://dns.alidns.com/dns-query#h3=true
  nameserver-policy:
    "geosite:cn,private":
      - 223.5.5.5
      - 114.114.114.114
      - https://dns.alidns.com/dns-query#h3=true

proxy-providers:
  ${subscribeSalt}_provider:
    type: http
    path: ./${subscribeSalt}_provider.yaml
    url: ${url}
    interval: 3600
    health-check:
      enable: false
      url: http://www.gstatic.com/generate_204
      interval: 300

proxy-groups:
  - name: 手动切换
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies: null
  - name: 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 36000
    tolerance: 50
    use:
      - ${subscribeSalt}_provider
    proxies: null

  - name: 全球代理
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择

  - name: 流媒体
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
      - DIRECT
  - name: DNS_Proxy
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 自动选择
      - DIRECT

  - name: Telegram
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
  - name: Google
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
      - DIRECT
  - name: YouTube
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
  - name: Netflix
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 流媒体
      - 手动切换
      - 自动选择
  - name: Spotify
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 流媒体
      - 手动切换
      - 自动选择
      - DIRECT
  - name: HBO
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 流媒体
      - 手动切换
      - 自动选择
  - name: Bing
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 自动选择
  - name: OpenAI
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 自动选择
      - 手动切换
  - name: Disney
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 流媒体
      - 手动切换
      - 自动选择
  - name: GitHub
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - 手动切换
      - 自动选择
      - DIRECT

  - name: 国内媒体
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - DIRECT
  - name: 本地直连
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - DIRECT
      - 自动选择
  - name: 漏网之鱼
    type: select
    use:
      - ${subscribeSalt}_provider
    proxies:
      - DIRECT
      - 手动切换
      - 自动选择
rule-providers:
  lan:
    type: http
    behavior: classical
    interval: 86400
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Lan/Lan.yaml
    path: ./Rules/lan.yaml
  reject:
    type: http
    behavior: domain
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt
    path: ./ruleset/reject.yaml
    interval: 86400
  proxy:
    type: http
    behavior: domain
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/proxy.txt
    path: ./ruleset/proxy.yaml
    interval: 86400
  direct:
    type: http
    behavior: domain
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt
    path: ./ruleset/direct.yaml
    interval: 86400
  private:
    type: http
    behavior: domain
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/private.txt
    path: ./ruleset/private.yaml
    interval: 86400
  gfw:
    type: http
    behavior: domain
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt
    path: ./ruleset/gfw.yaml
    interval: 86400
  greatfire:
    type: http
    behavior: domain
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/greatfire.txt
    path: ./ruleset/greatfire.yaml
    interval: 86400
  tld-not-cn:
    type: http
    behavior: domain
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/tld-not-cn.txt
    path: ./ruleset/tld-not-cn.yaml
    interval: 86400
  telegramcidr:
    type: http
    behavior: ipcidr
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/telegramcidr.txt
    path: ./ruleset/telegramcidr.yaml
    interval: 86400
  applications:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/applications.txt
    path: ./ruleset/applications.yaml
    interval: 86400
  Disney:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Disney/Disney.yaml
    path: ./ruleset/disney.yaml
    interval: 86400
  Netflix:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Netflix/Netflix.yaml
    path: ./ruleset/netflix.yaml
    interval: 86400
  YouTube:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.yaml
    path: ./ruleset/youtube.yaml
    interval: 86400
  HBO:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/HBO/HBO.yaml
    path: ./ruleset/hbo.yaml
    interval: 86400
  OpenAI:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml
    path: ./ruleset/openai.yaml
    interval: 86400
  Bing:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Bing/Bing.yaml
    path: ./ruleset/bing.yaml
    interval: 86400
  Google:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.yaml
    path: ./ruleset/google.yaml
    interval: 86400
  GitHub:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.yaml
    path: ./ruleset/github.yaml
    interval: 86400
  Spotify:
    type: http
    behavior: classical
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml
    path: ./ruleset/spotify.yaml
    interval: 86400
  ChinaMaxDomain:
    type: http
    behavior: domain
    interval: 86400
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml
    path: ./Rules/ChinaMaxDomain.yaml
  ChinaMaxIPNoIPv6:
    type: http
    behavior: ipcidr
    interval: 86400
    url: https://mirror.ghproxy.com/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_IP_No_IPv6.yaml
    path: ./Rules/ChinaMaxIPNoIPv6.yaml
rules:
  - RULE-SET,YouTube,YouTube,no-resolve
  - RULE-SET,Google,Google,no-resolve
  - RULE-SET,GitHub,GitHub
  - RULE-SET,telegramcidr,Telegram,no-resolve
  - RULE-SET,Spotify,Spotify,no-resolve
  - RULE-SET,Netflix,Netflix
  - RULE-SET,HBO,HBO
  - RULE-SET,Bing,Bing
  - RULE-SET,OpenAI,OpenAI
  - RULE-SET,Disney,Disney
  - RULE-SET,proxy,全球代理
  - RULE-SET,gfw,全球代理
  - RULE-SET,applications,本地直连
  - RULE-SET,ChinaMaxDomain,本地直连
  - RULE-SET,ChinaMaxIPNoIPv6,本地直连,no-resolve
  - RULE-SET,lan,本地直连,no-resolve
  - GEOIP,CN,本地直连
  - MATCH,漏网之鱼
EOF

}


initRandomSalt() {
    local chars="abcdefghijklmnopqrtuxyz"
    local initCustomPath=
    for i in {1..10}; do
        echo "${i}" >/dev/null
        initCustomPath+="${chars:RANDOM%${#chars}:1}"
    done
    echo "${initCustomPath}"
}


subscribe() {
    readInstallProtocolType

    if echo "${currentInstallProtocolType}" | grep -q 0 && [[ -n "${configPath}" ]]; then

        echoContent skyBlue "-------------------------Remarks--------------------- ----------"
        echoContent yellow "# Viewing subscriptions will regenerate local account subscriptions"
        echoContent yellow "# When adding an account or modifying an account, you need to re-check the subscription before the subscription content for external access will be regenerated"
        echoContent red "# You need to manually enter the md5 encrypted salt value. If you don't know, just use random"
        echoContent yellow "# Does not affect the content of added remote subscriptions\n"

        if [[ -f "/etc/v2ray-agent/subscribe_local/subscribeSalt" && -n $(cat "/etc/v2ray-agent/subscribe_local/subscribeSalt") ]]; then
            read -r -p "Read the Salt set by the last installation. Do you want to use the Salt generated last time? [y/n]:" historySaltStatus
            if [[ "${historySaltStatus}" == "y" ]]; then
                subscribeSalt=$(cat /etc/v2ray-agent/subscribe_local/subscribeSalt)
            else
                read -r -p "Please enter the salt value, [Enter] use random:" subscribeSalt
            fi
        else
            read -r -p "Please enter the salt value, [Enter] use random:" subscribeSalt
        fi

        if [[ -z "${subscribeSalt}" ]]; then
            subscribeSalt=$(initRandomSalt)
        fi
        echoContent yellow "\n ---> Salt: ${subscribeSalt}"

        echo "${subscribeSalt}" >/etc/v2ray-agent/subscribe_local/subscribeSalt

        rm -rf /etc/v2ray-agent/subscribe/default/*
        rm -rf /etc/v2ray-agent/subscribe/clashMeta/*
        rm -rf /etc/v2ray-agent/subscribe_local/default/*
        rm -rf /etc/v2ray-agent/subscribe_local/clashMeta/*
        showAccounts >/dev/null

        if [[ -n $(ls /etc/v2ray-agent/subscribe_local/default/) ]]; then
            find /etc/v2ray-agent/subscribe_local/default/* | while read -r email; do
                email=$(echo "${email}" | awk -F "[d][e][f][a][u][l][t][/]" '{print $2}')
                local emailMd5=
                emailMd5=$(echo -n "${email}${subscribeSalt}"$'\n' | md5sum | awk '{print $1}')

                cat "/etc/v2ray-agent/subscribe_local/default/${email}" >>"/etc/v2ray-agent/subscribe/default/${emailMd5}"

                if [[ -f "/etc/v2ray-agent/subscribe_remote/default/${email}" ]]; then
                    echo >"/etc/v2ray-agent/subscribe_remote/default/${email}_tmp"
                    while read -r remoteUrl; do
                        updateRemoteSubscribe "${emailMd5}" "${email}" "${remoteUrl}" "default"
                    done < <(grep "VLESS_TCP/TLS_Vision" <"/etc/v2ray-agent/subscribe_remote/default/${email}" | awk -F "@" '{print $2}' | awk -F "?" '{print $1}')

                    echo >"/etc/v2ray-agent/subscribe_remote/default/${email}"
                    cat "/etc/v2ray-agent/subscribe_remote/default/${email}_tmp" >"/etc/v2ray-agent/subscribe_remote/default/${email}"
                    cat "/etc/v2ray-agent/subscribe_remote/default/${email}" >>"/etc/v2ray-agent/subscribe/default/${emailMd5}"
                fi

                local base64Result
                base64Result=$(base64 -w 0 "/etc/v2ray-agent/subscribe/default/${emailMd5}")
                echo "${base64Result}" >"/etc/v2ray-agent/subscribe/default/${emailMd5}"

                echoContent yellow "--------------------------------------------------------------"
                local currentDomain=${currentHost}

                if [[ -n "${currentDefaultPort}" && "${currentDefaultPort}" != "443" ]]; then
                    currentDomain="${currentHost}:${currentDefaultPort}"
                fi
                echoContent skyBlue "\n----------Default subscription----------\n"
                echoContent green "email:${email}\n"
                echoContent yellow "url:https://${currentDomain}/s/default/${emailMd5}\n"
                echoContent yellow "Online QR code: https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=https://${currentDomain}/s/default/${emailMd5}\n "
                echo "https://${currentDomain}/s/default/${emailMd5}" | qrencode -s 10 -m 1 -t UTF8

                if [[ -f "/etc/v2ray-agent/subscribe_local/clashMeta/${email}" ]]; then

                    cat "/etc/v2ray-agent/subscribe_local/clashMeta/${email}" >>"/etc/v2ray-agent/subscribe/clashMeta/${emailMd5}"

                    if [[ -f "/etc/v2ray-agent/subscribe_remote/clashMeta/${email}" ]]; then
                        echo >"/etc/v2ray-agent/subscribe_remote/clashMeta/${email}_tmp"
                        while read -r remoteUrl; do
                            updateRemoteSubscribe "${emailMd5}" "${email}" "${remoteUrl}" "ClashMeta"
                        done < <(grep -A3 "VLESS_TCP/TLS_Vision" <"/etc/v2ray-agent/subscribe_remote/clashMeta/${email}" | awk '/server:|port:/ {print $2}' | paste -d ':' - -)
                        echo >"/etc/v2ray-agent/subscribe_remote/clashMeta/${email}"
                        cat "/etc/v2ray-agent/subscribe_remote/clashMeta/${email}_tmp" >"/etc/v2ray-agent/subscribe_remote/clashMeta/${email}"
                        cat "/etc/v2ray-agent/subscribe_remote/clashMeta/${email}" >>"/etc/v2ray-agent/subscribe/clashMeta/${emailMd5}"
                    fi

                    sed -i '1i\proxies:' "/etc/v2ray-agent/subscribe/clashMeta/${emailMd5}"

                    local clashProxyUrl="https://${currentDomain}/s/clashMeta/${emailMd5}"
                    clashMetaConfig "${clashProxyUrl}" "${emailMd5}"
                    echoContent skyBlue "\n----------clashMeta subscription----------\n"
                    echoContent yellow "url:https://${currentDomain}/s/clashMetaProfiles/${emailMd5}\n"
                    echoContent yellow "Online QR code: https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=https://${currentDomain}/s/clashMetaProfiles/${emailMd5}\n "
                    echo "https://${currentDomain}/s/clashMetaProfiles/${emailMd5}" | qrencode -s 10 -m 1 -t UTF8
                fi

                echoContent skyBlue "--------------------------------------------------------------"
            done
        fi
    else
        echoContent red " ---> The disguise site is not installed and the subscription service cannot be used"
    fi
}


updateRemoteSubscribe() {
    local emailMD5=$1
    local email=$2
    local remoteUrl=$3
    local type=$4
    local remoteDomain=
    remoteDomain=$(echo "${remoteUrl}" | awk -F ":" '{print $1}')
    local serverAlias=
    serverAlias=$(grep "${remoteDomain}" <"/etc/v2ray-agent/subscribe_remote/remoteSubscribeUrl" | awk -F ":" '{print $3}')

    if [[ "${type}" == "ClashMeta" ]]; then
        local clashMetaProxies=
        clashMetaProxies=$(curl -s -4 "https://${remoteUrl}/s/clashMeta/${emailMD5}" | sed '/proxies:/d' | sed "s/${email}/${email}_${serverAlias}/g")
        if echo "${clashMetaProxies}" | grep -q "${email}"; then
            echo "${clashMetaProxies}" >>"/etc/v2ray-agent/subscribe_remote/clashMeta/${email}_tmp"

            echoContent green " ---> clashMeta subscription ${remoteDomain}:${email} updated successfully"
        else
            echoContent red " ---> clashMeta subscription ${remoteDomain}:${email} does not exist"
        fi
    elif [[ "${type}" == "default" ]]; then
        local default=
        default=$(curl -s -4 "https://${remoteUrl}/s/default/${emailMD5}" | base64 -d | sed "s/${email}/${email}_${serverAlias }/g")
        if echo "${default}" | grep -q "${email}"; then
            echo "${default}" >>"/etc/v2ray-agent/subscribe_remote/default/${email}_tmp"

            echoContent green " ---> Universal subscription ${remoteDomain}:${email} updated successfully"
        else
            echoContent red " ---> Universal subscription ${remoteDomain}:${email} does not exist"
        fi
    fi
}


switchAlpn() {
    echoContent skyBlue "\nFunction 1/${totalProgress}: switch alpn"
    if [[ -z ${currentAlpn} ]]; then
        echoContent red " ---> Unable to read alpn, please check whether it is installed"
        exit 0
    fi

    echoContent red "\n================================================ ================="
    echoContent green "The first bit of the current alpn is: ${currentAlpn}"
    echoContent yellow " 1. When http/1.1 is the first, trojan is available, and some gRPC clients are available [the client supports manual selection of alpn]"
    echoContent yellow " 2. When h2 is the first, gRPC is available, and some trojan clients are available [the client supports manual selection of alpn]"
    echoContent yellow " 3. If the client does not support manual alpn replacement, it is recommended to use this function to change the server alpn order to use the corresponding protocol"
    echoContent red "================================================== ==============="

    if [[ "${currentAlpn}" == "http/1.1" ]]; then
        echoContent yellow "1.Switch alpn h2 first"
    elif [[ "${currentAlpn}" == "h2" ]]; then
        echoContent yellow "1.Switch alpn http/1.1 first"
    else
        echoContent red 'does not comply'
    fi

    echoContent red "=============================================================="

    read -r -p "请选择:" selectSwitchAlpnType
    if [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "http/1.1" ]]; then

        local frontingTypeJSON
        frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.tlsSettings.alpn = [\"h2\",\"http/1.1\"]" ${configPath}${frontingType}.json)
        echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json

    elif [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "h2" ]]; then
        local frontingTypeJSON
        frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.tlsSettings.alpn =[\"http/1.1\",\"h2\"]" ${configPath}${frontingType}.json)
        echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json
    else
        echoContent red " ---> 选择错误"
        exit 0
    fi
    reloadCore
}

initRealityKey() {
    echoContent skyBlue "\n========================== Generate key ================= =========\n"
    if [[ -n "${currentRealityPublicKey}" ]]; then
        read -r -p "Read the last installation record. Do you want to use the PublicKey/PrivateKey from the last installation? [y/n]:" historyKeyStatus
        if [[ "${historyKeyStatus}" == "y" ]]; then
            realityPrivateKey=${currentRealityPrivateKey}
            realityPublicKey=${currentRealityPublicKey}
        fi
    fi
    if [[ -z "${realityPrivateKey}" ]]; then
        realityX25519Key=$(/etc/v2ray-agent/xray/xray x25519)
        realityPrivateKey=$(echo "${realityX25519Key}" | head -1 | awk '{print $3}')
        realityPublicKey=$(echo "${realityX25519Key}" | tail -n 1 | awk '{print $3}')
    fi
    echoContent green "\n privateKey:${realityPrivateKey}"
    echoContent green "\n publicKey:${realityPublicKey}"
}


checkRealityDest() {
    local traceResult=
    traceResult=$(curl -s "https://$(echo "${realityDestDomain}" | cut -d ':' -f 1)/cdn-cgi/trace" | grep "visit_scheme=https")
    if [[ -n "${traceResult}" ]]; then
        echoContent red "\n ---> The domain name used is detected, hosted on cloudflare and the proxy is enabled. Using this type of domain name may cause VPS traffic to be used by others [not recommended]\n"
        read -r -p "Continue? [y/n]" setRealityDestStatus
        if [[ "${setRealityDestStatus}" != 'y' ]]; then
            exit 0
        fi
        echoContent yellow "\n --->Ignore the risks and continue using"
    fi
}

initRealityDest() {
    if [[ -n "${domain}" ]]; then
        realityDestDomain=${domain}:${port}
    else
        local realityDestDomainList=
        realityDestDomainList="gateway.icloud.com,itunes.apple.com,swdist.apple.com,swcdn.apple.com,updates.cdn-apple.com,mensura.cdn-apple.com,osxapps.itunes.apple.com ,aod.itunes.apple.com,download-installer.cdn.mozilla.net,addons.mozilla.org,s0.awsstatic.com,d1.awsstatic.com,images-na.ssl-images-amazon.com,m .media-amazon.com,player.live-video.net,one-piece.com,lol.secure.dyn.riotcdn.net,www.lovelive-anime.jp,www.nokia.com"

        echoContent skyBlue "\n====== Generate domain name with configuration fallback. For example: [addons.mozilla.org:443] ======\n"
        echoContent green "Fallback domain name list: https://www.v2ray-agent.com/archives/1680104902581#heading-8\n"
        read -r -p "Please enter [Enter] to use random:" realityDestDomain
        if [[ -z "${realityDestDomain}" ]]; then
            local randomNum=
            randomNum=$((RANDOM % 24 + 1))
            realityDestDomain=$(echo "${realityDestDomainList}" | awk -F ',' -v randomNum="$randomNum" '{print $randomNum":443"}')
        fi
        if ! echo "${realityDestDomain}" | grep -q ":"; then
            echoContent red "\n ---> The domain name does not comply with the standard, please re-enter"
            initRealityDest
        else
            checkRealityDest
            echoContent yellow "\n ---> Fallback domain name: ${realityDestDomain}"
        fi
    fi
}


initRealityClientServersName() {
    if [[ -n "${domain}" ]]; then
        realityServerNames=\"${domain}\"
    elif [[ -n "${realityDestDomain}" ]]; then
        realityServerNames=$(echo "${realityDestDomain}" | cut -d ":" -f 1)

        realityServerNames=\"${realityServerNames//,/\",\"}\"
    else
        echoContent skyBlue "\n================ Configure serverNames available to the client ================\n"
        echoContent yellow "#Notes"
        echoContent green "List of serverNames available to the client: https://www.v2ray-agent.com/archives/1680104902581#heading-8\n"
        echoContent yellow "Input example: addons.mozilla.org\n"
        read -r -p "Please enter [Enter] to use random:" realityServerNames
        if [[ -z "${realityServerNames}" ]]; then
            realityServerNames=\"addons.mozilla.org\"
        else
            realityServerNames=\"${realityServerNames//,/\",\"}\"
        fi
    fi

    echoContent yellow "\n ---> Available client domain names: ${realityServerNames}\n"
}

initRealityPort() {
    if [[ -n "${currentRealityPort}" ]]; then
        read -r -p "Read the last installation record. Do you want to use the port from the last installation? [y/n]:" historyRealityPortStatus
        if [[ "${historyRealityPortStatus}" == "y" ]]; then
            realityPort=${currentRealityPort}
        fi
    fi
    if [[ -z "${realityPort}" ]]; then
        if [[ -n "${port}" ]]; then
            read -r -p "Do you use TLS+Vision port? [y/n]:" realityPortTLSVisionStatus
            if [[ "${realityPortTLSVisionStatus}" == "y" ]]; then
                realityPort=${port}
            fi
        fi
        if [[ -z "${realityPort}" ]]; then
            echoContent yellow "Please enter the port [Enter random 10000-30000]"
            read -r -p "port:" realityPort
            if [[ -z "${realityPort}" ]]; then
                realityPort=$((RANDOM % 20001 + 10000))
            fi
        fi
        if [[ -n "${realityPort}" && "${currentRealityPort}" == "${realityPort}" ]]; then
            handleXray stop
        else
            checkPort "${realityPort}"
        fi
    fi
    if [[ -z "${realityPort}" ]]; then
        initRealityPort
    else
        allowPort "${realityPort}"
        echoContent yellow "\n ---> Port: ${realityPort}"
    fi

}


initXrayRealityConfig() {
    echoContent skyBlue "\n进度  $1/${totalProgress} : 初始化 Xray-core reality配置"
    initRealityPort
    initRealityKey
    initRealityDest
    initRealityClientServersName
}

updateXrayRealityConfig() {

    local realityVisionResult
    realityVisionResult=$(jq -r ".inbounds[0].port = ${realityPort}" ${configPath}07_VLESS_vision_reality_inbounds.json)
    realityVisionResult=$(echo "${realityVisionResult}" | jq -r ".inbounds[0].streamSettings.realitySettings.dest = \"${realityDestDomain}\"")
    realityVisionResult=$(echo "${realityVisionResult}" | jq -r ".inbounds[0].streamSettings.realitySettings.serverNames = [${realityServerNames}]")
    realityVisionResult=$(echo "${realityVisionResult}" | jq -r ".inbounds[0].streamSettings.realitySettings.privateKey = \"${realityPrivateKey}\"")
    realityVisionResult=$(echo "${realityVisionResult}" | jq -r ".inbounds[0].streamSettings.realitySettings.publicKey = \"${realityPublicKey}\"")
    echo "${realityVisionResult}" | jq . >${configPath}07_VLESS_vision_reality_inbounds.json
    reloadCore
    echoContent green " ---> Modification completed"
}


xrayCoreRealityInstall() {
    totalProgress=13
    installTools 2
    installXray 3 false
    installXrayService 6
    initXrayConfig custom 7
    handleXray stop
    cleanUp v2rayClean
    sleep 2
    handleXray start
    showAccounts 8
}


manageReality() {

    echoContent skyBlue "\nProgress 1/1: reality management"
    echoContent red "\n================================================ ================="

    if [[ -n "${realityStatus}" ]]; then
        echoContent yellow "1. Reinstall"
        echoContent yellow "2.Uninstall"
        echoContent yellow "3. Change configuration"
    else
        echoContent yellow "1.Installation"
    fi
    echoContent yellow "4. Scan Reality domain name"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" installRealityStatus

    if [[ "${installRealityStatus}" == "1" ]]; then
        selectCustomInstallType="7"
        xrayCoreRealityInstall
    elif [[ "${installRealityStatus}" == "2" ]]; then
        unInstallXrayCoreReality
    elif [[ "${installRealityStatus}" == "3" ]]; then
        initXrayRealityConfig 1
        updateXrayRealityConfig
    elif [[ "${installRealityStatus}" == "4" ]]; then
        installRealityScanner
        realityScanner
    fi
}


installRealityScanner() {
    if [[ ! -f "/etc/v2ray-agent/xray/reality_scan/RealiTLScanner-linux-64" ]]; then
        version=$(curl -s https://api.github.com/repos/XTLS/RealiTLScanner/releases?per_page=1 | jq -r '.[]|.tag_name')
        wget -c -q -P /etc/v2ray-agent/xray/reality_scan/ "https://github.com/XTLS/RealiTLScanner/releases/download/${version}/RealiTLScanner-linux-64"
        chmod 655 /etc/v2ray-agent/xray/reality_scan/RealiTLScanner-linux-64
    fi
}


realityScanner() {
    echoContent skyBlue "\nProgress 1/1: Scanning Reality domain name"
    echoContent red "\n================================================ ================="
    echoContent yellow "# Notes"
    echoContent yellow "After the scan is completed, please check whether the content of the scanned website results is compliant or not at your own risk"
    echoContent red "Some IDCs do not allow scanning operations, such as bricklayers, please bear the risk at your own risk\n"
    echoContent yellow "1.Scan IPv4"
    echoContent yellow "2.Scan IPv6"
    echoContent red "================================================== ==============="
    read -r -p "Please select:" realityScannerStatus
    local type=
    if [[ "${realityScannerStatus}" == "1" ]]; then
        type=4
    elif [[ "${realityScannerStatus}" == "2" ]]; then
        type=6
    fi

    read -r -p "Some IDCs do not allow scanning operations, such as moving bricks. Please bear the risk at your own risk. Do you want to continue? [y/n]:" scanStatus

    if [[ "${scanStatus}" != "y" ]]; then
        exit 0
    fi

    publicIP=$(getPublicIP "${type}")
    echoContent yellow "IP:${publicIP}"
    if [[ -z "${publicIP}" ]]; then
        echoContent red " ---> Unable to obtain IP"
        exit 0
    fi

    read -r -p "Is the IP correct? [y/n]:" ipStatus
    if [[ "${ipStatus}" == "y" ]]; then
        echoContent yellow "The results are stored in the /etc/v2ray-agent/xray/reality_scan/result.log file\n"
        /etc/v2ray-agent/xray/reality_scan/RealiTLScanner-linux-64 -addr "${publicIP}" | tee /etc/v2ray-agent/xray/reality_scan/result.log
    else
        echoContent red " ---> Unable to read the correct IP"
    fi
}


manageHysteria() {
    echoContent skyBlue "\nProgress 1/1: Hysteria2 Management"
    echoContent red "\n================================================ ================="
    local hysteria2Status=
    if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config.json" ]] && grep -q 'hysteria2' </etc/v2ray -agent/sing-box/conf/config.json; then
        echoContent yellow "Depends on third-party sing-box\n"
        echoContent yellow "1. Reinstall"
        echoContent yellow "2.Uninstall"
        hysteria2Status=true
    else
        echoContent yellow "1.Installation"
    fi

    echoContent red "================================================== ==============="
    read -r -p "Please select:" installHysteria2Status
    if [[ "${installHysteria2Status}" == "1" ]]; then
        unInstallHysteriaCore
        singBoxHysteria2Install
    elif [[ "${installHysteria2Status}" == "2" && "${hysteria2Status}" == "true" ]]; then
        unInstallSingBox hysteria2
    fi
}


manageTuic() {
    echoContent skyBlue "\nProgress 1/1: Tuic Management"
    echoContent red "\n================================================ ================="
    local tuicStatus=
    if [[ -n "${singBoxConfigPath}" ]] && [[ -f "/etc/v2ray-agent/sing-box/conf/config.json" ]] && grep -q 'tuic' </etc/v2ray -agent/sing-box/conf/config.json; then
        echoContent yellow "Depends on third-party sing-box\n"
        echoContent yellow "1. Reinstall"
        echoContent yellow "2.Uninstall"
        tuicStatus=true
    else
        echoContent yellow "1.Installation"
    fi

    echoContent red "================================================== ==============="
    read -r -p "Please select:" installTuicStatus
    if [[ "${installTuicStatus}" == "1" ]]; then
        unInstallTuicCore
        singBoxTuicInstall
    elif [[ "${installTuicStatus}" == "2" && "${tuicStatus}" == "true" ]]; then
        unInstallSingBox tuic
    fi
}


singBoxLog() {
    cat <<EOF >/etc/v2ray-agent/sing-box/conf/config/log.json
        {
          "log": {
            "disabled": $1,
            "level": "debug",
            "output": "/etc/v2ray-agent/sing-box/box.log",
            "timestamp": true
          }
        }
EOF

    handleSingBox stop
    handleSingBox start
}

hysteriaVersionManageMenu() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Hysteria version management"
    if [[ ! -d "/etc/v2ray-agent/hysteria/" ]]; then
        echoContent red " ---> The installation directory is not detected, please execute the script to install the content"
        menu
        exit 0
    fi
    echoContent red "\n================================================ ================="
    echoContent yellow "1.Upgrade Hysteria"
    echoContent yellow "2.Close Hysteria"
    echoContent yellow "3.Open Hysteria"
    echoContent yellow "4. Restart Hysteria"
    echoContent red "================================================== ==============="

    read -r -p "Please select:" selectHysteriaType
    if [[ "${selectHysteriaType}" == "1" ]]; then
        installHysteria 1
        handleHysteria start
    elif [[ "${selectHysteriaType}" == "2" ]]; then
        handleHysteria stop
    elif [[ "${selectHysteriaType}" == "3" ]]; then
        handleHysteria start
    elif [[ "${selectHysteriaType}" == "4" ]]; then
        handleHysteria stop
        handleHysteria start
    fi
}


singBoxVersionManageMenu() {
echoContent skyBlue "\nProgress $1/${totalProgress}: sing-box version management"
    if [[ ! -f "/etc/v2ray-agent/sing-box/sing-box" ]]; then
        echoContent red " ---> The installer is not detected, please execute the script to install the content"
        menu
        exit 0
    fi
    echoContent red "\n================================================ ================="
    echoContent yellow "1.Upgrade sing-box"
    echoContent yellow "2.Close sing-box"
    echoContent yellow "3.Open sing-box"
    echoContent yellow "4. Restart sing-box"
    echoContent yellow "================================================== ==============="
    local logStatus=
    if [[ -n "${singBoxConfigPath}" && -f "${singBoxConfigPath}config/log.json" && "$(jq -r .log.disabled ${singBoxConfigPath}config/log.json)" == " false" ]]; then
        echoContent yellow "5. Close log"
        logStatus=true
    else
        echoContent yellow "5. Enable logging"
        logStatus=false
    fi

    echoContent yellow "6. View log"
    echoContent red "================================================== ==============="

    read -r -p "请选择:" selectTuicType
    if [[ "${selectTuicType}" == "1" ]]; then
        installSingBox 1
        handleSingBox start
    elif [[ "${selectTuicType}" == "2" ]]; then
        handleSingBox stop
    elif [[ "${selectTuicType}" == "3" ]]; then
        handleSingBox start
    elif [[ "${selectTuicType}" == "4" ]]; then
        handleSingBox stop
        handleSingBox start
    elif [[ "${selectTuicType}" == "5" ]]; then
        singBoxLog ${logStatus}
        if [[ "${logStatus}" == "false" ]]; then
            tail -f "${singBoxConfigPath}../box.log"
        fi
    elif [[ "${selectTuicType}" == "6" ]]; then
        tail -f "${singBoxConfigPath}../box.log"
    fi
}


tuicVersionManageMenu() {
    echoContent skyBlue "\nProgress $1/${totalProgress}: Tuic version management"
    if [[ ! -d "/etc/v2ray-agent/tuic/" ]]; then
        echoContent red " ---> The installation directory is not detected, please execute the script to install the content"
        menu
        exit 0
    fi
    echoContent red "\n================================================ ================="
    echoContent yellow "1.Upgrade Tuic"
    echoContent yellow "2. Close Tuic"
    echoContent yellow "3.Open Tuic"
    echoContent yellow "4. Restart Tuic"
    echoContent red "================================================== ==============="

    read -r -p "Please select:" selectTuicType
    if [[ "${selectTuicType}" == "1" ]]; then
        installTuic 1
        handleTuic start
    elif [[ "${selectTuicType}" == "2" ]]; then
        handleTuic stop
    elif [[ "${selectTuicType}" == "3" ]]; then
        handleTuic start
    elif [[ "${selectTuicType}" == "4" ]]; then
        handleTuic stop
        handleTuic start
    fi
}


menu() {
    cd "$HOME" || exit
    echoContent red "\n================================================ ================="
    echoContent green "Author: mack-a"
    echoContent green "Current version: v2.11.25"
    echoContent green "Github: https://github.com/mack-a/v2ray-agent"
    echoContent green "Description: 8-in-1 coexistence script\c"
    showInstallStatus
    checkWgetShowProgress
    echoContent red "\n============================ Promotion area================ ============"
    echoContent red " "
    echoContent green "VPS purchasing guide: https://www.v2ray-agent.com/archives/1679975663984"
    echoContent green "Low-price VPS AS4837 with an annual payment of 10 US dollars: https://www.v2ray-agent.com/archives/racknerdtao-can-zheng-li-nian-fu-10mei-yuan"
    echoContent red "================================================== ==============="
    if [[ -n "${coreInstallType}" ]]; then
        echoContent yellow "1. Reinstall"
    else
        echoContent yellow "1.Installation"
    fi

    echoContent yellow "2. Install in any combination"
    if echo ${currentInstallProtocolType} | grep -q trojan; then
        echoContent yellow "3.Switch VLESS[XTLS]"
    elif echo ${currentInstallProtocolType} | grep -q 0; then
        echoContent yellow "3.Switch Trojan[XTLS]"
    fi

    echoContent yellow "4.Hysteria2 Management"
    echoContent yellow "5.REALITY Management"
    echoContent yellow "6.Tuic Management"
    echoContent skyBlue "-------------------------Tool Management-------------------- ---------"
    echoContent yellow "7.Account management"
    echoContent yellow "8. Change the camouflage station"
    echoContent yellow "9. Update certificate"
    echoContent yellow "10. Change CDN node"
    echoContent yellow "11. Diversion tool"
    echoContent yellow "12.Add new port"
    echoContent yellow "13.BT download management"
    echoContent yellow "15.Domain name blacklist"
    echoContent skyBlue "-------------------------Version Management-------------------- ---------"
    echoContent yellow "16.core management"
    echoContent yellow "17.Update script"
    echoContent yellow "18. Install BBR and DD scripts"
    echoContent skyBlue "-------------------------Script Management-------------------- ---------"
    echoContent yellow "19. View log"
    echoContent yellow "20. Uninstall script"
    echoContent red "================================================== ==============="
    mkdirTools
    aliasInstall
    read -r -p "Please select:" selectInstallType
    case ${selectInstallType} in
    1)
        selectCoreInstall
        ;;
    2)
        selectCoreInstall
        ;;
    3)
        initXrayFrontingConfig 1
        ;;
    4)
        manageHysteria
        ;;
    5)
        manageReality 1
        ;;
    6)
        manageTuic
        ;;
    7)
        manageAccount 1
        ;;
    8)
        updateNginxBlog 1
        ;;
    9)
        renewalTLS 1
        ;;
    10)
        updateV2RayCDN 1
        ;;
    11)
        routingToolsMenu 1
        ;;
    12)
        addCorePort 1
        ;;
    13)
        btTools 1
        ;;
    14)
        switchAlpn 1
        ;;
    15)
        blacklist 1
        ;;
    16)
        coreVersionManageMenu 1
        ;;
    17)
        updateV2RayAgent 1
        ;;
    18)
        bbrInstall
        ;;
    19)
        checkLog 1
        ;;
    20)
        unInstall 1
        ;;
    esac
}
cronFunction
menu
