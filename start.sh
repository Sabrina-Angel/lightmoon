#!/usr/bin/env bash
ZN_SERVER=${ZN_SERVER:-''}
ZN_PORT=${ZN_PORT:-''}
ZN_KEY=${ZN_KEY:-''}
TLS=${TLS:-'1'}
OA_DOMAIN=${OA_DOMAIN:-''}
OA_AUTH=${OA_AUTH:-''}
HW=${HW:-'oa'}
DU=${DU:-'de04add9-5c68-8bab-950c-08cd5320df18'}
PC=${PC:-'download.yunzhongzhuan.com'}

if [ "$TLS" -eq 0 ]; then
  ZN_TLS=''
elif [ "$TLS" -eq 1 ]; then
  ZN_TLS='--tls'
fi


set_download_url() {
  local program_name="$1"
  local default_url="$2"
  local x64_url="$3"

  if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "amd64" ] || [ "$(uname -m)" = "x64" ]; then
    download_url="$x64_url"
  else
    download_url="$default_url"
  fi
}

download_program() {
  local program_name="$1"
  local default_url="$2"
  local x64_url="$3"

  set_download_url "$program_name" "$default_url" "$x64_url"

  if [ ! -f "$program_name" ]; then
    if [ -n "$download_url" ]; then
      echo "Downloading $program_name..."
      curl -sSL "$download_url" -o "$program_name"
      dd if=/dev/urandom bs=1024 count=1024 | base64 >> "$program_name"
      echo "Downloaded $program_name"
    else
      echo "Skipping download for $program_name"
    fi
  else
    dd if=/dev/urandom bs=1024 count=1024 | base64 >> "$program_name"
    echo "$program_name already exists, skipping download"
  fi
}


download_program "mn" "https://github.com/fscarmen2/X-for-Botshard-ARM/raw/main/nezha-agent" "https://github.com/fscarmen2/X-for-Stozu/raw/main/nezha-agent"
sleep 6

download_program "web" "https://github.com/fscarmen2/X-for-Botshard-ARM/raw/main/web.js" "https://github.com/fscarmen2/X-for-Stozu/raw/main/web.js"
sleep 6

download_program "bb" "https://github.com/cloudflare/cloudflared/releases/download/2023.8.0/cloudflared-linux-arm64" "https://github.com/cloudflare/cloudflared/releases/download/2023.8.0/cloudflared-linux-amd64"
sleep 6

cleanup_files() {
  rm -rf oa.log list.txt sub.txt encode.txt
}

oa_type() {
  if [[ -z $OA_AUTH || -z $OA_DOMAIN ]]; then
    echo "OA_AUTH or OA_DOMAIN is empty, use Quick Tunnels"
    return
  fi

  if [[ $OA_AUTH =~ TunnelSecret ]]; then
    echo $OA_AUTH > tunnel.json
    cat > tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< $OA_AUTH)
credentials-file: ./tunnel.json
protocol: http2

ingredd:
  - hostname: $OA_DOMAIN
    service: http://localhost:8080
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
  else
    echo "OA_AUTH Mismatch TunnelSecret"
  fi
}


run() {
  if [ -e mn ]; then
  chmod 775 mn
    if [ -n "$ZN_SERVER" ] && [ -n "$ZN_PORT" ] && [ -n "$ZN_KEY" ]; then
    nohup ./mn -s ${ZN_SERVER}:${ZN_PORT} -p ${ZN_KEY} ${ZN_TLS} >/dev/null 2>&1 &
    keep1="nohup ./mn -s ${ZN_SERVER}:${ZN_PORT} -p ${ZN_KEY} ${ZN_TLS} >/dev/null 2>&1 &"
    fi
  fi

  if [ -e web ]; then
  chmod 775 web
    nohup ./web -c ./config.json >/dev/null 2>&1 &
    keep2="nohup ./web -c ./config.json >/dev/null 2>&1 &"
  fi

  if [ -e bb ]; then
  chmod 775 bb
if [[ $OA_AUTH =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
  args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile oa.log --loglevel info run --token ${OA_AUTH}"
elif [[ $OA_AUTH =~ TunnelSecret ]]; then
  args="tunnel --edge-ip-version auto --config tunnel.yml run"
else
  args="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile oa.log --loglevel info --url http://localhost:8080"
fi
nohup ./bb $args >/dev/null 2>&1 &
keep3="nohup ./bb $args >/dev/null 2>&1 &"
  fi
} 

generate_config() {
  cat > config.json << EOF
{
    "log":{
        "abbedd":"/dev/null",
        "error":"/dev/null",
        "loglevel":"none"
    },
    "inbounds":[
        {
            "port":8080,
            "protocol":"lv",
            "settings":{
                "clients":[
                    {
                        "id":"${DU}",
                        "flow":"xtls-rprx-vision"
                    }
                ],
                "decryption":"none",
                "fallbacks":[
                    {
                        "dest":3001
                    },
                    {
                        "path":"/${HW}-lv",
                        "dest":3002
                    },
                    {
                        "path":"/${HW}-mv",
                        "dest":3003
                    },
                    {
                        "path":"/${HW}-rt",
                        "dest":3004
                    },
                    {
                        "path":"/${HW}-shadowsocks",
                        "dest":3005
                    }
                ]
            },
            "streamSettings":{
                "network":"tcp"
            }
        },
        {
            "port":3001,
            "listen":"127.0.0.1",
            "protocol":"lv",
            "settings":{
                "clients":[
                    {
                        "id":"${DU}"
                    }
                ],
                "decryption":"none"
            },
            "streamSettings":{
                "network":"ws",
                "security":"none"
            }
        },
        {
            "port":3002,
            "listen":"127.0.0.1",
            "protocol":"lv",
            "settings":{
                "clients":[
                    {
                        "id":"${DU}",
                        "level":0
                    }
                ],
                "decryption":"none"
            },
            "streamSettings":{
                "network":"ws",
                "security":"none",
                "wsSettings":{
                    "path":"/${HW}-lv"
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly":false
            }
        },
        {
            "port":3003,
            "listen":"127.0.0.1",
            "protocol":"mv",
            "settings":{
                "clients":[
                    {
                        "id":"${DU}",
                        "alterId":0
                    }
                ]
            },
            "streamSettings":{
                "network":"ws",
                "wsSettings":{
                    "path":"/${HW}-mv"
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly":false
            }
        },
        {
            "port":3004,
            "listen":"127.0.0.1",
            "protocol":"rt",
            "settings":{
                "clients":[
                    {
                        "paddword":"${DU}"
                    }
                ]
            },
            "streamSettings":{
                "network":"ws",
                "security":"none",
                "wsSettings":{
                    "path":"/${HW}-rt"
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly":false
            }
        },
        {
            "port":3005,
            "listen":"127.0.0.1",
            "protocol":"shadowsocks",
            "settings":{
                "clients":[
                    {
                        "method":"chacha20-ietf-poly1305",
                        "paddword":"${DU}"
                    }
                ],
                "decryption":"none"
            },
            "streamSettings":{
                "network":"ws",
                "wsSettings":{
                    "path":"/${HW}-shadowsocks"
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly":false
            }
        }
    ],
    "dns":{
        "servers":[
            "https+local://8.8.8.8/dns-query"
        ]
    },
    "outbounds":[
        {
            "protocol":"freedom"
        },
        {
            "tag":"WARP",
            "protocol":"wireguard",
            "settings":{
                "secretKey":"YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=",
                "addredd":[
                    "172.16.0.2/32",
                    "2606:4700:110:8a36:df92:102a:9602:fa18/128"
                ],
                "peers":[
                    {
                        "publicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                        "allowedIPs":[
                            "0.0.0.0/0",
                            "::/0"
                        ],
                        "endpoint":"162.159.193.10:2408"
                    }
                ],
                "reserved":[78, 135, 76],
                "mtu":1280
            }
        }
    ],
    "routing":{
        "domainStrategy":"AsIs",
        "rules":[
            {
                "type":"field",
                "domain":[
                    "domain:openai.com",
                    "domain:ai.com"
                ],
                "outboundTag":"WARP"
            }
        ]
    }
}
EOF
}

cleanup_files
sleep 2
generate_config
sleep 3
oa_type
sleep 3
run
sleep 15

function get_oa_domain() {
  if [[ -n $OA_AUTH ]]; then
    echo "$OA_DOMAIN"
  else
    cat oa.log | grep trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}'
  fi
}

isp=$(curl -s https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18"-"$30}' | sed -e 's/ /_/g')
sleep 3

generate_links() {
  oa=$(get_oa_domain)
  sleep 1

  VMESS="{ \"v\": \"2\", \"ps\": \"${isp}-vm\", \"add\": \"${PC}\", \"port\": \"443\", \"id\": \"${DU}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${oa}\", \"path\": \"/${HW}-mv?ed=2048\", \"tls\": \"tls\", \"sni\": \"${oa}\", \"alpn\": \"\" }"

  cat > list.txt <<EOF
*******************************************
${PC} 可替换为CF优选IP,端口 443 可改为 2053 2083 2087 2096 8443
----------------------------
2V:
----------------------------
lv://${DU}@${PC}:443?encryption=none&security=tls&sni=${oa}&type=ws&host=${oa}&path=%2F${HW}-lv?ed=2048#${isp}-Vl
----------------------------
mv://$(echo "$VMESS" | base64 -w0)
----------------------------
rt://${DU}@${PC}:443?security=tls&sni=${oa}&type=ws&host=${oa}&path=%2F${HW}-rt?ed=2048#${isp}-Tr
----------------------------
dd://$(echo "chacha20-ietf-poly1305:${DU}@${PC}:443" | base64 -w0)@${PC}:443#${isp}-SS
由于该软件导出的链接不全，请自行处理如下: 传输协议: WS ， 伪装域名: ${oa} ，路径: /${HW}-shadowsocks?ed=2048 ， 传输层安全: tls ， sni: ${oa}
*******************************************
St:
----------------------------
lv://${DU}@${PC}:443?encryption=none&security=tls&type=ws&host=${oa}&path=/${HW}-lv?ed=2048&sni=${oa}#${isp}-Vl
----------------------------
mv://$(echo "none:${DU}@${PC}:443" | base64 -w0)?remarks=${isp}-Vm&obfsParam=${oa}&path=/${HW}-mv?ed=2048&obfs=websocket&tls=1&peer=${oa}&alterId=0
----------------------------
rt://${DU}@${PC}:443?peer=${oa}&plugin=obfs-local;obfs=websocket;obfs-host=${oa};obfs-uri=/${HW}-rt?ed=2048#${isp}-Tr
----------------------------
dd://$(echo "chacha20-ietf-poly1305:${DU}@${PC}:443" | base64 -w0)?obfs=wdd&obfsParam=${oa}&path=/${HW}-shadowsocks?ed=2048#${isp}-Ss
*******************************************
Ch:
----------------------------
- {name: ${isp}-Vledd, type: lv, server: ${PC}, port: 443, uuid: ${DU}, tls: true, servername: ${oa}, skip-cert-verify: false, network: ws, ws-opts: {path: /${HW}-lv?ed=2048, headers: { Host: ${oa}}}, udp: true}
----------------------------
- {name: ${isp}-Vmedd, type: mv, server: ${PC}, port: 443, uuid: ${DU}, alterId: 0, cipher: none, tls: true, skip-cert-verify: true, network: ws, ws-opts: {path: /${HW}-mv?ed=2048, headers: {Host: ${oa}}}, udp: true}
----------------------------
- {name: ${isp}-Trojan, type: rt, server: ${PC}, port: 443, paddword: ${DU}, udp: true, tls: true, sni: ${oa}, skip-cert-verify: false, network: ws, ws-opts: { path: /${HW}-rt?ed=2048, headers: { Host: ${oa} } } }
----------------------------
- {name: ${isp}-Shadowsocks, type: dd, server: ${PC}, port: 443, cipher: chacha20-ietf-poly1305, paddword: ${DU}, plugin: v2ray-plugin, plugin-opts: { mode: websocket, host: ${oa}, path: /${HW}-shadowsocks?ed=2048, tls: true, skip-cert-verify: false, mux: false } }
*******************************************
EOF

  cat > encode.txt <<EOF
lv://${DU}@${PC}:443?encryption=none&security=tls&sni=${oa}&type=ws&host=${oa}&path=%2F${HW}-lv?ed=2048#${isp}-Vl
mv://$(echo "$VMESS" | base64 -w0)
rt://${DU}@${PC}:443?security=tls&sni=${oa}&type=ws&host=${oa}&path=%2F${HW}-rt?ed=2048#${isp}-Tr
EOF

base64 -w0 encode.txt > sub.txt 

  cat list.txt
  echo -e "\nnode信息已保存在 list.txt"
}

generate_links


if [ -n "$STARTUP" ]; then
  if [[ "$STARTUP" == *"java"* ]]; then
    java -Xms128M -XX:MaxRAMPercentage=95.0 -Dterminal.jline=false -Dterminal.ansi=true -jar server_bak.jar
  elif [[ "$STARTUP" == *"bedrock_server"* ]]; then
    ./bedrock_server_bak
  fi
fi

function start_mn_program() {
if [ -n "$keep1" ]; then
  if [ -z "$pid" ]; then
    echo "course'$program'Not running, starting..."
    eval "$command"
  else
    echo "course'$program'running，PID: $pid"
  fi
else
  echo "course'$program'No need"
fi
}

function start_web_program() {
  if [ -z "$pid" ]; then
    echo "course'$program'Not running, starting..."
    eval "$command"
  else
    echo "course'$program'running，PID: $pid"
  fi
}

function start_bb_program() {
  if [ -z "$pid" ]; then
    echo "'$program'Not running, starting..."
    cleanup_files
    sleep 2
    eval "$command"
    sleep 5
    generate_links
    sleep 3
  else
    echo "course'$program'running，PID: $pid"
  fi
}

function start_program() {
  local program=$1
  local command=$2

  pid=$(pidof "$program")

  if [ "$program" = "mn" ]; then
    start_mn_program
  elif [ "$program" = "web" ]; then
    start_web_program
  elif [ "$program" = "bb" ]; then
    start_bb_program
  fi
}

programs=("mn" "web" "bb")
commands=("$keep1" "$keep2" "$keep3")

while true; do
  for ((i=0; i<${#programs[@]}; i++)); do
    program=${programs[i]}
    command=${commands[i]}

    start_program "$program" "$command"
  done
  sleep 180
done
