# 基础镜像
FROM ubuntu:22.04

# 1) 系统依赖安装
RUN apt update \
 && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends \
      python3 python3-pip python2 tzdata \
      curl ca-certificates wget unzip git build-essential \
      zmap graphviz jq golang-go \
      python3-geoip2 python3-netaddr python3-dateutil \
      python3-jsonpickle python3-pympler python3-wordcloud \
      python3-plotly python3-networkx python3-cryptography \
 && rm -rf /var/lib/apt/lists/*

# 2) 安装 pip2 并补 pytz
RUN curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py | python2 \
 && pip2 install pytz

# 3) 安装 zgrab（Go 版）并软链
RUN go install github.com/zmap/zgrab@latest \
 && ln -sf "$(go env GOPATH)/bin/zgrab" /usr/local/bin/zgrab

# 4) 设置默认 HOME 目录、工作目录及路径
ENV HOME=/root
ENV SURVEYS_DIR=$HOME/code/surveys
ENV OUTPUT_DIR=$HOME/data/smtp/runs
WORKDIR $SURVEYS_DIR

# 5) 拷贝整个项目到容器内
COPY . $SURVEYS_DIR

# 6) 确保所有脚本可执行
RUN chmod +x skey-all.sh install-deps.sh mm_update.sh

# 7) 创建输出目录，并保证可写
RUN mkdir -p $OUTPUT_DIR \
 && chown -R root:root $OUTPUT_DIR

# 8) 修正 install-deps.sh：去除 sudo、修复 cipher-mapping URL
RUN sed -i '/sudo\s\+/d' install-deps.sh \
 && sed -i 's|https://testssl.sh/etc/cipher-mapping.txt|https://testssl.sh/2.9.5/etc/cipher-mapping.txt|' install-deps.sh

# 9) 安装 Python3 依赖（通过项目自带的 install-deps.sh）
RUN ./install-deps.sh

# 10) 容器入口：先根据环境变量自动更新 GeoLite2 数据库，再执行 skey-all.sh
ENTRYPOINT [ "bash", "-lc", "\
  if [ -n \"$MAXMIND_LICENSE_KEY\" ]; then \
    echo \"[INFO] Updating GeoLite2 DB with key from env\"; \
    ./mm_update.sh -k \"$MAXMIND_LICENSE_KEY\"; \
  else \
    echo \"[WARN] MAXMIND_LICENSE_KEY not set; skipping GeoLite2 update\"; \
  fi; \
  exec ./skey-all.sh \"$@\" \
"]

# 11) 默认参数：扫描 IE、启用 maxmind、将结果输出到 ./results（相对于工作目录 $SURVEYS_DIR）
CMD ["-c", "IE", "-mm", "-r", "./results"]
