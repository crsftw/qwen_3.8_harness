# Kali LARGE toolset (kali-linux-large metapackage). VERY big image (many GB from Kali repos).
# NOTE: many of these tools (responder, bettercap, masscan, SYN scans, etc.) require root +
# NET_RAW/NET_ADMIN and/or L2 network access to actually function. The current run-kali.sh still
# runs non-root with cap-drop=ALL on a bridge, so those L2/raw tools are installed but INERT until
# the root/macvlan escalation is applied. L3 tools (nmap -sT, nikto, gobuster, sqlmap, ...) work now
# -- but nmap needs the file-capability strip below (see the setcap -r line) or its execve is EPERM'd.
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
        kali-linux-large python3 \
    && rm -rf /var/lib/apt/lists/*

# Kali's nmap package ships the real binary at /usr/lib/nmap/nmap with file capabilities
# (cap_net_admin,cap_net_raw,cap_net_bind_service=eip) behind a /usr/bin/nmap wrapper script.
# cap_net_admin is OUTSIDE Docker's default capability bounding set, and because the caps carry
# the effective bit, the kernel refuses the execve() with EPERM ("Operation not permitted") in our
# non-root cap-drop=ALL container -- breaking BOTH kali_nmap and kali_shell nmap. We only ever run
# -sT connect scans (no raw sockets), so strip the caps to make the binary executable again; raw/SYN
# scans stay impossible under cap-drop=ALL regardless, which is the intended posture.
RUN setcap -r /usr/lib/nmap/nmap

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin kali
COPY kali_mcp.py /opt/kali_mcp.py
USER kali
WORKDIR /home/kali
ENTRYPOINT ["python3", "/opt/kali_mcp.py"]
