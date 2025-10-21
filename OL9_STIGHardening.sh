#! /bin/bash
#STIG Hardening

#exit if a command exits w/ a non-zero status
set -euo pipefail

#backup existing file
backup_file() {
  local file=$1
  if [[ -f "$file" ]]; then
    cp -p "$file" "${file}.bak_$(date +%F_%T)"
    echo "[+] Backed up: $file"
  fi
}

echo "Applying STIG setting for Oracle Linux 9"


echo "[+] Configuring system settings"
backup_file /etc/sysctl.d
# EOF allows you to input multiple lines of text directly into a file w/o needing to escape/use special characters
cat <<EOF >> /etc/sysctl.d
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.all.log_martians=1


echo "[+] Configuring networking settings"
backup_file /etc/NetworkManager/NetworkManager.conf
cat <<EOF >> /etc/NetworkManager/NetworkManager.conf
dns=none
echo "[+] Restarting Network Manager"
systemctl reload NetworkManager
EOF

echo "[+] Chmod Cron Configuration Directories"
cron_perms=$(find /etc/cron* -type d | xargs stat -c "%a %n")
echo "$cron_perms"
sudo chmod 0700 /etc/cron*


echo "[+] Configuring SSH settings"
backup_file /etc/ssh/sshd_config
cat <<EOF >> /etc/ssh/sshd_config
ClientAliveInterval 600
PermitRootLogin no
echo "[+] Restarting SSH"
systemctl restart sshd.service
EOF

echo "[+] Configuring Logon/Logoff and GUI settings"
backup_file /etc/gdm/custom.conf
cat <<EOF >> /etc/gdm/custom.conf
AutomaticLoginEnable=false
EOF

cat <<EOF >> /etc/dconf/db/local.d/00-security-settings
[org/gnome/settings-daemon/peripherals/smartcard]
removal-action='lock-screen'
disable-restart-buttons='true'
/org/gnome/settings-daemon/peripherals/smartcard/removal-action
/org/gnome/desktop/media-handling/autorun-never
/org/gnome/desktop/media-handling/automount-open
[org/gnome/settings-daemon/plugins/media-keys]
logout=['']
[org/gnome/desktop/screensaver]
picture-uri=''
[org/gnome/desktop/media-handling]
automount-open=false
EOF

cat <<EOF >> /etc/dconf/db/local.d/00-security-settings-lock
/org/gnome/desktop/screensaver/picture-uri
EOF

cat <<EOF >> /etc/dconf/db/local.d/locks/session
/org/gnome/settings-daemon/plugins/media-keys/logout
/org/gnome/login-screen/disable-restart-buttons
/org/gnome/login-screen/banner-message-enable
EOF

echo "[+] Updating dconf system databases"
dconf update

echo "[+] Configuring password and encryption settings"
backup_file /etc/login.defs
cat <<EOF >> /etc/login.defs
SHA_CRYPT_MIN_ROUNDS 100000
SHA_CRYPT_MAX_ROUNDS 100000
EOF

backup_file /etc/pam.d/system-auth
cat <<EOF >> /etc/pam.d/system-auth
password sufficient pam_unix.so sha512 rounds=100000
password required pam_pwquality.so
EOF

backup_file /etc/pam.d/password-auth
cat <<EOF >> /etc/pam.d/password-auth
password sufficient pam_unix.so sha512 rounds=100000
password required pam_pwquality.so
EOF

echo "[+] Configuring audit settings"
backup_file /etc/audit/rules.d/audit.rules
cat <<EOF >> /etc/audit/rules.d/audit.rules
-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown
-a always,exit -F path=/usr/sbin/reboot -F perm=x -F auid>=1000 -F auid!=unset -k privileged-reboot
-a always,exit -F path=/usr/sbin/poweroff -F perm=x -F auid>=1000 -F auid!=unset -k privileged-poweroff
-a always,exit -F path=/usr/sbin/init -F perm=x -F auid>=1000 -F auid!=unset -k privileged-init
-w /var/log/tallylog -p wa -k logins
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv 
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv 
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd
EOF

echo "[+] Restarting Audit Service"
service auditd restart


echo "[+] Verifying that OL 9 software repositories have been configured correctly"
config_check=$(grep gpgcheck /etc/yum.repos.d/*.repo | more
gpgcheck = 1)
if [-z "$config_check"]; then
  echo "[!] No repositories have 'gpgcheck=1' — applying fix..."
  sudo sed -i 's/^[[:space:]]*gpgcheck[[:space:]]*=.*/gpgcheck=1/g' /etc/yum.repos.d/*.repo
else
    echo "[+] gpgcheck already set to 1 in one or more repo files:"
    echo "$config_check"
fi

localpkg_check=$(grep localpkg_gpgcheck /etc/dnf/dnf.conf 
localpkg_gpgcheck=1)
if [-z "$localpkg_check"]; then
  echo "[!] No repositories have 'localpkg_gpgcheck=1' — applying fix..."
  cat <<EOF >> /etc/dnf/dnf.conf
  localpkg_gpgcheck=1
else
    echo "[+] localpkg_gpgcheck already set to 1 in one or more repo files:"
    echo "$localpkg_check"
fi


echo "[+] Verifying that OL 9 has Advanced Intrusion Detection Environment (AIDE) package installed"
if ! rpm -q aide &>/dev/null; then
    echo "[!] AIDE is not installed — installing now..."
    sudo dnf install -y aide
    echo "[+] Initializing AIDE database..."
    sudo /usr/sbin/aide --init
    echo "[✓] AIDE installation and initialization complete."
else
    echo "[+] AIDE is already installed."
fi


sudo firewall-cmd --set-default-zone=drop
sudo firewall-cmd --permanent --zone=drop --change-interface=ens33
sudo firewall-cmd --reload


cat <<EOF >> /etc/modprobe.d/cramfs.conf
install cramfs /bin/false
blacklist cramfs
EOF

cat <<EOF >> /etc/modprobe.d/tipc.conf
install tipc /bin/false
blacklist tipc
EOF

cat <<EOF >> /etc/modprobe.d/sctp.conf
install sctp /bin/false
blacklist sctp
EOF

cat <<EOF >> /etc/modprobe.d/can.conf
install can /bin/false
blacklist can
EOF

cat <<EOF >> /etc/modprobe.d/atm.conf
install atm /bin/false
blacklist atm
EOF
