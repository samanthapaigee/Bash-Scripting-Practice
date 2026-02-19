#! /bin/bash

rpm_path="(ask ed/nadeem the typical file path for releases)"
log_file="/var/log/powerhselloffline.log"

check_powershell () {
  if command -v pwsh >/dev/null 2>&1 || command -v powerhsell >/dev/null 2>&1; then
    echo "Powershell already installed"
    exit 0
  else
    echo "Powershell not found, proceeding with installation"
  fi
}

echo "Checking installation"
check_powershell

echo "Starting Powershell installation" | tee -a "$log_file"

#ensure root perms
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" | tee -a "log_file"
  exit 1
fi

#check file path
if [[ ! -f "$rpm_path" ]]; then
  echo "RPM file not found" | tee -a "log_file"
  exit 1
fi

echo "Installing Powerhsell RPM" | tee -a "log_file"

dnf install -y --nogpgcheck "$rpm_path"

if command -v pwsh &> /dev/null; then
  echo "Powershell installed successfully"
else
  echo "Powershell installation failed"
  exit 1
fi

echo "System will reboot in 30 seconds. Run pwsh upon reboot to verify installation"
sleep 30

reboot
