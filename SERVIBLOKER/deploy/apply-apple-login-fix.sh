#!/bin/bash
# Run on the VPS with the replacement script as the first argument.
set -Eeuo pipefail
candidate=${1:?replacement script required}
target=/usr/local/sbin/blockservi-alwaysblock
backup_dir=$(mktemp -d /root/blockservi-apple-login-backup.XXXXXX)
cp -p "$target" "$backup_dir/alwaysblock"
iptables-save > "$backup_dir/iptables.v4"
iptables -S FORWARD > "$backup_dir/forward.before"
{
  echo '*filter'
  echo '-F BLOCKSERVI-ALWAYS'
  iptables -S BLOCKSERVI-ALWAYS | sed -n '/^-A /p'
  echo COMMIT
} > "$backup_dir/rollback.rules"
iptables-restore --wait 10 --noflush --test < "$backup_dir/rollback.rules"
rollback() {
  trap - ERR
  cp -p "$backup_dir/alwaysblock" "$target"
  if ! iptables-restore --wait 10 --noflush < "$backup_dir/rollback.rules"; then
    echo "ERROR: active-rule rollback failed; backup: $backup_dir" >&2
    exit 2
  fi
  echo "Change failed; script and active chain restored: $backup_dir" >&2
  exit 1
}
sh -n "$candidate"
trap rollback ERR
install -m 755 "$candidate" "$target"
"$target"
iptables -S FORWARD > "$backup_dir/forward.after"
cmp "$backup_dir/forward.before" "$backup_dir/forward.after"
iptables -S BLOCKSERVI-ALWAYS
systemctl is-active blockservi strongswan-starter
trap - ERR
printf 'Backup: %s\n' "$backup_dir"
