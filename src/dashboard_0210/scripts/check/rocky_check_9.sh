#!/bin/bash

resultfile="results.txt"
: > "$resultfile"

U_01() {
  local code="U-01"
  local item="root 계정 원격접속 제한"
  local severity="상"
  local status="양호"
  local reason="원격 접속 제한 설정이 가이드라인을 준수하고 있습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local VULN=0
  local REASON=""

  if systemctl is-active sshd &>/dev/null; then
    local ROOT_LOGIN
    ROOT_LOGIN="$(sshd -T 2>/dev/null | grep -i '^permitrootlogin' | awk '{print $2}')"

    if [[ "$ROOT_LOGIN" != "no" ]]; then
      VULN=1
      REASON="[SSH] PermitRootLogin이 no가 아닙니다 ($ROOT_LOGIN)."
    fi
  fi

  if systemctl is-active telnet.socket &>/dev/null || systemctl is-active telnet.service &>/dev/null; then
    
    if [ -f /etc/pam.d/login ]; then
      if ! grep -vE '^#|^\s#' /etc/pam.d/login | grep -qi 'pam_securetty.so'; then
        VULN=1
        REASON="${REASON} [Telnet] /etc/pam.d/login에 pam_securetty.so 설정 누락."
      fi
    fi

    if [ -f /etc/securetty ]; then
      if grep -vE '^#|^\s#' /etc/securetty | grep -q 'pts/'; then
        VULN=1
        REASON="${REASON} [Telnet] /etc/securetty에 pts/ 설정이 존재합니다."
      fi
    fi
  fi

  for svc in "rsh.socket" "rlogin.socket" "rexec.socket"; do
    if systemctl is-active "$svc" &>/dev/null; then
      VULN=1
      REASON="${REASON} [$svc] 서비스가 활성화되어 있습니다."
    fi
  done

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_02() {
  local code="U-02"
  local item="비밀번호 관리정책 설정"
  local severity="상"
  local status="양호"
  local reason="비밀번호 관리 정책이 설정되어 기준을 충족합니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local TARGET_PASS_MAX_DAYS=90
  local TARGET_PASS_MIN_DAYS=1
  local TARGET_MINLEN=8
  local TARGET_MINCLASS=3
  local TARGET_REMEMBER=4

  local vuln=0
  local reasons=()

  local pass_max pass_min
  pass_max="$(awk 'BEGIN{v=""} $1=="PASS_MAX_DAYS"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"
  pass_min="$(awk 'BEGIN{v=""} $1=="PASS_MIN_DAYS"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"

  if [[ -z "$pass_max" || "$pass_max" -gt "$TARGET_PASS_MAX_DAYS" ]]; then
    vuln=1
    reasons+=("/etc/login.defs: PASS_MAX_DAYS 기준(<=${TARGET_PASS_MAX_DAYS}) 미충족 (현재: ${pass_max:-미설정})")
  fi
  if [[ -z "$pass_min" || "$pass_min" -lt "$TARGET_PASS_MIN_DAYS" ]]; then
    vuln=1
    reasons+=("/etc/login.defs: PASS_MIN_DAYS 기준(>=${TARGET_PASS_MIN_DAYS}) 미충족 (현재: ${pass_min:-미설정})")
  fi

  local minlen="" minclass="" dcredit="" ucredit="" lcredit="" ocredit=""
  local has_credit=0

  if [[ -r /etc/security/pwquality.conf ]]; then
    minlen="$(awk -F= '/^[[:space:]]*minlen/{gsub(/[[:space:]]/,"",$2); v=$2} END{print v}' /etc/security/pwquality.conf 2>/dev/null)"
    minclass="$(awk -F= '/^[[:space:]]*minclass/{gsub(/[[:space:]]/,"",$2); v=$2} END{print v}' /etc/security/pwquality.conf 2>/dev/null)"
    grep -Eq '^[[:space:]]*(ucredit|lcredit|dcredit|ocredit)' /etc/security/pwquality.conf && has_credit=1
  fi

  local remember=""
  if [[ -r /etc/security/pwhistory.conf ]]; then
    remember="$(awk -F= '/^[[:space:]]*remember/{gsub(/[[:space:]]/,"",$2); v=$2} END{print v}' /etc/security/pwhistory.conf 2>/dev/null)"
  fi

  local pamline
  for f in "/etc/pam.d/system-auth" "/etc/pam.d/password-auth"; do
    [[ -r "$f" ]] || continue

    if [[ -z "$minlen" || -z "$minclass" ]]; then
      pamline="$(grep -E '^[[:space:]]*password[[:space:]]+.*pam_pwquality\.so' "$f" 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -n 1)"
      [[ -n "$pamline" ]] && {
        [[ -z "$minlen" ]] && minlen="$(echo "$pamline" | sed -nE 's/.*minlen=([0-9]+).*/\1/p')"
        [[ -z "$minclass" ]] && minclass="$(echo "$pamline" | sed -nE 's/.*minclass=([0-9]+).*/\1/p')"
        echo "$pamline" | grep -Eq '(ucredit=|lcredit=|dcredit=|ocredit=)' && has_credit=1
      }
    fi

    if [[ -z "$remember" ]]; then
      pamline="$(grep -E '^[[:space:]]*password[[:space:]]+.*pam_pwhistory\.so' "$f" 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -n 1)"
      [[ -n "$pamline" ]] && remember="$(echo "$pamline" | sed -nE 's/.*remember=([0-9]+).*/\1/p')"
    fi
  done

  if [[ -z "$minlen" || "$minlen" -lt "$TARGET_MINLEN" ]]; then
    vuln=1
    reasons+=("비밀번호 최소 길이(minlen) 기준(>=${TARGET_MINLEN}) 미충족 (현재: ${minlen:-미설정})")
  fi

  if [[ -n "$minclass" ]]; then
    if [[ "$minclass" -lt "$TARGET_MINCLASS" ]]; then
      vuln=1
      reasons+=("비밀번호 복잡성(minclass) 기준(>=${TARGET_MINCLASS}) 미충족 (현재: $minclass)")
    fi
  elif [[ "$has_credit" -eq 0 ]]; then
    vuln=1
    reasons+=("비밀번호 복잡성(minclass 또는 u/l/d/o credit) 설정을 확인할 수 없습니다.")
  fi

  if [[ -z "$remember" || "$remember" -lt "$TARGET_REMEMBER" ]]; then
    vuln=1
    reasons+=("비밀번호 재사용 제한(remember) 기준(>=${TARGET_REMEMBER}) 미충족 (현재: ${remember:-미설정})")
  fi

  if (( vuln == 0 )); then
    status="양호"
    reason="비밀번호 관리 정책이 설정되어 기준을 충족합니다."
  else
    status="취약"
    local r="${reasons[0]:-기준 미충족}"
    [[ ${#r} -gt 250 ]] && r="${r:0:250}..."
    reason="$r"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_03() {
  local code="U-03"
  local item="계정 잠금 임계값 설정"
  local severity="상"
  local status="양호"
  local reason="계정 잠금 임계값이 10회 이하로 설정되어 있습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local pam_files=(
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
  )
  local faillock_conf="/etc/security/faillock.conf"

  local found_any=0
  local max_deny=-1
  local file_exists_count=0

  _extract_deny_from_pam_file() {
    local f="$1"
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null \
      | grep -Ei 'pam_tally2\.so|pam_faillock\.so' \
      | grep -oE 'deny=[0-9]+' \
      | cut -d= -f2
  }

  _extract_deny_from_faillock_conf() {
    local f="$1"
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null \
      | grep -Ei '^[[:space:]]*deny[[:space:]]*=' \
      | grep -oE '[0-9]+' \
      | head -n 1
  }

  for f in "${pam_files[@]}"; do
    if [ -f "$f" ]; then
      ((file_exists_count++))
      while IFS= read -r deny; do
        [ -z "$deny" ] && continue
        found_any=1
        if [ "$deny" -gt "$max_deny" ]; then
          max_deny="$deny"
        fi
      done < <(_extract_deny_from_pam_file "$f")
    fi
  done

  if [ -f "$faillock_conf" ]; then
    local conf_deny
    conf_deny="$(_extract_deny_from_faillock_conf "$faillock_conf")"
    if [ -n "$conf_deny" ]; then
      found_any=1
      if [ "$conf_deny" -gt "$max_deny" ]; then
        max_deny="$conf_deny"
      fi
    fi
  fi

  if [ "$file_exists_count" -eq 0 ]; then
    status="취약"
    reason="계정 잠금 임계값을 점검할 PAM 파일이 없습니다. (system-auth/password-auth 미존재)"
  elif [ "$found_any" -eq 0 ]; then
    status="취약"
    reason="deny 설정을 찾지 못했습니다. (PAM 라인 또는 faillock.conf에서 deny=값 미발견)"
  elif [ "$max_deny" -eq 0 ]; then
    status="취약"
    reason="계정 잠금 임계값(deny)이 0으로 설정되어 있습니다. (잠금 미적용 가능)"
  elif [ "$max_deny" -gt 10 ]; then
    status="취약"
    reason="계정 잠금 임계값(deny)이 11회 이상으로 설정되어 있습니다. (max deny=$max_deny)"
  else
    status="양호"
    reason="계정 잠금 임계값이 10회 이하로 설정되어 있습니다. (max deny=$max_deny)"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_04() {
  local code="U-04"
  local item="비밀번호 파일 보호"
  local severity="상"
  local status="양호"
  local reason="쉐도우 비밀번호를 사용하고 있으며 /etc/shadow 파일이 존재합니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln_count=0
  local vuln_users=""

  if [ -f /etc/passwd ]; then
    vuln_count="$(awk -F: '$2 != "x" && $2 != "!!" && $2 != "*"' /etc/passwd 2>/dev/null | wc -l)"
    if [ "${vuln_count:-0}" -gt 0 ]; then
      vuln_users="$(awk -F: '$2 != "x" && $2 != "!!" && $2 != "*"{print $1}' /etc/passwd 2>/dev/null | paste -sd' ' -)"
      status="취약"
      reason="/etc/passwd 파일에 shadow 패스워드를 사용하지 않는 계정이 존재: ${vuln_users:-확인불가}"
    else
      if [ -f /etc/shadow ]; then
        status="양호"
        reason="쉐도우 비밀번호를 사용하고 있으며 /etc/shadow 파일이 존재합니다."
      else
        status="취약"
        reason="/etc/shadow 파일이 존재하지 않습니다."
      fi
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_05() {
  local code="U-05"
  local item="root 이외의 UID가 '0' 금지"
  local severity="상"
  local status="양호"
  local reason="root 계정과 동일한 UID(0)를 갖는 계정이 존재하지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  if [ -f /etc/passwd ]; then
    local dup_users
    dup_users="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | grep -vx 'root' || true)"
    if [ -n "$dup_users" ]; then
      status="취약"
      reason="root 외 UID 0 계정 발견: ${dup_users}"
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_06() {
  local code="U-06"
  local item="사용자 계정 su 기능 제한"
  local severity="상"
  local status="양호"
  local reason="su 명령이 특정 그룹(wheel 등) 사용자로 제한되어 있습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local VULN=0
  local REASON=""
  local PAM_SU="/etc/pam.d/su"

  if [ -f "$PAM_SU" ]; then
    local SU_RESTRICT
    SU_RESTRICT="$(grep -vE "^#|^[[:space:]]*#" "$PAM_SU" 2>/dev/null | grep -F "pam_wheel.so" | grep -F "use_uid" || true)"

    if [ -z "$SU_RESTRICT" ]; then
      VULN=1
      REASON="/etc/pam.d/su 파일에 pam_wheel.so 모듈 설정이 없거나 주석 처리되어 있습니다."
    fi
  else
    VULN=1
    REASON="$PAM_SU 파일이 존재하지 않습니다."
  fi

  local USER_COUNT
  USER_COUNT="$(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd 2>/dev/null | wc -l)"

  if [ "$VULN" -eq 1 ] && [ "${USER_COUNT:-0}" -eq 0 ]; then
    VULN=0
    REASON="일반 사용자 계정 없이 root 계정만 사용하여 su 명령어 사용 제한이 불필요합니다."
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  else
    status="양호"
    reason="su 명령이 특정 그룹(wheel 등) 사용자로 제한되어 있습니다."
    if [ -n "$REASON" ]; then
      reason="$REASON"
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_07() {
  local code="U-07"
  local item="불필요한 계정 제거"
  local severity="상"
  local status="양호"
  local reason="불필요한(로그인 가능한) 시스템 계정이 존재하지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local det_reason=""

  local system_users
  system_users="$(awk -F: '
    ($3 < 1000 && $1 != "root" && $1 != "sync" && $1 != "shutdown" && $1 != "halt") &&
    ($7 !~ /nologin|false/) {
      print $1 "(uid=" $3 ",shell=" $7 ")"
    }' /etc/passwd 2>/dev/null)"

  if [[ -n "$system_users" ]]; then
    vuln=1
    det_reason="로그인 가능한 시스템 계정 존재: $(echo "$system_users" | paste -sd', ' -)"
    det_reason="$(echo "$det_reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if (( ${#det_reason} > 250 )); then det_reason="${det_reason:0:250}..."; fi
  fi

  if (( vuln == 0 )); then
    status="양호"
    reason="불필요한(로그인 가능한) 시스템 계정이 존재하지 않습니다."
  else
    status="취약"
    reason="$det_reason"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_08() {
  local code="U-08"
  local item="관리자 그룹에 최소한의 계정 포함"
  local severity="중"
  local status="양호"
  local reason="root 그룹에 root 이외의 계정이 포함되어 있지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln_found=0
  local all_non_root_members=""

  if [ ! -f /etc/group ]; then
    status="N/A"
    reason="/etc/group 파일이 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local group_line members user
  group_line="$(getent group "root" 2>/dev/null)"

  if [ -z "$group_line" ]; then
    status="N/A"
    reason="root 그룹 정보를 시스템에서 찾을 수 없습니다."
  else
    members="$(echo "$group_line" | awk -F: '{print $4}' | tr ',' ' ')"

    for user in $members; do
      if [ -n "$user" ] && [ "$user" != "root" ]; then
        vuln_found=1
        all_non_root_members+="$user "
      fi
    done

    if [ "$vuln_found" -eq 1 ]; then
      status="취약"
      all_non_root_members="$(echo "$all_non_root_members" | tr -s ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      reason="root 그룹에 root 이외 계정이 포함되어 있습니다: ${all_non_root_members}"
    else
      status="양호"
      reason="root 그룹에 root 이외의 계정이 포함되어 있지 않습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_09() {
  local code="U-09"
  local item="계정이 존재하지 않는 GID 금지"
  local severity="하"
  local status="양호"
  local reason="계정이 존재하지 않는 불필요한 그룹이 발견되지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  if [ ! -f /etc/passwd ] || [ ! -f /etc/group ]; then
    status="취약"
    reason="/etc/passwd 또는 /etc/group 파일이 존재하지 않아 점검할 수 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local USED_GIDS CHECK_GIDS VULN_GROUPS gid GROUP_NAME
  USED_GIDS="$(awk -F: '{print $4}' /etc/passwd 2>/dev/null | sort -u)"
  CHECK_GIDS="$(awk -F: '$3 >= 500 {print $3}' /etc/group 2>/dev/null)"

  VULN_GROUPS=""
  for gid in $CHECK_GIDS; do
    if ! echo "$USED_GIDS" | grep -qxw "$gid"; then
      GROUP_NAME="$(grep -w ":$gid:" /etc/group 2>/dev/null | cut -d: -f1 | head -n 1)"
      [ -z "$GROUP_NAME" ] && GROUP_NAME="unknown"
      VULN_GROUPS="$VULN_GROUPS $GROUP_NAME($gid)"
    fi
  done

  VULN_GROUPS="$(echo "$VULN_GROUPS" | tr -s ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

  if [ -n "$VULN_GROUPS" ]; then
    status="취약"
    reason="계정이 존재하지 않는 불필요한 그룹 존재: $VULN_GROUPS"
  else
    status="양호"
    reason="계정이 존재하지 않는 불필요한 그룹이 발견되지 않습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_10() {
  local code="U-10"
  local item="동일한 UID 금지"
  local severity="중"
  local status="양호"
  local reason="동일한 UID로 설정된 사용자 계정이 존재하지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  if [ -f /etc/passwd ]; then
    local dup_uids dup_uid_count
    dup_uids="$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)"
    dup_uid_count="$(echo "$dup_uids" | sed '/^[[:space:]]*$/d' | wc -l)"

    if [ "${dup_uid_count:-0}" -gt 0 ]; then
      status="취약"
      reason="동일한 UID로 설정된 사용자 계정이 존재합니다. (중복 UID: $(echo "$dup_uids" | paste -sd',' -))"
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_11() {
  local code="U-11"
  local item="사용자 shell 점검"
  local severity="하"
  local status="양호"
  local reason="로그인이 필요하지 않은 계정에 /bin/false 또는 nologin 쉘이 부여되어 있습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local VULN=0
  local VUL_ACCOUNTS=""
  local EXCEPT_USERS="^(sync|shutdown|halt)$"

  if [ -f /etc/passwd ]; then
    while IFS=: read -r user pass uid gid comment home shell; do
      if { [ "$uid" -ge 1 ] && [ "$uid" -lt 1000 ]; } || [ "$user" = "nobody" ]; then
        if [[ "$user" =~ $EXCEPT_USERS ]]; then
          continue
        fi
        if [[ "$shell" != "/bin/false" ]] && \
           [[ "$shell" != "/sbin/nologin" ]] && \
           [[ "$shell" != "/usr/sbin/nologin" ]]; then
          if [ -z "$VUL_ACCOUNTS" ]; then
            VUL_ACCOUNTS="$user($shell)"
          else
            VUL_ACCOUNTS="$VUL_ACCOUNTS, $user($shell)"
          fi
        fi
      fi
    done < /etc/passwd

    if [ -n "$VUL_ACCOUNTS" ]; then
      VULN=1
    fi
  else
    VULN=1
    VUL_ACCOUNTS=""
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  if [ "$status" != "취약" ]; then
    if [ "$VULN" -eq 1 ]; then
      status="취약"
      reason="로그인이 불필요한 계정에 쉘이 부여되어 있습니다: $VUL_ACCOUNTS"
    else
      status="양호"
      reason="로그인이 필요하지 않은 계정에 /bin/false 또는 nologin 쉘이 부여되어 있습니다."
    fi
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_12() {
  local code="U-12"
  local item="세션 종료 시간 설정"
  local severity="중"
  local status="양호"
  local reason="Session Timeout(TMOUT)이 600초 이하로 설정되어 있으며 export 조건을 충족합니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local det_reason=""
  local ok=0

  local candidates=(
    "/etc/profile"
    "/etc/bashrc"
    "/etc/profile.d/*.sh"
    "/etc/bash.bashrc"
    "/etc/profile.local"
  )

  local found_count=0

  local f ff lines v
  for f in "${candidates[@]}"; do
    for ff in $f; do
      [[ -r "$ff" ]] || continue

      lines="$(grep -vE '^[[:space:]]*#' "$ff" 2>/dev/null | grep -E '^[[:space:]]*TMOUT[[:space:]]*=' || true)"
      if [[ -n "$lines" ]]; then
        found_count=$((found_count + 1))

        v="$(echo "$lines" | tail -n 1 | sed -nE 's/^[[:space:]]*TMOUT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p')"
        if [[ -n "$v" && "$v" -le 600 ]]; then
          # readonly 조건을 제거하고 export 조건만 확인하도록 수정
          if grep -vE '^[[:space:]]*#' "$ff" 2>/dev/null | grep -Eq '^[[:space:]]*export[[:space:]]+TMOUT\b'; then
            ok=1
          fi
        fi
      fi
    done
  done

  if (( found_count == 0 )); then
    vuln=1
    det_reason="TMOUT 설정이 전역 설정 파일에서 확인되지 않습니다."
  elif (( ok == 0 )); then
    vuln=1
    det_reason="TMOUT 설정은 존재하나 600초 이하 및 export 조건을 충족하지 않습니다."
  fi

  if (( vuln == 0 )); then
    status="양호"
    reason="Session Timeout(TMOUT)이 600초 이하로 설정되어 있으며 export 조건을 충족합니다."
  else
    status="취약"
    reason="$det_reason"
    reason="$(echo "$reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_13() {
  local code="U-13"
  local item="안전한 비밀번호 암호화 알고리즘 사용"
  local severity="중"
  local status="양호"
  local reason="SHA-2 계열(SHA-256/512) 비밀번호 해시 알고리즘을 사용하고 있습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local shadow="/etc/shadow"

  if [ ! -e "$shadow" ]; then
    status="N/A"
    reason="$shadow 파일이 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  if [ ! -r "$shadow" ]; then
    status="N/A"
    reason="$shadow 파일을 읽을 수 없습니다. (권한 부족: root 권한 필요)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local vuln_found=0
  local checked=0
  local evidence=""

  while IFS=: read -r user hash rest; do
    [ -z "$user" ] && continue

    if [ -z "$hash" ] || [[ "$hash" =~ ^[!*]+$ ]]; then
      continue
    fi

    if [[ "$hash" != \$* ]]; then
      checked=$((checked + 1))
      vuln_found=1
      evidence+="$user:UNKNOWN_FORMAT; "
      continue
    fi

    local id
    id="$(echo "$hash" | awk -F'$' '{print $2}')"
    [ -z "$id" ] && id="UNKNOWN"

    checked=$((checked + 1))

    if [ "$id" = "5" ] || [ "$id" = "6" ]; then
      : # good (sha256/sha512)
    else
      vuln_found=1
      evidence+="$user:\$$id\$; "
    fi
  done < "$shadow"

  if [ "$checked" -eq 0 ]; then
    status="N/A"
    reason="점검 가능한 패스워드 해시 계정이 없습니다. (모두 잠금/미설정 계정일 수 있음)"
  elif [ "$vuln_found" -eq 1 ]; then
    status="취약"
    evidence="$(echo "$evidence" | tr -s ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    reason="취약하거나 기준(SHA-2) 미만의 해시 알고리즘을 사용하는 계정이 존재합니다. ${evidence:+(탐지: $evidence)}"
  else
    status="양호"
    reason="SHA-2 계열(SHA-256/512) 비밀번호 해시 알고리즘을 사용하고 있습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_14() {
  local code="U-14"
  local item="root 홈, 패스 디렉터리 권한 및 패스 설정"
  local severity="상"
  local status="양호"
  local reason="PATH 환경변수에 '.'(현재 디렉터리)가 맨 앞이나 중간에 포함되어 있지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local ROOT_PATH="$PATH"

  if [ -z "$ROOT_PATH" ]; then
    status="N/A"
    reason="root 계정 PATH를 확인할 수 없습니다."
  elif echo "$ROOT_PATH" | grep -qE '(^|:)\.(:|$)|::|^:|:$'; then
    status="취약"
    reason="root PATH 환경변수 내 취약 경로 포함: $ROOT_PATH"
  else
    status="양호"
    reason="PATH 환경변수에 '.'(현재 디렉터리)가 맨 앞이나 중간에 포함되어 있지 않습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_15() {
  local code="U-15"
  local item="파일 및 디렉터리 소유자 설정"
  local severity="상"
  local status="양호"
  local reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local cnt
  cnt="$(find / \( -nouser -o -nogroup \) 2>/dev/null | wc -l)"
  cnt="${cnt:-0}"

  if [ "$cnt" -gt 0 ]; then
    status="취약"
    reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다. (개수: $cnt)"
  else
    status="양호"
    reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_16() {
  local code="U-16"
  local item="/etc/passwd 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하입니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local VULN=0
  local REASON=""
  local FILE="/etc/passwd"

  if [ -f "$FILE" ]; then
    local OWNER PERMIT
    OWNER="$(stat -c "%U" "$FILE" 2>/dev/null)"
    PERMIT="$(stat -c "%a" "$FILE" 2>/dev/null)"

    if [ "$OWNER" != "root" ] || [ "${PERMIT:-999}" -gt 644 ]; then
      VULN=1
      if [ "$OWNER" != "root" ]; then
        REASON="/etc/passwd 파일의 소유자가 root가 아닙니다 (현재: $OWNER)."
      fi
      if [ "${PERMIT:-999}" -gt 644 ]; then
        if [ -n "$REASON" ]; then
          REASON="$REASON / 권한이 644보다 높습니다 (현재: $PERMIT)."
        else
          REASON="권한이 644보다 높습니다 (현재: $PERMIT)."
        fi
      fi
    fi
  else
    VULN=1
    REASON="$FILE 파일이 존재하지 않습니다."
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  else
    status="양호"
    reason="/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하입니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_17() {
  local code="U-17"
  local item="시스템 시작 스크립트 권한 설정"
  local severity="상"
  local status="양호"
  local reason="모든 시스템 시작 스크립트의 소유자가 root이고 일반 사용자(group/other)의 쓰기 권한이 없습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local targets=(
    "/etc/rc.local"
    "/etc/rc.d/rc.local"
    "/etc/systemd/system"
    "/usr/lib/systemd/system"
  )

  local vuln_found=0
  local offenders=""

  for target in "${targets[@]}"; do
    [ -e "$target" ] || continue

    while IFS= read -r file; do
      local uid=$(stat -L -c '%u' "$file")
      local perms=$(stat -L -c '%A' "$file")
      local group_w=$(echo "$perms" | cut -c 6)
      local other_w=$(echo "$perms" | cut -c 9)

      if [ "$uid" != "0" ] || [ "$group_w" = "w" ] || [ "$other_w" = "w" ]; then
        vuln_found=1
        offenders="$file"
        break 2
      fi
    done < <(find -L "$target" -maxdepth 2 -type f 2>/dev/null)
  done

  if [ "$vuln_found" -eq 1 ]; then
    status="취약"
    reason="시작 스크립트 관리 미흡(소유자 미일치 또는 그룹/기타 쓰기 권한 존재): $offenders"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_18() {
  local code="U-18"
  local item="/etc/shadow 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/shadow 파일의 소유자가 root이고, 권한이 400입니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local target="/etc/shadow"

  if [ ! -e "$target" ]; then
    status="N/A"
    reason="$target 파일이 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  if [ ! -f "$target" ]; then
    status="N/A"
    reason="$target 가 일반 파일이 아닙니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local owner perm
  owner="$(stat -c '%U' "$target" 2>/dev/null)"
  perm="$(stat -c '%a' "$target" 2>/dev/null)"

  if [ -z "$owner" ] || [ -z "$perm" ]; then
    status="N/A"
    reason="stat 명령으로 $target 정보를 읽지 못했습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  if [ "$owner" != "root" ]; then
    status="취약"
    reason="$target 파일의 소유자가 root가 아닙니다. (owner=$owner)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  if [[ "$perm" =~ ^[0-7]{4}$ ]]; then
    perm="${perm:1:3}"
  elif [[ "$perm" =~ ^[0-7]{1,3}$ ]]; then
    perm="$(printf "%03d" "$perm")"
  fi

  if ! [[ "$perm" =~ ^[0-7]{3}$ ]]; then
    status="N/A"
    reason="$target 파일 권한 형식이 예상과 다릅니다. (perm=$perm)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  if [ "$perm" != "400" ]; then
    status="취약"
    reason="$target 파일 권한이 400이 아닙니다. (perm=$perm)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local o g oth
  o="${perm:0:1}"; g="${perm:1:1}"; oth="${perm:2:1}"
  if [ "$o" != "4" ] || [ "$g" != "0" ] || [ "$oth" != "0" ]; then
    status="취약"
    reason="$target 파일 권한 구성(owner/group/other)이 기준과 다릅니다. (perm=$perm)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  status="양호"
  reason="/etc/shadow 파일의 소유자가 root이고, 권한이 400입니다."

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_19() {
  local code="U-19"
  local item="/etc/hosts 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하입니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local target="/etc/hosts"

  if [ ! -f "$target" ]; then
    status="N/A"
    reason="$target 파일이 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local FILE_OWNER_UID FILE_OWNER_NAME FILE_PERM USER_PERM GROUP_PERM OTHER_PERM
  FILE_OWNER_UID="$(stat -c "%u" "$target" 2>/dev/null)"
  FILE_OWNER_NAME="$(stat -c "%U" "$target" 2>/dev/null)"
  FILE_PERM="$(stat -c "%a" "$target" 2>/dev/null)"

  if [ -z "$FILE_OWNER_UID" ] || [ -z "$FILE_PERM" ]; then
    status="N/A"
    reason="stat 명령으로 $target 정보를 읽지 못했습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  USER_PERM="${FILE_PERM:0:1}"
  GROUP_PERM="${FILE_PERM:1:1}"
  OTHER_PERM="${FILE_PERM:2:1}"

  if [ "$FILE_OWNER_UID" -ne 0 ]; then
    status="취약"
    reason="소유자(owner)가 root가 아닙니다. (현재: ${FILE_OWNER_NAME:-unknown})"
  elif [ "${USER_PERM:-9}" -gt 6 ] || [ "${GROUP_PERM:-9}" -gt 4 ] || [ "${OTHER_PERM:-9}" -gt 4 ]; then
    status="취약"
    reason="권한이 644보다 큽니다. (현재: $FILE_PERM)"
  else
    status="양호"
    reason="/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하입니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_20() {
  local code="U-20"
  local item="systemd 및 (x)inetd 설정 파일 권한 설정"
  local status="양호"
  local reason="설정 파일의 소유자가 root이고 권한이 600 이하입니다."

  local vuln=0
  local evidences=()

  local check_files=("/etc/inetd.conf" "/etc/xinetd.conf" "/etc/systemd/system.conf")
  
  for file in "${check_files[@]}"; do
    if [ -f "$file" ]; then
      local owner=$(stat -c %U "$file")
      local perm=$(stat -c %a "$file")
      if [ "$owner" != "root" ] || [ "$perm" -gt 600 ]; then
        vuln=1
        evidences+=("$file($owner:$perm)")
      fi
    fi
  done

  local check_dirs=("/etc/xinetd.d" "/etc/systemd")
  for dir in "${check_dirs[@]}"; do
    if [ -d "$dir" ]; then
      local bad_files=$(find "$dir" -type f ! -user root -o -type f ! -perm 600 2>/dev/null)
      if [ -n "$bad_files" ]; then
        vuln=1
        evidences+=("$dir 내 권한 미흡 파일 존재")
      fi
    fi
  done

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="다음 파일의 권한 설정이 미흡합니다: ${evidences[*]}"
  fi

  printf '{"code":"%s","item":"%s","status":"%s","reason":"%s"}\n' "$code" "$item" "$status" "$reason"
}

U_21() {
  local code="U-21"
  local item="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/(r)syslog.conf 파일의 소유자 및 권한이 기준(소유자 root/bin/sys, 권한 640 이하)에 적합합니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local target=""
  if [ -f "/etc/rsyslog.conf" ]; then
    target="/etc/rsyslog.conf"
  elif [ -f "/etc/syslog.conf" ]; then
    target="/etc/syslog.conf"
  else
    status="N/A"
    reason="/etc/rsyslog.conf 또는 /etc/syslog.conf 파일이 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local OWNER PERMIT
  OWNER="$(stat -c '%U' "$target" 2>/dev/null)"
  PERMIT="$(stat -c '%a' "$target" 2>/dev/null)"

  if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
    status="N/A"
    reason="stat 명령으로 $target 정보를 읽지 못했습니다. (권한 문제 등)"
  elif [[ ! "$OWNER" =~ ^(root|bin|sys)$ ]]; then
    status="취약"
    reason="$target 파일의 소유자가 root, bin, sys가 아닙니다. (owner=$OWNER)"
  elif [ "$PERMIT" -gt 640 ]; then
    status="취약"
    reason="$target 파일의 권한이 640보다 큽니다. (permit=$PERMIT)"
  else
    status="양호"
    reason="$target 파일의 소유자($OWNER) 및 권한($PERMIT)이 기준에 적합합니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_22() {
  local code="U-22"
  local item="/etc/services 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/services 파일 소유자가 root이며, 그룹/기타 쓰기 권한이 제거되어 있습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local f="/etc/services"

  if [[ ! -e "$f" ]]; then
    status="취약"
    reason="/etc/services 파일이 존재하지 않습니다."
  else
    local owner perm
    owner="$(stat -Lc '%U' "$f" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$f" 2>/dev/null)"

    if [[ -z "$owner" || -z "$perm" ]]; then
      status="N/A"
      reason="stat 명령으로 /etc/services 정보를 읽지 못했습니다."
    elif [[ "$owner" != "root" ]]; then
      status="취약"
      reason="/etc/services 소유자가 root가 아닙니다(owner=$owner)."
    else
      local oct="0$perm"
      if (( (oct & 18) != 0 )); then
        status="취약"
        reason="/etc/services에 그룹/기타 쓰기 권한이 존재합니다(perm=$perm)."
      else
        status="양호"
        reason="/etc/services 파일 소유자가 root이며, 그룹/기타 쓰기 권한이 제거되어 있습니다."
      fi
    fi
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_23() {
  local code="U-23"
  local item="SUID, SGID, Sticky bit 설정 파일 점검"
  local severity="상"
  local status="양호"
  local reason="비정상/사용자쓰기가능 경로 또는 패키지 미소유 SUID/SGID 파일이 발견되지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local SEARCH_ROOT="/"
  local MAX_EVIDENCE=30

  local whitelist=(
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
    "/usr/bin/chfn"
    "/usr/bin/chsh"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/crontab"
    "/usr/sbin/unix_chkpwd"
    "/usr/sbin/pam_timestamp_check"
    "/usr/libexec/utempter/utempter"
    "/usr/sbin/mount.nfs"
  )

  _is_whitelisted() {
    local f="$1" w
    for w in "${whitelist[@]}"; do
      [ "$f" = "$w" ] && return 0
    done
    return 1
  }

  _is_bad_path() {
    local f="$1"
    case "$f" in
      /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/run/user/*) return 0 ;;
    esac
    return 1
  }

  local vuln_found=0
  local evidence_vuln=""
  local count_v=0

  while IFS= read -r f; do
    [ -f "$f" ] || continue

    local mode owner group
    mode="$(stat -c '%A' "$f" 2>/dev/null)"
    owner="$(stat -c '%U' "$f" 2>/dev/null)"
    group="$(stat -c '%G' "$f" 2>/dev/null)"
    [ -z "$mode" ] && continue

    if _is_bad_path "$f"; then
      vuln_found=1
      if (( count_v < MAX_EVIDENCE )); then
        evidence_vuln+="$mode $owner:$group $f (BAD_PATH); "
        count_v=$((count_v+1))
      fi
      continue
    fi

    if _is_whitelisted "$f"; then
      continue
    fi

    if command -v rpm >/dev/null 2>&1; then
      if ! rpm -qf "$f" >/dev/null 2>&1; then
        vuln_found=1
        if (( count_v < MAX_EVIDENCE )); then
          evidence_vuln+="$mode $owner:$group $f (NOT_OWNED_BY_RPM); "
          count_v=$((count_v+1))
        fi
        continue
      fi
    fi
  done < <(find "$SEARCH_ROOT" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

  evidence_vuln="$(echo "$evidence_vuln" | tr -s ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

  if (( vuln_found == 1 )); then
    status="취약"
    reason="비정상/사용자쓰기가능 경로 또는 패키지 미소유 SUID/SGID 파일이 존재합니다. ${evidence_vuln:+(예: $evidence_vuln)}"
  else
    status="양호"
    reason="비정상/사용자쓰기가능 경로 또는 패키지 미소유 SUID/SGID 파일이 발견되지 않습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_24() {
  local code="U-24"
  local item="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="홈 디렉터리 환경변수 파일의 소유자가 root 또는 해당 계정이며, 그룹/기타 쓰기 권한이 없습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local VULN=0
  local REASON=""

  local CHECK_FILES=(
    ".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login" ".bash_logout"
    ".exrc" ".vimrc" ".netrc" ".forward" ".rhosts" ".shosts"
  )

  local USER_LIST USER_INFO USER_NAME USER_HOME FILE TARGET
  USER_LIST="$(awk -F: '$7!~/(nologin|false)/ {print $1":"$6}' /etc/passwd 2>/dev/null)"

  for USER_INFO in $USER_LIST; do
    USER_NAME="${USER_INFO%%:*}"
    USER_HOME="${USER_INFO#*:}"

    [ -d "$USER_HOME" ] || continue

    for FILE in "${CHECK_FILES[@]}"; do
      TARGET="$USER_HOME/$FILE"
      [ -f "$TARGET" ] || continue

      local FILE_OWNER
      FILE_OWNER="$(stat -c '%U' "$TARGET" 2>/dev/null)"
      if [ -n "$FILE_OWNER" ] && [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USER_NAME" ]; then
        VULN=1
        REASON="${REASON}파일 소유자 불일치: $TARGET (소유자: $FILE_OWNER) | "
      fi

      local PERM MODE OCT
      MODE="$(stat -c '%a' "$TARGET" 2>/dev/null)"
      if [[ -n "$MODE" && "$MODE" =~ ^[0-9]+$ ]]; then
        OCT="0$MODE"
        if (( (OCT & 18) != 0 )); then
          VULN=1
          PERM="$(stat -c '%A' "$TARGET" 2>/dev/null)"
          REASON="${REASON}권한 취약: $TARGET (perm=${MODE}${PERM:+/$PERM} - group/other write 존재) | "
        fi
      else
        VULN=1
        REASON="${REASON}권한 확인 실패: $TARGET (stat로 권한 확인 불가) | "
      fi
    done
  done

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    REASON="$(echo "$REASON" | tr '\r' ' ' | sed -e 's/[[:space:]]*$//')"
    reason="$REASON"
  else
    status="양호"
    reason="홈 디렉터리 환경변수 파일의 소유자가 root 또는 해당 계정이며, 그룹/기타 쓰기 권한이 없습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_25() {
  local code="U-25"
  local item="world writable 파일 점검"
  local severity="상"
  local status="양호"
  local reason="점검 경로 내 World Writable 파일이 발견되지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local CHECK_DIRS="/etc /bin /sbin /usr/bin /usr/sbin /var/log /home"
  local FILES count sample

  FILES="$(find $CHECK_DIRS -xdev -type f -perm -2 2>/dev/null)"

  if [ -n "$FILES" ]; then
    count="$(echo "$FILES" | wc -l | tr -d '[:space:]')"
    sample="$(echo "$FILES" | head -n 5 | paste -sd', ' -)"
    status="취약"
    reason="World Writable 파일이 존재합니다. (개수: ${count}${sample:+, 예시: $sample})"
  else
    status="양호"
    reason="점검 경로 내 World Writable 파일이 발견되지 않습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_26() {
  local code="U-26"
  local item="/dev에 존재하지 않는 device 파일 점검"
  local severity="상"
  local status="양호"
  local reason="/dev 내부에 존재하지 않아야 할 일반 파일이 발견되지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local target_dir="/dev"

  if [ ! -d "$target_dir" ]; then
    status="N/A"
    reason="$target_dir 디렉터리가 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local VUL_FILES sample count
  VUL_FILES="$(find /dev \( -path /dev/mqueue -o -path /dev/shm \) -prune -o -type f -print 2>/dev/null)"

  if [ -n "$VUL_FILES" ]; then
    count="$(echo "$VUL_FILES" | wc -l | tr -d '[:space:]')"
    sample="$(echo "$VUL_FILES" | head -n 5 | paste -sd', ' -)"
    status="취약"
    reason="/dev 내부에 존재하지 않아야 할 일반 파일이 발견되었습니다. (개수: ${count}${sample:+, 예시: $sample})"
  else
    status="양호"
    reason="/dev 내부에 존재하지 않아야 할 일반 파일이 발견되지 않습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_27() {
  local code="U-27"
  local item="$HOME/.rhosts, hosts.equiv 사용 금지"
  local severity="상"
  local status="양호"
  local reason=""

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local svc_active=0
  for svc in "rsh.socket" "rlogin.socket" "rexec.socket" "rsh.service" "rlogin.service" "rexec.service"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      svc_active=1
      break
    fi
  done

  if [[ "$svc_active" -eq 0 ]]; then
    status="양호"
    reason="rlogin, rsh, rexec 서비스를 사용하지 않으므로 보안 기준을 충족합니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local vuln_files=()
  local found_files=()
  local target_list=("/etc/hosts.equiv")
  
  for rh in /root/.rhosts /home/*/.rhosts; do
    [[ -e "$rh" ]] && target_list+=("$rh")
  done

  for file in "${target_list[@]}"; do
    [[ -e "$file" ]] || continue
    found_files+=("$file")

    local perm=$(stat -c "%a" "$file")
    local owner_uid=$(stat -c "%u" "$file")
    local dir_uid=$(stat -c "%u" "$(dirname "$file")") 
    local has_plus=$(grep -E '^\+' "$file" 2>/dev/null)

    local is_vuln=0
    
    if [[ "$owner_uid" -ne 0 && "$owner_uid" -ne "$dir_uid" ]]; then
      is_vuln=1
    fi
    
    if [[ "$perm" -gt 600 ]]; then
      is_vuln=1
    fi
    
    if [[ -n "$has_plus" ]]; then
      is_vuln=1
    fi

    [[ "$is_vuln" -eq 1 ]] && vuln_files+=("$file")
  done

  if (( ${#vuln_files[@]} > 0 )); then
    status="취약"
    reason="관련 서비스가 활성화되어 있으나, 보안 설정이 미비한 파일이 존재합니다: ${vuln_files[*]}"
  elif (( ${#found_files[@]} > 0 )); then
    status="양호"
    reason="관련 서비스가 활성화되어 있으나, 모든 파일이 소유자/권한(600 이하)/내용(+ 미포함) 기준을 충족합니다."
  else
    status="양호"
    reason="관련 서비스가 활성화되어 있으나, hosts.equiv 또는 .rhosts 파일이 존재하지 않습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$reason")"
}

U_28() {
  local code="U-28"
  local item="접속 IP 및 포트 제한"
  local severity="상"
  local status="양호"
  local reason="활성화된 방화벽/접근제어 기능에서 IP/포트 제한 설정이 확인됩니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local FW_ACTIVE=0
  local VULN_FOUND=0
  local REASON=""

  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    FW_ACTIVE=1
    local fw_rules
    fw_rules="$(firewall-cmd --list-all 2>/dev/null | grep -E "sources:|rich rules:" | grep -vE "sources:[[:space:]]*$|rich rules:[[:space:]]*$")"
    if [ -z "$fw_rules" ]; then
      VULN_FOUND=1
      REASON+="[Firewalld 규칙 미비] "
    fi
  fi

  if command -v iptables >/dev/null 2>&1 && systemctl is-active --quiet iptables; then
    FW_ACTIVE=1
    local ipt_rules
    ipt_rules="$(iptables -S 2>/dev/null | grep -vE '^-P (INPUT|FORWARD|OUTPUT) ACCEPT$' | wc -l | tr -d '[:space:]')"
    if [ "${ipt_rules:-0}" -eq 0 ]; then
      VULN_FOUND=1
      REASON+="[Iptables 규칙 미비] "
    fi
  fi

  if ldd "$(which sshd 2>/dev/null)" 2>/dev/null | grep -q 'libwrap'; then
    FW_ACTIVE=1
    local deny="/etc/hosts.deny"
    local allow="/etc/hosts.allow"

    if ! grep -vE '^#|^\s#' "$deny" 2>/dev/null | grep -qi "ALL:ALL"; then
      VULN_FOUND=1
      REASON+="[TCP Wrapper deny 미설정] "
    elif grep -vE '^#|^\s#' "$allow" 2>/dev/null | grep -qi "ALL:ALL"; then
      VULN_FOUND=1
      REASON+="[TCP Wrapper allow 과대허용] "
    fi
  fi

  if [ "$FW_ACTIVE" -eq 0 ]; then
    status="취약"
    reason="활성화된 방화벽 서비스가 없습니다."
  elif [ "$VULN_FOUND" -eq 1 ]; then
    status="취약"
    REASON="$(echo "$REASON" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    reason="활성화된 서비스 중 설정 미비 항목이 있습니다: $REASON"
  else
    status="양호"
    reason="활성화된 방화벽/접근제어 기능에서 IP/포트 제한 설정이 확인됩니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_29() {
  local code="U-29"
  local item="hosts.lpd 파일 소유자 및 권한 설정"
  local severity="하"
  local status="양호"
  local reason="/etc/hosts.lpd 파일이 존재하지 않거나, 존재하더라도 소유자(root) 및 권한(600 이하)이 기준에 적합합니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local TARGET="/etc/hosts.lpd"

  if [ -f "$TARGET" ]; then
    local OWNER PERMIT
    OWNER="$(stat -c "%U" "$TARGET" 2>/dev/null)"
    PERMIT="$(stat -c "%a" "$TARGET" 2>/dev/null)"

    if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
      status="N/A"
      reason="stat 명령으로 $TARGET 정보를 읽지 못했습니다."
    elif [ "$OWNER" != "root" ]; then
      status="취약"
      reason="$TARGET 파일의 소유자가 root가 아닙니다(현재: $OWNER)."
    elif [ "$PERMIT" -gt 600 ]; then
      status="취약"
      reason="$TARGET 파일 권한이 600보다 큽니다(현재: $PERMIT)."
    else
      status="양호"
      reason="$TARGET 파일이 존재하며 소유자(root) 및 권한($PERMIT)이 기준(600 이하)에 적합합니다."
    fi
  else
    status="양호"
    reason="$TARGET 파일이 존재하지 않습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_30() {
  local code="U-30"
  local item="UMASK 설정 관리"
  local severity="중"
  local status="양호"
  local reason="systemd 서비스 UMask 및 로그인 UMASK 설정이 기준(022 이상)을 충족합니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln_flag=0

  local svc umask_val umask_dec
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    umask_val="$(systemctl show "$svc" -p UMask 2>/dev/null | awk -F= '{print $2}')"
    [ -z "$umask_val" ] && continue

    if [[ "$umask_val" =~ ^[0-7]+$ ]]; then
      umask_dec=$((8#$umask_val))
      if [ "$umask_dec" -lt 18 ]; then
        status="취약"
        reason="systemd 서비스 [$svc]에 설정된 UMask 값($umask_val)이 022 미만입니다."
        vuln_flag=1
        break
      fi
    else
      status="N/A"
      reason="systemd 서비스 [$svc]의 UMask 값 형식을 해석할 수 없습니다. (UMask=$umask_val)"
      vuln_flag=1
      break
    fi
  done < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')

  if [ "$vuln_flag" -eq 0 ]; then
    if grep -q "pam_umask\.so" /etc/pam.d/common-session 2>/dev/null; then
      local login_umask
      login_umask="$(grep -E "^[[:space:]]*UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -n 1)"

      if [ -z "$login_umask" ]; then
        status="취약"
        reason="/etc/login.defs 파일에 UMASK 설정이 존재하지 않습니다."
        vuln_flag=1
      elif [[ "$login_umask" =~ ^[0-7]+$ ]]; then
        if [ $((8#$login_umask)) -lt 18 ]; then
          status="취약"
          reason="/etc/login.defs 파일의 UMASK 값($login_umask)이 022 미만입니다."
          vuln_flag=1
        fi
      else
        status="N/A"
        reason="/etc/login.defs의 UMASK 값 형식을 해석할 수 없습니다. (UMASK=$login_umask)"
        vuln_flag=1
      fi
    else
      status="취약"
      reason="PAM 설정에 pam_umask.so 모듈이 적용되어 있지 않습니다."
      vuln_flag=1
    fi
  fi

  if [ "$vuln_flag" -eq 0 ]; then
    status="양호"
    reason="systemd 서비스 UMask 및 로그인 UMASK 설정이 기준(022 이상)을 충족합니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_31() {
  local code="U-31"
  local item="홈 디렉토리 소유자 및 권한 설정"
  local severity="중"
  local status="양호"
  local reason="일반 사용자 홈 디렉토리의 소유자가 해당 계정이며, 타 사용자 쓰기 권한이 제거되어 있습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local VULN=0
  local REASON=""

  local USER_LIST USER USERNAME HOMEDIR OWNER PERMIT OTHERS_PERMIT
  USER_LIST="$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /nologin|false/ { print $1 ":" $6 }' /etc/passwd 2>/dev/null)"

  for USER in $USER_LIST; do
    USERNAME="${USER%%:*}"
    HOMEDIR="${USER#*:}"

    if [ -d "$HOMEDIR" ]; then
      OWNER="$(stat -c '%U' "$HOMEDIR" 2>/dev/null)"
      PERMIT="$(stat -c '%a' "$HOMEDIR" 2>/dev/null)"
      OTHERS_PERMIT="${PERMIT: -1}"

      if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
        VULN=1
        REASON="${REASON}홈 디렉토리 정보 확인 실패: $USERNAME 홈($HOMEDIR) | "
        continue
      fi

      if [ "$OWNER" != "$USERNAME" ]; then
        VULN=1
        REASON="${REASON}소유자 불일치: $USERNAME 홈($HOMEDIR), 현재 소유자=$OWNER | "
      fi

      if [[ "$OTHERS_PERMIT" =~ [2367] ]]; then
        VULN=1
        REASON="${REASON}타 사용자 쓰기 권한 존재: $USERNAME 홈($HOMEDIR), perm=$PERMIT | "
      fi
    else
      VULN=1
      REASON="${REASON}홈 디렉토리 미존재: $USERNAME 홈($HOMEDIR) | "
    fi
  done

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    REASON="$(echo "$REASON" | tr '\r' ' ' | sed -e 's/[[:space:]]*$//')"
    reason="$REASON"
  else
    status="양호"
    reason="일반 사용자 홈 디렉토리의 소유자가 해당 계정이며, 타 사용자 쓰기 권한이 제거되어 있습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_32() {
  local code="U-32"
  local item="홈 디렉토리로 지정한 디렉토리의 존재 관리"
  local severity="중"
  local status="양호"
  local reason="로그인 가능한 계정 중 홈 디렉토리가 없거나 존재하지 않는 계정이 발견되지 않습니다."

  _json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local missing=()

  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue

    case "$shell" in
      */nologin|*/false) continue ;;
    esac

    if [[ -z "$home" || "$home" == "/" ]]; then
      missing+=("$user (home=$home)")
      continue
    fi
    if [[ ! -d "$home" ]]; then
      missing+=("$user (home=$home)")
    fi
  done < /etc/passwd

  if (( ${#missing[@]} > 0 )); then
    status="취약"
    reason="로그인 가능한 계정 중 홈 디렉토리가 없거나 존재하지 않는 항목이 있습니다(예: ${missing[0]})."
  else
    status="양호"
    reason="로그인 가능한 계정 중 홈 디렉토리가 없거나 존재하지 않는 계정이 발견되지 않습니다."
  fi

  local r="$reason"
  r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#r} > 250 )); then r="${r:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}

U_33() {
  local code="U-33"
  local item="숨겨진 파일 및 디렉터리 검색 및 제거"
  local severity="하"
  local status="양호"
  local reason="의심스러운 숨김파일이 발견되지 않았습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local max_list=20
  local sus_hidden_files sus_count sample

  sus_hidden_files="$(find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /run -prune -o \
    -path /dev -prune -o \
    -name ".*" -type f \
    \( -executable -o -perm -4000 -o -perm -2000 -o -mtime -7 \) \
    ! -name ".bash_history" \
    ! -name ".lesshst" \
    ! -name ".viminfo" \
    ! -name "*.hmac" \
    ! -name ".updated" \
    ! -name ".rpm.lock" \
    ! -name ".pwd.lock" \
    -print 2>/dev/null)"

  if [ -n "$sus_hidden_files" ]; then
    sus_count="$(printf '%s\n' "$sus_hidden_files" | sed '/^$/d' | wc -l | tr -d ' ')"
    if [ "${sus_count:-0}" -gt 0 ]; then
      status="취약"
      sample="$(printf '%s\n' "$sus_hidden_files" | sed '/^$/d' | head -n "$max_list" | paste -sd ',' -)"
      if [ "$sus_count" -gt "$max_list" ]; then
        reason="의심 숨김파일 ${sus_count}개 발견(상위 ${max_list}개 예시: ${sample} ...)"
      else
        reason="의심 숨김파일 ${sus_count}개 발견: ${sample}"
      fi
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_34() {
  local code="U-34"
  local item="Finger 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="Finger 서비스가 비활성화되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local reasons=()
  local port_check=""
  local svc

  local services=("finger" "fingerd" "in.fingerd" "finger.socket")

  for svc in "${services[@]}"; do
    if systemctl is-active "$svc" >/dev/null 2>&1; then
      vuln=1
      reasons+=("Finger 서비스가 활성화되어 있습니다($svc).")
    fi
  done

  if ps -ef | grep -v grep | grep -Ei "fingerd|in\.fingerd" >/dev/null 2>&1; then
    vuln=1
    reasons+=("Finger 프로세스가 실행 중입니다.")
  fi

  if command -v ss >/dev/null 2>&1; then
    port_check="$(ss -nlp 2>/dev/null | grep -w ":79" || true)"
  else
    port_check="$(netstat -natp 2>/dev/null | grep -w ":79" || true)"
  fi

  if [ -n "$port_check" ]; then
    vuln=1
    reasons+=("Finger 포트(79)가 리스닝 중입니다.")
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="$(IFS=' '; printf '%s' "${reasons[*]}")"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_35() {
  local code="U-35"
  local item="공유 서비스에 대한 익명 접근 제한 설정"
  local severity="상"
  local status="양호"
  local reason="점검 대상 공유 서비스에서 익명/게스트 접근을 유발하는 설정이 발견되지 않았습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln_flag=0
  local reasons=()

  is_listening_port() {
    ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$"
  }
  is_active_service() {
    systemctl is-active "$1" >/dev/null 2>&1
  }
  dedup() { printf "%s\n" "$@" | awk 'NF && !seen[$0]++'; }

  local ftp_checked=0 ftp_running=0 ftp_pkg=0 ftp_conf_found=0
  local VSFTPD_FILES=() PROFTPD_FILES=()
  local conf pkg

  if command -v rpm >/dev/null 2>&1; then
    rpm -q vsftpd >/dev/null 2>&1 && ftp_pkg=1
    rpm -q proftpd >/dev/null 2>&1 && ftp_pkg=1
    rpm -q proftpd-core >/dev/null 2>&1 && ftp_pkg=1
  fi

  if is_active_service vsftpd || is_active_service proftpd; then
    ftp_running=1
  fi
  if is_listening_port 21; then
    ftp_running=1
  fi

  for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
    [ -f "$f" ] && VSFTPD_FILES+=("$f")
  done
  for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf /etc/proftpd.d/proftpd.conf; do
    [ -f "$f" ] && PROFTPD_FILES+=("$f")
  done

  if command -v rpm >/dev/null 2>&1; then
    if rpm -q vsftpd >/dev/null 2>&1; then
      while IFS= read -r f; do
        [ -f "$f" ] && VSFTPD_FILES+=("$f")
      done < <(rpm -qc vsftpd 2>/dev/null)
    fi
    for pkg in proftpd proftpd-core; do
      if rpm -q "$pkg" >/dev/null 2>&1; then
        while IFS= read -r f; do
          [ -f "$f" ] && PROFTPD_FILES+=("$f")
        done < <(rpm -qc "$pkg" 2>/dev/null)
      fi
    done
  fi

  VSFTPD_FILES=( $(dedup "${VSFTPD_FILES[@]}") )
  PROFTPD_FILES=( $(dedup "${PROFTPD_FILES[@]}") )

  if [ "${#VSFTPD_FILES[@]}" -gt 0 ] || [ "${#PROFTPD_FILES[@]}" -gt 0 ]; then
    ftp_conf_found=1
  fi
  if [ "$ftp_conf_found" -eq 1 ] || [ "$ftp_running" -eq 1 ] || [ "$ftp_pkg" -eq 1 ]; then
    ftp_checked=1
  fi

  if [ "$ftp_checked" -eq 1 ]; then
    for conf in "${PROFTPD_FILES[@]}"; do
      [ -f "$conf" ] || continue
      local block_hit
      block_hit="$(
        awk '
          BEGIN{inblk=0;hit=0}
          /^[[:space:]]*#/ {next}
          /<Anonymous[[:space:]>]/ {inblk=1}
          inblk && /<\/Anonymous>/ {inblk=0}
          inblk && ($1 ~ /^User$/ || $1 ~ /^UserAlias$/) {hit=1}
          END{print hit}
        ' "$conf" 2>/dev/null
      )"
      if [ "$block_hit" = "1" ]; then
        vuln_flag=1
        reasons+=("${conf} 파일에서 익명(Anonymous) FTP 설정 블록이 존재합니다.")
      fi
    done

    for conf in "${VSFTPD_FILES[@]}"; do
      [ -f "$conf" ] || continue
      local last_val
      last_val="$(
        grep -i '^[[:space:]]*anonymous_enable[[:space:]]*=' "$conf" 2>/dev/null \
          | grep -v '^[[:space:]]*#' \
          | tail -n 1 \
          | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}'
      )"
      if [ -n "$last_val" ] && [ "$last_val" = "yes" ]; then
        vuln_flag=1
        reasons+=("${conf} 파일에서 익명 FTP 접속 허용(anonymous_enable=YES).")
      fi
    done

    if [ "$ftp_conf_found" -eq 0 ] && [ "$ftp_running" -eq 1 ]; then
      vuln_flag=1
      reasons+=("FTP 서비스가 동작 중이나(vsftpd/proftpd 또는 21/tcp 리슨), 설정 파일을 확인할 수 없습니다.")
    fi
  fi

  local nfs_checked=0 nfs_running=0 nfs_conf_found=0 nfs_pkg=0

  [ -f /etc/exports ] && nfs_conf_found=1
  is_active_service nfs-server && nfs_running=1
  if command -v rpm >/dev/null 2>&1; then
    rpm -q nfs-utils >/dev/null 2>&1 && nfs_pkg=1
  fi
  if [ "$nfs_conf_found" -eq 1 ] || [ "$nfs_running" -eq 1 ] || [ "$nfs_pkg" -eq 1 ]; then
    nfs_checked=1
  fi

  if [ "$nfs_checked" -eq 1 ]; then
    if [ -f /etc/exports ]; then
      local cnt_no_root cnt_star
      cnt_no_root="$(
        grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null \
          | grep -E '(^|[[:space:]\(,])no_root_squash([[:space:]\),]|$)' \
          | wc -l | tr -d ' '
      )"
      if [ "${cnt_no_root:-0}" -gt 0 ]; then
        vuln_flag=1
        reasons+=("/etc/exports 에 no_root_squash 설정이 존재합니다.")
      fi

      cnt_star="$(
        grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null \
          | grep -E '(^|[[:space:]])\*([[:space:]\(]|$)' \
          | wc -l | tr -d ' '
      )"
      if [ "${cnt_star:-0}" -gt 0 ]; then
        vuln_flag=1
        reasons+=("/etc/exports 전체 호스트(*) 공유 설정이 존재합니다.")
      fi
    else
      if [ "$nfs_running" -eq 1 ]; then
        vuln_flag=1
        reasons+=("NFS 서비스가 동작 중이나(nfs-server active), /etc/exports 파일이 존재하지 않습니다.")
      fi
    fi
  fi

  local smb_checked=0 smb_running=0 smb_conf_found=0 smb_pkg=0

  [ -f /etc/samba/smb.conf ] && smb_conf_found=1
  (is_active_service smb || is_active_service nmb) && smb_running=1
  if command -v rpm >/dev/null 2>&1; then
    rpm -q samba >/dev/null 2>&1 && smb_pkg=1
  fi
  if [ "$smb_conf_found" -eq 1 ] || [ "$smb_running" -eq 1 ] || [ "$smb_pkg" -eq 1 ]; then
    smb_checked=1
  fi

  if [ "$smb_checked" -eq 1 ]; then
    if [ -f /etc/samba/smb.conf ]; then
      local smb_hits cnt_guest cnt_public cnt_share cnt_map
      smb_hits="$(
        grep -v '^[[:space:]]*#' /etc/samba/smb.conf 2>/dev/null \
          | grep -Ei '^[[:space:]]*(guest[[:space:]]+ok|public|map[[:space:]]+to[[:space:]]+guest|security)[[:space:]]*=' \
          || true
      )"
      if [ -n "$smb_hits" ]; then
        cnt_guest="$(printf '%s\n' "$smb_hits" | grep -Ei '^[[:space:]]*guest[[:space:]]+ok[[:space:]]*=[[:space:]]*yes' | wc -l | tr -d ' ')"
        cnt_public="$(printf '%s\n' "$smb_hits" | grep -Ei '^[[:space:]]*public[[:space:]]*=[[:space:]]*yes' | wc -l | tr -d ' ')"
        cnt_share="$(printf '%s\n' "$smb_hits" | grep -Ei '^[[:space:]]*security[[:space:]]*=[[:space:]]*share' | wc -l | tr -d ' ')"
        cnt_map="$(printf '%s\n' "$smb_hits" | grep -Ei '^[[:space:]]*map[[:space:]]+to[[:space:]]+guest[[:space:]]*=' | wc -l | tr -d ' ')"

        if [ "${cnt_guest:-0}" -gt 0 ] || [ "${cnt_public:-0}" -gt 0 ] || [ "${cnt_share:-0}" -gt 0 ] || [ "${cnt_map:-0}" -gt 0 ]; then
          vuln_flag=1
          local sample
          sample="$(printf '%s\n' "$smb_hits" | head -n 5 | paste -sd ',' -)"
          reasons+=("/etc/samba/smb.conf 익명/게스트 접근 유발 가능 설정이 존재합니다(예: ${sample}).")
        fi
      fi
    else
      if [ "$smb_running" -eq 1 ]; then
        vuln_flag=1
        reasons+=("Samba 서비스가 동작 중이나(smb/nmb active), /etc/samba/smb.conf 파일이 존재하지 않습니다.")
      fi
    fi
  fi

  if [ "$vuln_flag" -eq 1 ]; then
    status="취약"
    reason="$(IFS=' '; printf '%s' "${reasons[*]}")"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_36() {
  local code="U-36"
  local item="r 계열 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="r 계열 서비스 및 관련 포트가 비활성화되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local reasons=()
  local check_port=""
  local svc=""
  local xinetd_vul=""

  check_port="$(ss -antl 2>/dev/null | grep -E ':(512|513|514)\b' || true)"
  if [ -n "$check_port" ]; then
    vuln=1
    reasons+=("r-command 관련 포트(512, 513, 514)가 리스닝 중입니다.")
  fi

  local services=("rlogin" "rsh" "rexec" "shell" "login" "exec")
  for svc in "${services[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      vuln=1
      reasons+=("활성화된 r 계열 서비스 발견: ${svc}(active).")
    fi
  done

  if [ -d "/etc/xinetd.d" ]; then
    xinetd_vul="$(
      grep -lE "disable[[:space:]]*=[[:space:]]*no" \
        /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec \
        /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec \
        2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/[[:space:]]$//'
    )"
    if [ -n "$xinetd_vul" ]; then
      vuln=1
      reasons+=("xinetd 설정에서 r 계열 서비스가 활성화(disable=no)되어 있습니다: ${xinetd_vul}.")
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="$(IFS=' '; printf '%s' "${reasons[*]}")"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_37() {
  local code="U-37"
  local item="crontab 설정파일 권한 설정 미흡"
  local severity="상"
  local status="양호"
  local reason="crontab/at 실행 권한 및 관련 파일 권한이 가이드라인 기준(640 이하)을 준수하고 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local offenders=()
  local MAX_EVIDENCE=50

  add_offender() {
    if [ "${#offenders[@]}" -lt "$MAX_EVIDENCE" ]; then
      offenders+=("$1")
    fi
  }

  _oct2dec() { echo $((8#$1)); }

  check_file_640_guideline() {
    local f="$1"
    [ -e "$f" ] || return 0

    local owner perm
    owner="$(stat -Lc '%U' "$f" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$f" 2>/dev/null)"
    
    if [ "$owner" != "root" ]; then
      vuln=1; add_offender "$f: 소유자($owner) 미일치"
    fi

    local perm_dec=$(_oct2dec "$perm")
    if [ $((perm_dec & 0007)) -ne 0 ]; then
      vuln=1; add_offender "$f: 일반 사용자 권한 존재(perm=$perm)"
    fi

    if [ $((perm_dec & 0030)) -ne 0 ]; then
      vuln=1; add_offender "$f: 그룹 쓰기/실행 권한 존재(perm=$perm)"
    fi
  }

  check_cmd_750_guideline() {
    local f="$1"
    [ -e "$f" ] || return 0

    local owner perm
    owner="$(stat -Lc '%U' "$f" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$f" 2>/dev/null)"

    if [ "$owner" != "root" ]; then
      vuln=1; add_offender "$f: 소유자($owner) 미일치"
    fi

    local perm_dec=$(_oct2dec "$perm")
    if [ $((perm_dec & 0001)) -ne 0 ]; then
      vuln=1; add_offender "$f: 일반 사용자 실행 권한 존재(perm=$perm)"
    fi
    
    if [ $((perm_dec & 06000)) -ne 0 ]; then
      vuln=1; add_offender "$f: SUID/SGID 설정됨(perm=$perm)"
    fi
  }

  local cmds=("/usr/bin/crontab" "/usr/bin/at" "/usr/bin/atq" "/usr/bin/atrm")
  for c in "${cmds[@]}"; do
    check_cmd_750_guideline "$c"
  done

  local config_files=(
    "/etc/crontab" "/etc/anacrontab" 
    "/etc/cron.allow" "/etc/cron.deny" 
    "/etc/at.allow" "/etc/at.deny"
  )
  for f in "${config_files[@]}"; do
    check_file_640_guideline "$f"
  done

  local config_dirs=(
    "/etc/cron.d" "/etc/cron.hourly" "/etc/cron.daily" 
    "/etc/cron.weekly" "/etc/cron.monthly" 
    "/var/spool/cron" "/var/spool/at"
  )
  for d in "${config_dirs[@]}"; do
    if [ -d "$d" ]; then
      local d_perm=$(stat -Lc '%a' "$d" 2>/dev/null)
      if [ $(( 8#$d_perm & 0007 )) -ne 0 ]; then
        vuln=1; add_offender "$d: 일반 사용자 접근 권한 존재(perm=$d_perm)"
      fi
    fi
  done

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    local reason_line="${offenders[0]}"
    local extra=$(( ${#offenders[@]} - 1 ))
    [ "$extra" -gt 0 ] && reason_line="${reason_line} 외 ${extra}건"
    reason="$reason_line"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_38() {
  local code="U-38"
  local item="DoS 공격에 취약한 서비스 비활성화"
  local severity="상"
  local status="양호" 
  local reason="모든 DoS 취약 서비스(echo, discard, daytime, chargen 등)가 비활성화되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local evidences=()

  if [ -d /etc/xinetd.d ]; then
    for svc in echo discard daytime chargen; do
      if [ -f "/etc/xinetd.d/$svc" ]; then
        if ! grep -vE '^\s*#' "/etc/xinetd.d/$svc" | grep -qiE 'disable\s*=\s*yes'; then
          vuln=1
          evidences+=("xinetd: $svc 활성 상태")
        fi
      fi
    done
  fi

  if [ -f /etc/inetd.conf ]; then
    if grep -vE '^\s*#' /etc/inetd.conf | grep -qiE 'echo|discard|daytime|chargen'; then
      vuln=1
      evidences+=("inetd: 취약 서비스 주석 미처리")
    fi
  fi

  local check_units=(
    "echo.socket" "discard.socket" "daytime.socket" "chargen.socket"
    "echo.service" "discard.service" "daytime.service" "chargen.service"
    "snmpd.service" "named.service" "bind9.service"
  )

  for u in "${check_units[@]}"; do
    if systemctl list-unit-files "$u" &>/dev/null; then
      if systemctl is-active --quiet "$u" 2>/dev/null || systemctl is-enabled --quiet "$u" 2>/dev/null; then
        vuln=1
        evidences+=("systemd: $u 활성 상태")
      fi
    fi
  done

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="${evidences[0]}"
    [ "${#evidences[@]}" -gt 1 ] && reason="${reason} 외 $(( ${#evidences[@]} - 1 ))건"
  else
    status="양호"
    reason="DoS 공격에 취약한 서비스가 비활성화되어 있거나 설치되어 있지 않습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(json_escape "$reason")"
}

U_39() {
  local code="U-39"
  local item="불필요한 NFS 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="NFS 서비스 관련 데몬이 비활성화되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local found=0
  local active_services=()

  local nfs_units=("nfs-server" "rpcbind" "nfs-mountd" "nfs-idmapd")

  if command -v systemctl >/dev/null 2>&1; then
    for u in "${nfs_units[@]}"; do
      if systemctl is-active --quiet "${u}.service" 2>/dev/null || \
         systemctl is-enabled --quiet "${u}.service" 2>/dev/null; then
        found=1
        active_services+=("${u}.service")
      fi
    done
  fi

  if [ "$found" -eq 1 ]; then
    status="취약"
    reason="불필요한 NFS 서비스가 활성화되어 있습니다: ${active_services[*]}"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_40() {
  local code="U-40"
  local item="NFS 접근 통제"
  local severity="상"
  local status="양호"
  local reason="NFS 서비스가 동작하지 않거나, 접근 통제가 적절히 설정되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local nfs_running=0
  local etc_exports_all_count=0
  local etc_exports_insecure_count=0
  local etc_exports_directory_count=0
  local etc_exports_squash_count=0

  if [ "$(ps -ef 2>/dev/null \
        | grep -iE 'nfs|rpc\.statd|statd|rpc\.lockd|lockd' \
        | grep -ivE 'grep|kblockd|rstatd' \
        | wc -l | tr -d ' ')" -gt 0 ]; then
    nfs_running=1
  fi

  if [ "$nfs_running" -eq 1 ]; then
    if [ -f /etc/exports ]; then
      etc_exports_all_count="$(grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | grep '\*' | wc -l | tr -d ' ')"
      etc_exports_insecure_count="$(grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | grep -i 'insecure' | wc -l | tr -d ' ')"
      etc_exports_directory_count="$(grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | wc -l | tr -d ' ')"
      etc_exports_squash_count="$(grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | grep -iE 'root_squash|all_squash' | wc -l | tr -d ' ')"

      if [ "${etc_exports_all_count:-0}" -gt 0 ]; then
        status="취약"
        reason="/etc/exports 파일에 '*' 설정이 있습니다."
      elif [ "${etc_exports_insecure_count:-0}" -gt 0 ]; then
        status="취약"
        reason="/etc/exports 파일에 'insecure' 옵션이 설정되어 있습니다."
      else
        if [ "${etc_exports_directory_count:-0}" -ne "${etc_exports_squash_count:-0}" ]; then
          status="취약"
          reason="/etc/exports 파일에 'root_squash' 또는 'all_squash' 옵션이 설정되어 있지 않습니다."
        else
          status="양호"
          reason="NFS 접근 통제가 설정되어 있으며, 취약 설정('*', insecure, squash 미설정)이 발견되지 않았습니다."
        fi
      fi
    else
      status="취약"
      reason="NFS 관련 데몬이 실행 중이나 /etc/exports 파일이 존재하지 않아 점검할 수 없습니다."
    fi
  else
    status="양호"
    reason="NFS 관련 데몬이 실행 중이지 않습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_41() {
  local code="U-41"
  local item="불필요한 automountd 제거"
  local severity="상"
  local status="양호"
  local reason="automountd(autofs) 서비스가 비활성화되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local reasons=()

  if systemctl is-active --quiet autofs 2>/dev/null; then
    vuln=1
    reasons+=("automountd(autofs) 서비스가 활성화되어 있습니다(autofs active).")
  fi

  if ps -ef 2>/dev/null | grep -v grep | grep -Ei "automount|autofs" >/dev/null 2>&1; then
    vuln=1
    reasons+=("automountd 관련 프로세스가 실행 중입니다.")
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="$(IFS=' '; printf '%s' "${reasons[*]}")"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_42() {
  local code="U-42"
  local item="불필요한 RPC 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="rpcbind(RPC) 서비스가 비활성화되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local rpc_active=0
  if systemctl is-active rpcbind.service >/dev/null 2>&1 || systemctl is-active rpcbind.socket >/dev/null 2>&1; then
    rpc_active=1
  fi

  if [ "$rpc_active" -eq 1 ]; then
    status="취약"
    reason="rpcbind(RPC) 서비스가 활성 상태입니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_43() {
  local code="U-43"
  local item="NIS, NIS+ 점검"
  local severity="상"
  local status="양호"
  local reason="NIS 서비스가 비활성화되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local nis_in_use=0
  local vulnerable=0
  local evidences=()

  local nis_procs_regex='ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated|yppasswdd|ypupdated'
  local nisplus_procs_regex='nisplus|rpc\.nisd|nisd'

  if command -v systemctl >/dev/null 2>&1; then
    local nis_units=("ypserv.service" "ypbind.service" "ypxfrd.service")
    local unit

    for unit in "${nis_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-active --quiet "$unit" 2>/dev/null || systemctl is-enabled --quiet "$unit" 2>/dev/null; then
          nis_in_use=1
          vulnerable=1
          evidences+=("systemd: ${unit} 가 active/enabled 상태입니다.")
        fi
      fi
    done

    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "rpcbind.service"; then
      if systemctl is-active --quiet "rpcbind.service" 2>/dev/null || systemctl is-enabled --quiet "rpcbind.service" 2>/dev/null; then
        evidences+=("info: rpcbind.service 가 active/enabled 입니다(NIS/RPC 계열 사용 가능성, 단 NIS 단독 증거는 아님).")
      fi
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE "$nis_procs_regex" | grep -vE 'grep|U_43\(|U_28\(' >/dev/null 2>&1; then
    nis_in_use=1
    vulnerable=1
    evidences+=("process: NIS 관련 프로세스(yp*)가 실행 중입니다.")
  fi

  if command -v ss >/dev/null 2>&1; then
    if ss -lntup 2>/dev/null | grep -E ':(111)\b' >/dev/null 2>&1; then
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(ss).")
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lntup 2>/dev/null | grep -E ':(111)\b' >/dev/null 2>&1; then
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(netstat).")
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE "$nisplus_procs_regex" | grep -v grep >/dev/null 2>&1; then
    evidences+=("info: NIS+ 관련 프로세스 흔적이 감지되었습니다.")
  fi

  if [ "$nis_in_use" -eq 0 ]; then
    status="N/A"
    reason="NIS 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다(yp* 서비스/프로세스 미검출)."
  elif [ "$vulnerable" -eq 1 ]; then
    status="취약"
    if [ "${#evidences[@]}" -gt 0 ]; then
      reason="${evidences[0]}"
      local extra=$(( ${#evidences[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="NIS 서비스가 활성화(실행/enable)된 흔적이 확인되었습니다."
    fi
  else
    status="양호"
    reason="NIS 사용 흔적은 있으나 활성화(active/enabled) 상태는 확인되지 않았습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_44() {
  local code="U-44"
  local item="tftp, talk 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="tftp/talk/ntalk 서비스가 비활성화되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local services=("tftp" "talk" "ntalk")
  local vuln=0
  local reasons=()
  local s u disable_line

  if command -v systemctl >/dev/null 2>&1; then
    for s in "${services[@]}"; do
      local units=(
        "$s" "$s.service" "${s}d" "${s}d.service"
        "${s}-server" "${s}-server.service"
        "tftp-server.service" "tftpd.service" "talkd.service"
      )
      for u in "${units[@]}"; do
        if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
          if systemctl is-active --quiet "$u" 2>/dev/null; then
            vuln=1
            reasons+=("${s} 서비스가 systemd에서 활성 상태입니다(unit=${u}).")
          fi
        fi
      done
    done
  fi

  if [ -d /etc/xinetd.d ]; then
    for s in "${services[@]}"; do
      if [ -f "/etc/xinetd.d/$s" ]; then
        disable_line="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "/etc/xinetd.d/$s" 2>/dev/null \
          | grep -Ei '^[[:space:]]*disable[[:space:]]*=' | tail -n 1)"
        if ! echo "$disable_line" | grep -Eiq 'disable[[:space:]]*=[[:space:]]*yes'; then
          vuln=1
          reasons+=("${s} 서비스가 /etc/xinetd.d/${s} 에서 비활성화(disable=yes)되어 있지 않습니다.")
        fi
      fi
    done
  fi

  if [ -f /etc/inetd.conf ]; then
    for s in "${services[@]}"; do
      if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null \
        | grep -Eiq "(^|[[:space:]])$s([[:space:]]|$)"; then
        vuln=1
        reasons+=("${s} 서비스가 /etc/inetd.conf 파일에서 활성 상태(주석 아님)로 존재합니다.")
      fi
    done
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="${reasons[0]}"
    local extra=$(( ${#reasons[@]} - 1 ))
    if [ "$extra" -gt 0 ]; then
      reason="${reason} 외 ${extra}건"
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_45() {
  local code="U-45"
  local item="메일 서비스 버전 점검"
  local severity="상"
  local status="양호"
  local reason="메일 서비스 버전이 기준(8.18.2)에 부합합니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local expected_prefix="8.18.2"
  local smtp_port_count=0
  local smtp_ports=()
  local i netstat_smtp_count
  local rpm_smtp_version=""
  local dnf_smtp_version=""
  local ps_smtp_count=0

  if [ -f /etc/services ]; then
    smtp_port_count="$(grep -vE '^#|^\s#' /etc/services 2>/dev/null \
      | awk 'tolower($1)=="smtp" {print $2}' \
      | awk -F/ 'tolower($2)=="tcp" {print $1}' \
      | wc -l | tr -d ' ')"

    if [ "${smtp_port_count:-0}" -gt 0 ]; then
      mapfile -t smtp_ports < <(grep -vE '^#|^\s#' /etc/services 2>/dev/null \
        | awk 'tolower($1)=="smtp" {print $2}' \
        | awk -F/ 'tolower($2)=="tcp" {print $1}')

      for ((i=0; i<${#smtp_ports[@]}; i++)); do
        netstat_smtp_count="$(netstat -nat 2>/dev/null \
          | grep -w 'tcp' \
          | grep -Ei 'listen|established|syn_sent|syn_received' \
          | grep ":${smtp_ports[$i]} " \
          | wc -l | tr -d ' ')"

        if [ "${netstat_smtp_count:-0}" -gt 0 ]; then
          rpm_smtp_version="$(rpm -qa 2>/dev/null | grep 'sendmail' | awk -F 'sendmail-' '{print $2}' | head -n 1)"
          dnf_smtp_version="$(dnf list installed sendmail 2>/dev/null | grep -v 'Installed Packages' | awk '{print $2}' | head -n 1)"

          if [[ "$rpm_smtp_version" != ${expected_prefix}* ]] && [[ "$dnf_smtp_version" != ${expected_prefix}* ]]; then
            status="취약"
            reason="메일 서비스 버전이 최신 버전(${expected_prefix})이 아닙니다."
          fi
          break
        fi
      done
    fi
  fi

  if [ "$status" != "취약" ]; then
    ps_smtp_count="$(ps -ef 2>/dev/null | grep -iE 'smtp|sendmail' | grep -v 'grep' | wc -l | tr -d ' ')"
    if [ "${ps_smtp_count:-0}" -gt 0 ]; then
      rpm_smtp_version="$(rpm -qa 2>/dev/null | grep 'sendmail' | awk -F 'sendmail-' '{print $2}' | head -n 1)"
      dnf_smtp_version="$(dnf list installed sendmail 2>/dev/null | grep -v 'Installed Packages' | awk '{print $2}' | head -n 1)"
      if [[ "$rpm_smtp_version" != ${expected_prefix}* ]] && [[ "$dnf_smtp_version" != ${expected_prefix}* ]]; then
        status="취약"
        reason="메일 서비스 버전이 최신 버전(${expected_prefix})이 아닙니다."
      fi
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_46() {
  local code="U-46"
  local item="일반 사용자의 메일 서비스 실행 방지"
  local severity="상"
  local status="양호"
  local reason="Sendmail 실행 제한(restrictqrun) 설정이 적용되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local reasons=()

  if ps -ef 2>/dev/null | grep -v grep | grep -q "sendmail"; then
    if [ -f "/etc/mail/sendmail.cf" ]; then
      local check
      check="$(grep -i "PrivacyOptions" /etc/mail/sendmail.cf 2>/dev/null | grep -i "restrictqrun" || true)"

      if [ -z "$check" ]; then
        vuln=1
        reasons+=("Sendmail 서비스가 실행 중이며 restrictqrun 설정이 적용되어 있지 않습니다.")
      fi
    else
      vuln=1
      reasons+=("Sendmail 서비스가 실행 중이나 /etc/mail/sendmail.cf 설정파일이 존재하지 않습니다.")
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="${reasons[0]}"
    local extra=$(( ${#reasons[@]} - 1 ))
    if [ "$extra" -gt 0 ]; then
      reason="${reason} 외 ${extra}건"
    fi
  else
    status="양호"
    reason="Sendmail 서비스가 실행 중이 아니거나, 실행 중인 경우에도 restrictqrun 설정이 적용되어 있습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_47() {
  local code="U-47"
  local item="스팸 메일 릴레이 제한"
  local severity="상"
  local status="양호"
  local reason="릴레이 제한이 적절히 설정되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  if systemctl is-active postfix.service >/dev/null 2>&1 || command -v postconf >/dev/null 2>&1; then
    if command -v postconf >/dev/null 2>&1; then
      local relay_restr recip_restr mynet
      relay_restr="$(postconf -h smtpd_relay_restrictions 2>/dev/null)"
      recip_restr="$(postconf -h smtpd_recipient_restrictions 2>/dev/null)"
      mynet="$(postconf -h mynetworks 2>/dev/null)"

      local has_reject=0
      echo "$relay_restr $recip_restr" | grep -q "reject_unauth_destination" && has_reject=1

      local net_ok=1
      echo "$mynet" | grep -Eq '0\.0\.0\.0/0|::/0' && net_ok=0

      if [ "$has_reject" -eq 1 ] && [ "$net_ok" -eq 1 ]; then
        status="양호"
        reason="Postfix에서 reject_unauth_destination 설정이 존재하며 mynetworks가 과다(0.0.0.0/0, ::/0)로 설정되어 있지 않습니다."
      else
        status="취약"
        reason="reject_unauth_destination 설정 누락 또는 mynetworks 과다 설정 가능성이 있습니다."
      fi

      printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
        "$(json_escape "$code")" \
        "$(json_escape "$item")" \
        "$(json_escape "$severity")" \
        "$(json_escape "$status")" \
        "$(json_escape "$reason")"
      return 0
    fi
  fi

  if systemctl is-active sendmail.service >/dev/null 2>&1 || command -v sendmail >/dev/null 2>&1; then
    status="수동점검"
    reason="Sendmail 사용 시 릴레이 제한 자동 판정이 어려워 수동 점검이 필요합니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  status="양호"
  reason="메일 서비스(Postfix/Sendmail)가 사용되지 않는 것으로 판단됩니다."
  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_48() {
  local code="U-48"
  local item="expn, vrfy 명령어 제한"
  local severity="중"
  local status="양호"
  local reason="expn/vrfy 제한 설정이 적절히 적용되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local mail_in_use=0
  local vulnerable=0
  local evidences=()

  local has_sendmail=0
  local has_postfix=0
  local has_exim=0

  if command -v ss >/dev/null 2>&1; then
    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '(:25)$'; then
      mail_in_use=1
      evidences+=("network: TCP 25(smtp) LISTEN 감지(ss)")
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lnt 2>/dev/null | awk '{print $4}' | grep -Eq '(:25)$'; then
      mail_in_use=1
      evidences+=("network: TCP 25(smtp) LISTEN 감지(netstat)")
    fi
  fi

  if command -v systemctl >/dev/null 2>&1; then
    local unit
    for unit in sendmail.service postfix.service exim4.service; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
          mail_in_use=1
          evidences+=("systemd: ${unit} active")
          case "$unit" in
            sendmail.service) has_sendmail=1 ;;
            postfix.service)  has_postfix=1 ;;
            exim4.service)    has_exim=1 ;;
          esac
        fi
      fi
    done
  fi

  if ps -ef 2>/dev/null | grep -iE 'sendmail' | grep -v grep >/dev/null 2>&1; then
    mail_in_use=1
    has_sendmail=1
    evidences+=("process: sendmail 프로세스 감지")
  fi
  if ps -ef 2>/dev/null | grep -iE 'postfix|master' | grep -v grep >/dev/null 2>&1; then
    mail_in_use=1
    has_postfix=1
    evidences+=("process: postfix(master 등) 프로세스 감지")
  fi
  if ps -ef 2>/dev/null | grep -iE 'exim' | grep -v grep >/dev/null 2>&1; then
    mail_in_use=1
    has_exim=1
    evidences+=("process: exim 프로세스 감지")
  fi

  if [ "$mail_in_use" -eq 0 ]; then
    status="N/A"
    reason="메일(SMTP) 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다(25/tcp LISTEN 및 MTA 미검출)."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  local ok_cnt=0
  local bad_cnt=0

  if [ "$has_sendmail" -eq 1 ]; then
    local sendmail_ok=0
    local sendmail_cf_candidates=("/etc/mail/sendmail.cf" "/etc/sendmail.cf")
    local found_cf=""

    local cf
    for cf in "${sendmail_cf_candidates[@]}"; do
      if [ -f "$cf" ]; then
        found_cf="$cf"
        local goaway_count noexpn_novrfy_count
        goaway_count="$(grep -vE '^\s*#' "$cf" 2>/dev/null | grep -iE 'PrivacyOptions' | grep -i 'goaway' | wc -l | tr -d ' ')"
        noexpn_novrfy_count="$(grep -vE '^\s*#' "$cf" 2>/dev/null | grep -iE 'PrivacyOptions' | grep -i 'noexpn' | grep -i 'novrfy' | wc -l | tr -d ' ')"

        if [ "${goaway_count:-0}" -gt 0 ] || [ "${noexpn_novrfy_count:-0}" -gt 0 ]; then
          sendmail_ok=1
          evidences+=("sendmail: ${cf} 에 PrivacyOptions(goaway 또는 noexpn+novrfy) 설정 확인")
        else
          evidences+=("sendmail: ${cf} 에 noexpn/novrfy(goaway 포함) 설정이 없음")
        fi
        break
      fi
    done

    if [ -z "$found_cf" ]; then
      vulnerable=1
      bad_cnt=$((bad_cnt+1))
      evidences+=("sendmail: 실행 흔적은 있으나 sendmail.cf 파일을 찾지 못했습니다(설정 점검 불가).")
    else
      if [ "$sendmail_ok" -eq 1 ]; then
        ok_cnt=$((ok_cnt+1))
      else
        vulnerable=1
        bad_cnt=$((bad_cnt+1))
      fi
    fi
  fi

  if [ "$has_postfix" -eq 1 ]; then
    if [ -f /etc/postfix/main.cf ]; then
      local postfix_vrfy
      postfix_vrfy="$(grep -vE '^\s*#' /etc/postfix/main.cf 2>/dev/null \
        | grep -iE '^\s*disable_vrfy_command\s*=\s*yes\s*$' | wc -l | tr -d ' ')"

      if [ "${postfix_vrfy:-0}" -gt 0 ]; then
        ok_cnt=$((ok_cnt+1))
        evidences+=("postfix: /etc/postfix/main.cf 에 disable_vrfy_command=yes 설정 확인")
      else
        vulnerable=1
        bad_cnt=$((bad_cnt+1))
        evidences+=("postfix: postfix 사용 중이나 disable_vrfy_command=yes 설정이 없음")
      fi
    else
      vulnerable=1
      bad_cnt=$((bad_cnt+1))
      evidences+=("postfix: postfix 사용 흔적은 있으나 /etc/postfix/main.cf 파일이 없습니다(설정 점검 불가).")
    fi
  fi

  if [ "$has_exim" -eq 1 ]; then
    evidences+=("exim: exim 사용 흔적 감지(구성 파일 기반 vrfy/expn 제한 수동 확인 필요).")
  fi

  if [ "$vulnerable" -eq 1 ]; then
    status="취약"
    if [ "${#evidences[@]}" -gt 0 ]; then
      reason="${evidences[0]}"
      local extra=$(( ${#evidences[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="메일(SMTP) 서비스 사용 중이며 expn/vrfy 제한 설정이 미흡합니다(미설정/점검불가=${bad_cnt}, 설정확인=${ok_cnt})."
    fi
  else
    status="양호"
    reason="메일(SMTP) 서비스 사용 중이며 expn/vrfy 제한 설정이 확인되었습니다(설정확인=${ok_cnt})."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_49() {
  local code="U-49"
  local item="DNS 보안 버전 패치"
  local severity="상"
  local status="양호"
  local reason="주기적으로 패치를 관리하고 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local named_active=0
  local named_running=0
  local bind_ver=""
  local major="" minor="" patch=""

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet named 2>/dev/null; then
      named_active=1
    fi
  fi

  if ps -ef 2>/dev/null | grep -i 'named' | grep -v grep >/dev/null 2>&1; then
    named_running=1
  fi

  if [ "$named_active" -eq 0 ] && [ "$named_running" -eq 0 ]; then
    status="양호"
    reason="DNS 서비스(named)가 비활성/미사용 상태입니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  if command -v named >/dev/null 2>&1; then
    bind_ver="$(named -v 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  fi

  if [ -z "$bind_ver" ]; then
    if command -v rpm >/dev/null 2>&1; then
      bind_ver="$(rpm -q bind 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
    fi
  fi

  if [ -z "$bind_ver" ]; then
    status="취약"
    reason="named는 동작 중이나 BIND 버전을 확인하지 못했습니다(named -v / rpm -q bind 실패)."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  major="$(echo "$bind_ver" | awk -F. '{print $1}')"
  minor="$(echo "$bind_ver" | awk -F. '{print $2}')"
  patch="$(echo "$bind_ver" | awk -F. '{print $3}')"

  if [ "$major" -ne 9 ] 2>/dev/null; then
    status="취약"
    reason="BIND 메이저 버전이 9가 아닙니다(현재: ${bind_ver})."
  elif [ "$minor" -ge 19 ] 2>/dev/null; then
    status="취약"
    reason="BIND ${bind_ver} 는 9.19+(개발/테스트 버전으로 간주) 입니다. 운영 권고 버전(9.18.7 이상)으로 관리 필요."
  elif [ "$minor" -lt 18 ] 2>/dev/null; then
    status="취약"
    reason="BIND 버전이 9.18 미만입니다(현재: ${bind_ver}, 기준: 9.18.7 이상)."
  else
    if [ "$minor" -eq 18 ] 2>/dev/null && [ "$patch" -lt 7 ] 2>/dev/null; then
      status="취약"
      reason="BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다(현재: ${bind_ver})."
    else
      status="양호"
      reason="DNS 서비스 사용 중이며 BIND 버전이 기준 이상입니다(현재: ${bind_ver})."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_50() {
  local code="U-50"
  local item="DNS Zone Transfer 설정"
  local severity="상"
  local status="양호"
  local reason="Zone Transfer가 적절히 제한되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local ps_dns_count=0
  local allow_any_count=0

  ps_dns_count="$(ps -ef 2>/dev/null | grep -i 'named' | grep -v 'grep' | wc -l | tr -d ' ')"

  if [ "${ps_dns_count:-0}" -gt 0 ]; then
    if [ -f /etc/named.conf ]; then
      allow_any_count="$(grep -vE '^#|^\s#' /etc/named.conf 2>/dev/null \
        | grep -i 'allow-transfer' \
        | grep -i 'any' \
        | wc -l | tr -d ' ')"

      if [ "${allow_any_count:-0}" -gt 0 ]; then
        status="취약"
        reason="/etc/named.conf 파일에 allow-transfer { any; } 설정이 있습니다."
      else
        status="양호"
        reason="named 사용 중이며 allow-transfer { any; } 설정이 확인되지 않습니다."
      fi
    else
      status="취약"
      reason="named는 실행 중이나 /etc/named.conf 파일이 존재하지 않아 Zone Transfer 설정을 점검할 수 없습니다."
    fi
  else
    status="양호"
    reason="DNS(named) 서비스를 사용하지 않는 것으로 확인됩니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_51() {
  local code="U-51"
  local item="DNS 서비스의 취약한 동적 업데이트 설정 금지"
  local severity="중"
  local status="양호"
  local reason="DNS 동적 업데이트가 전체(any)로 허용되어 있지 않습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local reasons=()

  if ps -ef 2>/dev/null | grep -v grep | grep -q "named"; then
    local CONF="/etc/named.conf"
    local CONF_FILES=("$CONF")

    if [ -f "$CONF" ]; then
      local extracted_paths IN_FILE
      extracted_paths="$(grep -E '^\s*(include|file)' "$CONF" 2>/dev/null | awk -F'"' '{print $2}')"

      for IN_FILE in $extracted_paths; do
        if [ -f "$IN_FILE" ]; then
          CONF_FILES+=("$IN_FILE")
        elif [ -f "/etc/$IN_FILE" ]; then
          CONF_FILES+=("/etc/$IN_FILE")
        elif [ -f "/var/named/$IN_FILE" ]; then
          CONF_FILES+=("/var/named/$IN_FILE")
        fi
      done
    fi

    local FILE CHECK
    for FILE in "${CONF_FILES[@]}"; do
      if [ -f "$FILE" ]; then
        CHECK="$(grep -vE '^\s*//|^\s*#|^\s*/\*' "$FILE" 2>/dev/null \
          | grep -i "allow-update" \
          | grep -Ei 'any|\{\s*any\s*;\s*\}' || true)"

        if [ -n "$CHECK" ]; then
          vuln=1
          reasons+=("${FILE} 파일에서 동적 업데이트가 전체(any)로 허용되어 있습니다.")
        fi
      fi
    done
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="${reasons[0]}"
    local extra=$(( ${#reasons[@]} - 1 ))
    if [ "$extra" -gt 0 ]; then
      reason="${reason} 외 ${extra}건"
    fi
  else
    status="양호"
    reason="named 미사용이거나, 사용 중인 경우에도 allow-update any 설정이 확인되지 않습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_52() {
  local code="U-52"
  local item="Telnet 서비스 비활성화"
  local severity="중"
  local status="양호"
  local reason="Telnet 활성화 징후가 발견되지 않습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local details=()
  add_detail() { details+=("$1"); }

  local listen23=""
  listen23="$(ss -lntp 2>/dev/null | awk '$4 ~ /:23$/ {print}' | head -n 1)"
  if [ -n "$listen23" ]; then
    vuln=1
    add_detail "23/tcp LISTEN 감지"
  fi

  local units=("telnet.socket" "telnet.service" "telnet@.service" "telnetd.service")
  local u
  for u in "${units[@]}"; do
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
      local is_act="inactive" is_en="disabled"
      systemctl is-active "$u" >/dev/null 2>&1 && is_act="active"
      systemctl is-enabled "$u" >/dev/null 2>&1 && is_en="enabled"
      if [ "$is_act" = "active" ] || [ "$is_en" = "enabled" ]; then
        vuln=1
        add_detail "$u 상태: $is_act/$is_en"
      fi
    fi
  done

  if [ -r /etc/xinetd.d/telnet ]; then
    local disabled=""
    disabled="$(awk 'tolower($1)=="disable"{print tolower($3)}' /etc/xinetd.d/telnet 2>/dev/null | tail -n 1)"
    if [ "$disabled" != "yes" ]; then
      vuln=1
      add_detail "/etc/xinetd.d/telnet disable=${disabled:-미설정}"
    fi
  fi

  if [ -r /etc/inetd.conf ]; then
    if grep -Eq '^[[:space:]]*telnet[[:space:]]' /etc/inetd.conf 2>/dev/null; then
      vuln=1
      add_detail "/etc/inetd.conf: telnet 설정 존재"
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="Telnet 활성화 징후: ${details[0]}"
    local extra=$(( ${#details[@]} - 1 ))
    if [ "$extra" -gt 0 ]; then
      reason="${reason} 외 ${extra}건"
    fi
  else
    status="양호"
    reason="Telnet 관련 포트(23/tcp) 리스닝 및 서비스 활성화(systemd/xinetd/inetd) 흔적이 없습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_53() {
  local code="U-53"
  local item="FTP 서비스 정보 노출 제한"
  local severity="하"
  local status="양호"
  local reason="FTP 접속 배너에 서비스명/버전 등 정보 노출 징후가 없습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local listen_info=""
  if command -v ss >/dev/null 2>&1; then
    listen_info="$(ss -ltnp 2>/dev/null | awk '$4 ~ /:21$/ {print}' | head -n 1)"
  else
    listen_info="$(netstat -ltnp 2>/dev/null | awk '$4 ~ /:21$/ {print}' | head -n 1)"
  fi

  if [ -z "$listen_info" ]; then
    status="N/A"
    reason="FTP 서비스(21/tcp)가 리스닝 상태가 아니므로 점검 대상이 아닙니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  local daemon=""
  if echo "$listen_info" | grep -qi "vsftpd"; then
    daemon="vsftpd"
  elif echo "$listen_info" | grep -Eqi "proftpd|proftp"; then
    daemon="proftpd"
  else
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet vsftpd 2>/dev/null; then
      daemon="vsftpd"
    elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet proftpd 2>/dev/null; then
      daemon="proftpd"
    fi
  fi

  local config_leak=0

  if [ "$daemon" = "vsftpd" ]; then
    local f vline
    for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
      if [ -f "$f" ]; then
        vline="$(grep -E '^[[:space:]]*ftpd_banner[[:space:]]*=' "$f" 2>/dev/null | tail -n 1)"
        if [ -n "$vline" ]; then
          echo "$vline" | grep -Eqi '(vsftpd|ftp server|version|[0-9]+\.[0-9]+(\.[0-9]+)?)' && config_leak=1
        fi
      fi
    done
  elif [ "$daemon" = "proftpd" ]; then
    local f pline
    for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
      if [ -f "$f" ]; then
        pline="$(grep -E '^[[:space:]]*ServerIdent[[:space:]]+' "$f" 2>/dev/null | tail -n 1)"
        if [ -n "$pline" ]; then
          echo "$pline" | grep -Eqi '(ServerIdent[[:space:]]+on|version|[0-9]+\.[0-9]+(\.[0-9]+)?)' && config_leak=1
        fi
      fi
    done
  fi

  local banner=""
  if command -v timeout >/dev/null 2>&1; then
    if command -v nc >/dev/null 2>&1; then
      banner="$((echo -e "QUIT\r\n"; sleep 0.2) | timeout 3 nc -n 127.0.0.1 21 2>/dev/null | head -n 1 | tr -d '\r')"
    else
      banner="$(timeout 3 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/21 || exit 1
        IFS= read -r line <&3 || true
        echo "$line"
        echo -e "QUIT\r\n" >&3
        exec 3<&-; exec 3>&-
      ' 2>/dev/null | head -n 1 | tr -d '\r')"
    fi
  fi

  local banner_leak=0
  if [ -n "$banner" ]; then
    echo "$banner" | grep -Eqi \
      '(vsftpd|proftpd|pure-?ftpd|wu-?ftpd|ftp server|version|[0-9]+\.[0-9]+(\.[0-9]+)?)' \
      && banner_leak=1
  fi

  if [ "$config_leak" -eq 1 ] || [ "$banner_leak" -eq 1 ]; then
    status="취약"
    if [ "$banner_leak" -eq 1 ]; then
      reason="FTP 배너에서 서비스명/버전 등 정보 노출 징후가 확인됩니다(예: ${banner})."
    else
      reason="FTP 설정에서 배너에 서비스명/버전 등 정보 노출 가능성이 있습니다."
    fi
  else
    status="양호"
    reason="FTP 서비스는 리스닝 중이며 배너/설정에서 서비스명·버전 노출 징후가 확인되지 않습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_54() {
  local code="U-54"
  local item="암호화되지 않는 FTP 서비스 비활성화"
  local severity="중"
  local status="양호"
  local reason="암호화되지 않은 FTP 서비스 활성화 징후가 없습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local ftp_active=0
  local reasons=()

  local svc
  for svc in vsftpd proftpd; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      ftp_active=1
      reasons+=("${svc} 활성")
    fi
  done

  if [ -d /etc/xinetd.d ]; then
    if grep -rEi "disable[[:space:]]*=[[:space:]]*no" /etc/xinetd.d/ 2>/dev/null | grep -qi "ftp"; then
      ftp_active=1
      reasons+=("xinetd 내 ftp 활성 설정 발견")
    fi
  fi

  if [ "$ftp_active" -eq 1 ]; then
    status="취약"
    reason="${reasons[0]}"
    local extra=$(( ${#reasons[@]} - 1 ))
    if [ "$extra" -gt 0 ]; then
      reason="${reason} 외 ${extra}건"
    fi
  else
    status="양호"
    reason="vsftpd/proftpd 활성 상태가 아니며, xinetd에서도 ftp 활성 설정이 확인되지 않습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_55() {
  local code="U-55"
  local item="FTP 계정 Shell 제한"
  local severity="중"
  local status="양호"
  local reason="FTP 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되어 있습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local ftp_installed=1
  local ftp_users=("ftp" "vsftpd" "proftpd")
  local ftp_exist=0
  local ftp_vuln=0
  local offenders=()

  if ! rpm -qa 2>/dev/null | egrep -qi 'vsftpd|proftpd'; then
    ftp_installed=0
  fi

  if [ "$ftp_installed" -eq 0 ]; then
    status="양호"
    reason="FTP 서비스가 미설치되어 있습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  local user shell
  for user in "${ftp_users[@]}"; do
    if id "$user" >/dev/null 2>&1; then
      ftp_exist=1
      shell="$(grep "^${user}:" /etc/passwd 2>/dev/null | awk -F: '{print $7}' | tail -n 1)"
      if [ "$shell" != "/bin/false" ] && [ "$shell" != "/sbin/nologin" ]; then
        ftp_vuln=1
        offenders+=("${user}(shell=${shell:-미확인})")
      fi
    fi
  done

  if [ "$ftp_exist" -eq 0 ]; then
    status="양호"
    reason="FTP 계정이 존재하지 않습니다."
  elif [ "$ftp_vuln" -eq 1 ]; then
    status="취약"
    reason="FTP 계정에 제한 쉘(/bin/false 또는 /sbin/nologin)이 부여되어 있지 않습니다: ${offenders[0]}"
    local extra=$(( ${#offenders[@]} - 1 ))
    if [ "$extra" -gt 0 ]; then
      reason="${reason} 외 ${extra}건"
    fi
  else
    status="양호"
    reason="FTP 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되어 있습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_56() {
  local code="U-56"
  local item="FTP 서비스 접근 제어 설정"
  local severity="하"
  local status="양호"
  local reason="FTP 접근 제어 설정(파일/설정) 미흡 징후가 없습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local VULN=0
  local REASON=""
  local CONF USERLIST_ENABLE U_F_U LIMIT

  if ps -ef 2>/dev/null | grep -v grep | grep -q "vsftpd"; then
    CONF="/etc/vsftpd/vsftpd.conf"
    [ -f "$CONF" ] || CONF="/etc/vsftpd.conf"

    if [ -f "$CONF" ]; then
      USERLIST_ENABLE="$(grep -vE "^\s*#" "$CONF" 2>/dev/null \
        | grep -i "userlist_enable" | awk -F= '{print $2}' | tr -d ' ' | tail -n 1)"

      if [ "$USERLIST_ENABLE" = "YES" ]; then
        if [ ! -f "/etc/vsftpd/user_list" ] && [ ! -f "/etc/vsftpd.user_list" ]; then
          VULN=1
          REASON="vsftpd(userlist_enable=YES)를 사용 중이나, 접근 제어 파일이 없습니다."
        fi
      else
        if [ ! -f "/etc/vsftpd/ftpusers" ] && [ ! -f "/etc/vsftpd.ftpusers" ]; then
          VULN=1
          REASON="vsftpd(userlist_enable=NO)를 사용 중이나, 접근 제어 파일이 없습니다."
        fi
      fi
    else
      VULN=1
      REASON="vsftpd 서비스가 실행중이나 설정파일을 찾을 수 없습니다."
    fi

  elif ps -ef 2>/dev/null | grep -v grep | grep -q "proftpd"; then
    CONF="/etc/proftpd.conf"
    [ -f "$CONF" ] || CONF="/etc/proftpd/proftpd.conf"

    if [ -f "$CONF" ]; then
      U_F_U="$(grep -vE "^\s*#" "$CONF" 2>/dev/null | grep -i "UseFtpUsers" | awk '{print $2}' | tail -n 1)"
      if [ -z "$U_F_U" ] || [ "$U_F_U" = "on" ]; then
        if [ ! -f "/etc/ftpusers" ] && [ ! -f "/etc/ftpd/ftpusers" ]; then
          VULN=1
          REASON="proftpd(UseFtpUsers=on)를 사용 중이나, 접근 제어 파일이 없습니다."
        fi
      else
        LIMIT="$(grep -i "<Limit LOGIN>" "$CONF" 2>/dev/null | tail -n 1)"
        if [ -z "$LIMIT" ]; then
          VULN=1
          REASON="proftpd(UseFtpUsers=off)를 사용 중이나, 설정 파일 내 접근 제어 설정이 없습니다."
        fi
      fi
    else
      VULN=1
      REASON="proftpd 서비스가 실행중이나 설정파일을 찾을 수 없습니다."
    fi
  else
    VULN=0
    REASON="FTP(vsftpd/proftpd) 서비스 실행 흔적이 없어 점검 대상이 아닙니다."
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  else
    status="양호"
    reason="$REASON"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_57() {
  local code="U-57"
  local item="Ftpusers 파일 설정"
  local severity="중"
  local status="양호"
  local reason="FTP 서비스가 미사용이거나, root 접속 차단(ftpusers/user_list) 설정이 적절합니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln=0
  local why=""
  local ftp_running=0
  local svc
  for svc in vsftpd.service proftpd.service pure-ftpd.service; do
    if systemctl is-active "$svc" &>/dev/null; then
      ftp_running=1
      break
    fi
  done

  if [ "$ftp_running" -eq 0 ]; then
    status="양호"
    reason="FTP 서비스가 동작 중이 아니므로 점검 대상 위험이 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  local candidates=("/etc/vsftpd/ftpusers" "/etc/ftpusers" "/etc/vsftpd/user_list")
  local file_found=""
  local f
  for f in "${candidates[@]}"; do
    if [ -r "$f" ]; then
      file_found="$f"
      break
    fi
  done

  if [ -z "$file_found" ]; then
    vuln=1
    why="ftpusers/user_list 후보 파일을 찾지 못했습니다."
  else
    local has_root=0
    grep -Eq '^[[:space:]]*root([[:space:]]|$)' "$file_found" && has_root=1

    local owner perm
    owner="$(stat -Lc '%U' "$file_found" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$file_found" 2>/dev/null)"

    if [ "$owner" != "root" ]; then
      vuln=1
      why="$file_found 소유자가 root가 아닙니다. (owner=${owner:-확인불가})"
    fi

    if [ "$vuln" -eq 0 ]; then
      if [ -n "$perm" ]; then
        local oct="0$perm"
        if (( (oct & 18) != 0 )); then
          vuln=1
          why="$file_found 그룹/기타 쓰기 권한이 존재합니다. (perm=$perm)"
        fi
      else
        vuln=1
        why="$file_found 권한을 확인하지 못했습니다."
      fi
    fi

    if [ "$vuln" -eq 0 ] && [ "$has_root" -eq 0 ]; then
      vuln=1
      why="$file_found 차단 목록에 root가 포함되어 있지 않습니다."
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="$why"
  else
    status="양호"
    reason="FTP 서비스 동작 중이며 $file_found 에 root 차단이 설정되어 있고, 소유자/권한이 적절합니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_58() {
  local code="U-58"
  local item="불필요한 SNMP 서비스 구동 점검"
  local severity="중"
  local status="양호"
  local reason="SNMP 서비스를 사용하지 않는 것으로 확인되었습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local found=0
  local why=""

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet snmpd 2>/dev/null; then
      found=1
      why="snmpd 서비스가 활성(Active) 상태입니다."
    elif systemctl is-active --quiet snmptrapd 2>/dev/null; then
      found=1
      why="snmptrapd 서비스가 활성(Active) 상태입니다."
    fi
  fi

  if [ "$found" -eq 0 ] && command -v pgrep >/dev/null 2>&1; then
    if pgrep -x snmpd >/dev/null 2>&1; then
      found=1
      why="snmpd 프로세스가 실행 중입니다."
    elif pgrep -x snmptrapd >/dev/null 2>&1; then
      found=1
      why="snmptrapd 프로세스가 실행 중입니다."
    fi
  fi

  if [ "$found" -eq 0 ]; then
    if command -v ss >/dev/null 2>&1; then
      if ss -lunp 2>/dev/null | awk '$5 ~ /:(161|162)$/ {print}' | head -n 1 | grep -q .; then
        found=1
        why="SNMP 포트(161/162 UDP)가 리스닝 상태입니다."
      fi
    elif command -v netstat >/dev/null 2>&1; then
      if netstat -lunp 2>/dev/null | awk '$4 ~ /:(161|162)$/ {print}' | head -n 1 | grep -q .; then
        found=1
        why="SNMP 포트(161/162 UDP)가 리스닝 상태입니다."
      fi
    fi
  fi

  if [ "$found" -eq 1 ]; then
    status="취약"
    reason="SNMP 서비스를 사용하고 있습니다. ${why}"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_59() {
  local code="U-59"
  local item="안전한 SNMP 버전 사용"
  local severity="상"
  local status="양호"
  local reason="SNMP 서비스를 v3 이상으로 사용하는 것으로 확인되었습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local snmpd_conf="/etc/snmp/snmpd.conf"
  local snmpd_persist="/var/lib/net-snmp/snmpd.conf"

  local snmp_active=0
  local cfg_files=()
  local cfg_exists_count=0

  local found_v1v2=0
  local found_v3_user=0
  local found_createuser=0
  local found_sha=0
  local found_aes=0

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet snmpd 2>/dev/null; then
      snmp_active=1
    fi
  fi

  if [ "$snmp_active" -eq 0 ]; then
    status="양호"
    reason="SNMP 서비스(snmpd)가 비활성 상태이므로 보안 가이드라인을 준수하고 있습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  if [ -f "$snmpd_conf" ]; then
    cfg_files+=("$snmpd_conf")
    ((cfg_exists_count++))
  fi
  if [ -f "$snmpd_persist" ]; then
    cfg_files+=("$snmpd_persist")
    ((cfg_exists_count++))
  fi

  if [ "$cfg_exists_count" -eq 0 ]; then
    status="취약"
    reason="snmpd는 활성 상태이나 설정 파일이 없습니다. (${snmpd_conf} / ${snmpd_persist} 미존재)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  _scan_snmp_cfg() {
    local f="$1"
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null
  }

  local f
  for f in "${cfg_files[@]}"; do
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*(rocommunity|rwcommunity|community|com2sec)[[:space:]]+'; then
      found_v1v2=1
    fi
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*(rouser|rwuser)[[:space:]]+'; then
      found_v3_user=1
    fi
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*createUser[[:space:]]+'; then
      found_createuser=1
    fi
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*createUser[[:space:]].*(SHA|SHA1|SHA224|SHA256|SHA384|SHA512)'; then
      found_sha=1
    fi
    if _scan_snmp_cfg "$f" | grep -Eiq '^[[:space:]]*createUser[[:space:]].*(AES|AES128|AES192|AES256)'; then
      found_aes=1
    fi
  done

  if [ "$found_v1v2" -eq 1 ]; then
    status="취약"
    reason="SNMP v1/v2c(community 기반) 설정이 존재합니다. (rocommunity/rwcommunity/com2sec 등)"
  elif [ "$found_v3_user" -eq 1 ] && [ "$found_createuser" -eq 1 ] && [ "$found_sha" -eq 1 ] && [ "$found_aes" -eq 1 ]; then
    status="양호"
    reason="SNMPv3 사용자(rouser/rwuser) 및 createUser(SHA+AES) 설정이 확인되었습니다."
  else
    status="취약"
    reason="snmpd는 활성 상태이나 SNMPv3 필수 설정이 미흡합니다. (createUser(SHA+AES) 또는 rouser/rwuser 미확인)"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_60() {
  local code="U-60"
  local item="SNMP Community String 복잡성 설정"
  local severity="중"
  local status="양호"
  local reason="SNMP Community String이 복잡성 기준을 만족합니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local vuln_flag=0
  local community_found=0

  local ps_snmp_count
  ps_snmp_count="$(ps -ef 2>/dev/null | grep -iE 'snmpd|snmptrapd' | grep -v 'grep' | wc -l)"
  if [ "$ps_snmp_count" -eq 0 ]; then
    status="양호"
    reason="SNMP 서비스가 미설치/미사용 상태입니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  local snmpdconf_files=()
  [ -f /etc/snmp/snmpd.conf ] && snmpdconf_files+=("/etc/snmp/snmpd.conf")
  [ -f /usr/local/etc/snmp/snmpd.conf ] && snmpdconf_files+=("/usr/local/etc/snmp/snmpd.conf")
  while IFS= read -r f; do
    snmpdconf_files+=("$f")
  done < <(find /etc -maxdepth 4 -type f -name 'snmpd.conf' 2>/dev/null | sort -u)

  if [ "${#snmpdconf_files[@]}" -gt 0 ]; then
    mapfile -t snmpdconf_files < <(printf "%s\n" "${snmpdconf_files[@]}" | awk '!seen[$0]++')
  fi

  if [ "${#snmpdconf_files[@]}" -eq 0 ]; then
    status="취약"
    reason="SNMP 서비스를 사용하고 있으나 Community String 설정 파일(snmpd.conf)을 찾지 못했습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  is_strong_community() {
    local s="$1"
    s="${s%\"}"; s="${s#\"}"
    s="${s%\'}"; s="${s#\'}"

    echo "$s" | grep -qiE '^(public|private)$' && return 1

    local len=${#s}
    local has_alpha=0 has_digit=0 has_special=0
    echo "$s" | grep -qE '[A-Za-z]' && has_alpha=1
    echo "$s" | grep -qE '[0-9]' && has_digit=1
    echo "$s" | grep -qE '[^A-Za-z0-9]' && has_special=1

    if [ $has_alpha -eq 1 ] && [ $has_digit -eq 1 ] && [ $len -ge 10 ]; then
      return 0
    fi
    if [ $has_alpha -eq 1 ] && [ $has_digit -eq 1 ] && [ $has_special -eq 1 ] && [ $len -ge 8 ]; then
      return 0
    fi
    return 1
  }

  local evidence_file="" evidence_comm="" evidence_kind=""

  local i
  for ((i=0; i<${#snmpdconf_files[@]}; i++)); do
    local cf="${snmpdconf_files[$i]}"

    while IFS= read -r comm; do
      community_found=1
      if ! is_strong_community "$comm"; then
        vuln_flag=1
        [ -z "$evidence_file" ] && evidence_file="$cf" && evidence_comm="$comm" && evidence_kind="rocommunity/rwcommunity"
        break
      fi
    done < <(grep -vE '^\s*#|^\s*$' "$cf" 2>/dev/null \
      | awk 'tolower($1) ~ /^(rocommunity6?|rwcommunity6?)$/ {print $2}')

    while IFS= read -r comm; do
      community_found=1
      if ! is_strong_community "$comm"; then
        vuln_flag=1
        [ -z "$evidence_file" ] && evidence_file="$cf" && evidence_comm="$comm" && evidence_kind="com2sec"
        break
      fi
    done < <(grep -vE '^\s*#|^\s*$' "$cf" 2>/dev/null \
      | awk 'tolower($1)=="com2sec" {print $4}')

    [ "$vuln_flag" -eq 1 ] && break
  done

  if [ "$community_found" -eq 0 ]; then
    status="취약"
    reason="SNMP 서비스를 사용하나 Community String 설정(rocommunity/rwcommunity/com2sec)을 확인할 수 없습니다."
  elif [ "$vuln_flag" -eq 1 ]; then
    status="취약"
    if [ -n "$evidence_file" ]; then
      reason="SNMP Community String이 public/private 이거나 복잡성 기준을 만족하지 않습니다. (file=${evidence_file}, type=${evidence_kind})"
    else
      reason="SNMP Community String이 public/private 이거나 복잡성 기준을 만족하지 않습니다."
    fi
  else
    status="양호"
    reason="SNMP Community String이 복잡성 기준을 만족합니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_61() {
  local code="U-61"
  local item="SNMP Access Control 설정"
  local severity="상"
  local status="양호"
  local reason="SNMP 서비스에 접근 제어 설정이 확인되었습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local VULN=0
  local REASON=""

  if ps -ef 2>/dev/null | grep -v grep | grep -q "snmpd"; then
    local CONF="/etc/snmp/snmpd.conf"

    if [ -f "$CONF" ]; then
      local CHECK_COM2SEC CHECK_COMM
      CHECK_COM2SEC="$(grep -vE '^\s*#' "$CONF" 2>/dev/null | grep -E '^\s*com2sec' | awk '$3=="default" {print $0}')"
      CHECK_COMM="$(grep -vE '^\s*#' "$CONF" 2>/dev/null | grep -Ei '^\s*(ro|rw)community6?|^\s*(ro|rw)user')"

      local IS_COMM_VULN=0
      local bad_line=""

      if [ -n "$CHECK_COMM" ]; then
        while IFS= read -r line; do
          local COMM_STR SOURCE_IP
          COMM_STR="$(echo "$line" | awk '{print $2}')"
          SOURCE_IP="$(echo "$line" | awk '{print $3}')"

          if [[ "$SOURCE_IP" == "default" ]] || echo "$COMM_STR" | grep -Eqi 'public|private'; then
            IS_COMM_VULN=1
            bad_line="$line"
            break
          fi
        done <<< "$CHECK_COMM"
      fi

      if [ -n "$CHECK_COM2SEC" ] || [ "$IS_COMM_VULN" -eq 1 ]; then
        VULN=1
        REASON="SNMP 설정 파일($CONF)에 모든 호스트 접근을 허용하는 설정이 존재합니다."
      fi

      if [ "$VULN" -eq 1 ] && [ -n "$bad_line" ]; then
        REASON="$REASON (예: $(echo "$bad_line" | tr '\r' ' '))"
      fi
    else
      VULN=1
      REASON="SNMP 서비스가 실행 중이나 설정 파일($CONF)을 찾을 수 없습니다."
    fi
  else
    status="양호"
    reason="SNMP 서비스(snmpd)가 비활성/미사용 상태입니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  else
    status="양호"
    reason="SNMP 서비스에 모든 호스트 허용(default) 등 취약 설정이 확인되지 않았습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_62() {
  local code="U-62"
  local item="로그인 시 경고 메시지 설정"
  local severity="하"
  local status="양호"
  local reason="로그인 배너(/etc/issue, /etc/issue.net, SSH Banner)에서 경고 메시지가 확인되었습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local ok=0
  local issue_files=("/etc/issue" "/etc/issue.net")
  local f content

  for f in "${issue_files[@]}"; do
    [[ -r "$f" ]] || continue
    content="$(grep -vE '^[[:space:]]*$' "$f" 2>/dev/null | head -n 20)"
    if [[ -n "$content" ]]; then
      if echo "$content" | grep -Eqi '(unauthorized|authorized|warning|disclaimer|무단|불법|경고|접근금지)'; then
        ok=1
        break
      fi
    fi
  done

  if (( ok == 0 )) && [[ -r /etc/ssh/sshd_config ]]; then
    local banner bcontent
    banner="$(grep -E '^[[:space:]]*Banner[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -n 1)"
    if [[ -n "$banner" && "$banner" != "none" && -r "$banner" ]]; then
      bcontent="$(grep -vE '^[[:space:]]*$' "$banner" 2>/dev/null | head -n 20)"
      if [[ -n "$bcontent" ]] && echo "$bcontent" | grep -Eqi '(unauthorized|authorized|warning|disclaimer|무단|불법|경고|접근금지)'; then
        ok=1
      fi
    fi
  fi

  if (( ok == 1 )); then
    status="양호"
    reason="로그인 배너에서 경고 메시지 키워드가 확인되었습니다."
  else
    status="취약"
    reason="로그인 배너(/etc/issue, /etc/issue.net, SSH Banner)에서 경고 메시지 키워드를 확인하지 못했습니다."
    reason="$(echo "$reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_63() {
  local code="U-63"
  local item="sudo 명령어 접근 관리"
  local severity="중"
  local status="양호"
  local reason="/etc/sudoers 파일 소유자가 root이고 권한이 640으로 확인되었습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  if [ ! -e /etc/sudoers ]; then
    status="N/A"
    reason="/etc/sudoers 파일이 존재하지 않아 점검 대상이 아닙니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  local owner perm
  owner="$(stat -c %U /etc/sudoers 2>/dev/null)"
  perm="$(stat -c %a /etc/sudoers 2>/dev/null)"

  if [ -z "$owner" ] || [ -z "$perm" ]; then
    status="점검불가"
    reason="/etc/sudoers 권한 정보를 숫자(예: 640)로 확인할 수 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$(json_escape "$code")" \
      "$(json_escape "$item")" \
      "$(json_escape "$severity")" \
      "$(json_escape "$status")" \
      "$(json_escape "$reason")"
    return 0
  fi

  if [ "$owner" = "root" ] && [ "$perm" = "640" ]; then
    status="양호"
    reason="/etc/sudoers 파일 소유자가 root이고 권한이 640입니다."
  else
    status="취약"
    reason="/etc/sudoers 소유자 또는 권한 설정이 기준에 부합하지 않습니다. 현재 소유자: $owner, 권한: $perm"
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_64() {
  local code="U-64"
  local item="주기적 보안 패치 및 벤더 권고사항 적용"
  local severity="상"
  local status="양호"
  local reason="미적용 보안 업데이트가 없고, 최신 커널로 부팅 중입니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local running_kernel latest_kernel pending_updates
  running_kernel="$(uname -r 2>/dev/null)"
  latest_kernel=""
  pending_updates=""

  if command -v dnf >/dev/null 2>&1; then
    pending_updates="$(dnf check-update --security -C -q 2>/dev/null | grep -i "\.security" || true)"
  elif command -v yum >/dev/null 2>&1; then
    pending_updates="$(yum check-update --security -C -q 2>/dev/null | grep -i "\.security" || true)"
  fi

  if command -v rpm >/dev/null 2>&1; then
    latest_kernel="$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -n 1)"
  fi

  if [ -n "$pending_updates" ]; then
    status="취약"
    reason="미적용된 보안 업데이트가 존재합니다."
  elif [ -z "$latest_kernel" ] || [ -z "$running_kernel" ]; then
    status="점검불가"
    reason="커널 정보(running/latest)를 확인할 수 없습니다."
  elif [[ "$latest_kernel" != "$running_kernel" ]]; then
    status="취약"
    reason="최신 커널($latest_kernel) 설치 후 재부팅이 되지 않았습니다. (현재: $running_kernel)"
  else
    status="양호"
    reason="미적용 보안 업데이트가 없고, 최신 커널로 부팅 중입니다. "
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_65() {
  local code="U-65"
  local item="NTP 및 시각 동기화 설정"
  local severity="중"
  local status="취약"
  local reason=""

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local service_active=0
  if systemctl is-active --quiet chronyd 2>/dev/null || systemctl is-active --quiet ntpd 2>/dev/null; then
    service_active=1
  fi

  local server_configured=0
  local conf_files=("/etc/chrony.conf" "/etc/ntp.conf")
  for f in "${conf_files[@]}"; do
    if [ -f "$f" ]; then
      if grep -vE '^\s*#' "$f" | grep -qiE '^\s*(server|pool)\s+'; then
        server_configured=1
        break
      fi
    fi
  done

  if [ "$service_active" -eq 1 ] && [ "$server_configured" -eq 1 ]; then
    status="양호"
    reason="NTP 서비스가 활성화되어 있으며, 가이드라인에 따른 서버 설정이 존재합니다."
  elif [ "$service_active" -eq 0 ]; then
    status="취약"
    reason="NTP 서비스가 구동 중이지 않습니다."
  else
    status="취약"
    reason="NTP 서비스는 구동 중이나 설정 파일 내에 서버(server) 주소가 없습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(json_escape "$reason")"
}

U_66() {
  local code="U-66"
  local item="정책에 따른 시스템 로깅 설정"
  local severity="중"
  local status="양호"
  local reason="rsyslogd 데몬이 실행 중이며, 주요 로그 항목 설정이 확인되었습니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local VULN=0
  local REASON=""
  local CONF="/etc/rsyslog.conf"
  local CONF_FILES=("$CONF")

  if [ -d "/etc/rsyslog.d" ]; then
    while IFS= read -r f; do
      CONF_FILES+=("$f")
    done < <(find /etc/rsyslog.d -maxdepth 1 -type f -name '*.conf' 2>/dev/null | sort)
  fi

  if ps -ef | grep -v grep | grep -qiE "rsyslog|syslog"; then
    if [ -f "$CONF" ]; then
      local ALL_CONTENT
      ALL_CONTENT="$(cat "${CONF_FILES[@]}" 2>/dev/null | grep -vE '^[[:space:]]*#')"

      local MISSING_LOGS=""
      
      echo "$ALL_CONTENT" | grep -qiE '\.info.*messages' || MISSING_LOGS="$MISSING_LOGS [messages]"
      echo "$ALL_CONTENT" | grep -qiE 'authpriv.*secure' || MISSING_LOGS="$MISSING_LOGS [secure]"
      echo "$ALL_CONTENT" | grep -qiE 'mail.*maillog'    || MISSING_LOGS="$MISSING_LOGS [maillog]"
      echo "$ALL_CONTENT" | grep -qiE 'cron.*cron'       || MISSING_LOGS="$MISSING_LOGS [cron]"
      echo "$ALL_CONTENT" | grep -qiE '\.emerg'          || MISSING_LOGS="$MISSING_LOGS [emerg]"

      if [ -n "$MISSING_LOGS" ]; then
        VULN=1
        REASON="주요 로그 설정 미비:$MISSING_LOGS"
      fi
    else
      VULN=1
      REASON="rsyslog 설정 파일 없음"
    fi
  else
    VULN=1
    REASON="시스템 로그 데몬 미실행"
  fi

  [ "$VULN" -eq 1 ] && { status="취약"; reason="$REASON"; }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" "$(json_escape "$item")" "$(json_escape "$severity")" \
    "$(json_escape "$status")" "$(json_escape "$reason")"
}

U_67() {
  local code="U-67"
  local item="로그 디렉터리 소유자 및 권한 설정"
  local severity="중"
  local status="양호"
  local reason="로그 디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하입니다."

  json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
  }

  local LOG_DIR="/var/log"
  local MAX_MODE="644"

  if [[ $(id -u) -ne 0 ]]; then
    status="N/A"
    reason="root 권한 필요"
  elif [[ ! -d "$LOG_DIR" ]]; then
    status="N/A"
    reason="$LOG_DIR 디렉터리 미존재"
  else
    local total=0 vuln=0
    local first_bad=""
    local err_cnt=0

    while IFS= read -r -d '' f; do
      ((total++))

      local owner mode
      owner="$(stat -c '%U' "$f" 2>/dev/null)"
      mode="$(stat -c '%a' "$f" 2>/dev/null)"

      if [[ -z "$owner" || -z "$mode" ]]; then
        ((err_cnt++))
        continue
      fi

      local is_bad=0
      local bad_reason=""

      if [[ "$owner" != "root" ]]; then
        is_bad=1
        bad_reason+="소유자=$owner "
      fi

      if [[ "$mode" =~ ^[0-7]+$ ]]; then
        if (( 8#$mode > 8#$MAX_MODE )); then
          is_bad=1
          bad_reason+="권한=$mode "
        fi
      else
        is_bad=1
        bad_reason+="권한파싱오류 "
      fi

      if [[ $is_bad -eq 1 ]]; then
        ((vuln++))
        if [[ -z "$first_bad" ]]; then
          first_bad="파일=$f | ${bad_reason%% }"
        fi
      fi
    done < <(find "$LOG_DIR" -maxdepth 2 -xdev -type f -print0 2>/dev/null)

    if (( total == 0 )); then
      status="N/A"
      reason="점검 대상 파일 없음"
    elif (( vuln == 0 )) && (( err_cnt == 0 )); then
      status="양호"
      reason="로그 디렉터리 내 로그 파일의 소유자가 root이고, 권한이 644 이하입니다."
    else
      status="취약"
      if [[ -n "$first_bad" ]]; then
        reason="$first_bad"
      else
        reason="기준 위반 파일이 존재합니다."
      fi
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(json_escape "$code")" \
    "$(json_escape "$item")" \
    "$(json_escape "$severity")" \
    "$(json_escape "$status")" \
    "$(json_escape "$reason")"
}

U_01
U_02
U_03
U_04
U_05
U_06
U_07
U_08
U_09
U_10
U_11
U_12
U_13
U_14
U_15
U_16
U_17
U_18
U_19
U_20
U_21
U_22
U_23
U_24
U_25
U_26
U_27
U_28
U_29
U_30
U_31
U_32
U_33
U_34
U_35
U_36
U_37
U_38
U_39
U_40
U_41
U_42
U_43
U_44
U_45
U_46
U_47
U_48
U_49
U_50
U_51
U_52
U_53
U_54
U_55
U_56
U_57
U_58
U_59
U_60
U_61
U_62
U_63
U_64
U_65
U_66
U_67
