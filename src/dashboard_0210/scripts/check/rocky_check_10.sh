#!/bin/bash

U_01() {
  local code="U-01"
  local item="root 계정 원격접속 제한"
  local severity="상"
  local status="양호"
  local reason="원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속이 차단되어 있습니다."

  local VULN=0
  local REASON=""

  _json_escape() {
    # stdin -> escaped string
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local BAD_SERVICES=("telnet.socket" "rsh.socket" "rlogin.socket" "rexec.socket")

  local svc
  for svc in "${BAD_SERVICES[@]}"; do
    if systemctl is-active "$svc" &>/dev/null; then
      if [[ "$svc" == *"telnet"* ]]; then
        break
      else
        VULN=1
        REASON="$svc 서비스가 실행 중입니다."
        break
      fi
    fi
  done

  if [ "$VULN" -eq 0 ]; then
    if ps -ef | grep -i 'telnet' | grep -v 'grep' &>/dev/null || \
       netstat -nat 2>/dev/null | grep -w 'tcp' | grep -i 'LISTEN' | grep ':23 ' &>/dev/null || \
       ss -lnt 2>/dev/null | grep -qE '(:23)\s'; then

      if [ -f /etc/pam.d/login ]; then
        if ! grep -vE '^#|^\s#' /etc/pam.d/login | grep -qi 'pam_securetty\.so'; then
          VULN=1
          REASON="Telnet 서비스 사용 중이며, /etc/pam.d/login에 pam_securetty.so 설정이 없습니다."
        fi
      fi

      if [ "$VULN" -eq 0 ]; then
        if [ -f /etc/securetty ]; then
          if grep -vE '^#|^\s#' /etc/securetty | grep -q '^ *pts'; then
            VULN=1
            REASON="Telnet 서비스 사용 중이며, /etc/securetty에 pts 터미널이 허용되어 있습니다."
          fi
        fi
      fi
    fi
  fi

  if [ "$VULN" -eq 0 ]; then
    if systemctl is-active sshd &>/dev/null || systemctl is-active ssh &>/dev/null || ps -ef | grep -v grep | grep -q '[s]shd'; then
      local ROOT_LOGIN=""
      ROOT_LOGIN="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2; exit}')"

      if [ -z "$ROOT_LOGIN" ]; then
        VULN=1
        REASON="SSH 서비스가 동작 중이나 PermitRootLogin 적용값을 확인할 수 없습니다."
      elif [ "$ROOT_LOGIN" != "no" ]; then
        VULN=1
        REASON="SSH root 접속이 허용 중입니다 (PermitRootLogin: $ROOT_LOGIN)."
      fi
    fi
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}


U_02() {
  local code="U-02"
  local item="비밀번호 관리정책 설정"
  local severity="상"
  local status="양호"
  local reason="비밀번호 관리정책이 기준에 맞게 설정되어 있습니다."

  local TARGET_PASS_MAX_DAYS=90
  local TARGET_PASS_MIN_DAYS=1
  local TARGET_MINLEN=8
  local TARGET_CREDIT=-1
  local TARGET_REMEMBER=4

  local vuln=0
  local reasons=()

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local pass_max pass_min
  pass_max="$(awk 'BEGIN{v=""} $1=="PASS_MAX_DAYS"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"
  pass_min="$(awk 'BEGIN{v=""} $1=="PASS_MIN_DAYS"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"

  if [[ -z "$pass_max" || ! "$pass_max" =~ ^[0-9]+$ ]]; then
    vuln=1; reasons+=("/etc/login.defs 에 PASS_MAX_DAYS 설정을 확인할 수 없습니다.")
  elif (( pass_max > TARGET_PASS_MAX_DAYS )); then
    vuln=1; reasons+=("PASS_MAX_DAYS($pass_max) > 기준($TARGET_PASS_MAX_DAYS)")
  fi

  if [[ -z "$pass_min" || ! "$pass_min" =~ ^[0-9]+$ ]]; then
    vuln=1; reasons+=("/etc/login.defs 에 PASS_MIN_DAYS 설정을 확인할 수 없습니다.")
  elif (( pass_min < TARGET_PASS_MIN_DAYS )); then
    vuln=1; reasons+=("PASS_MIN_DAYS($pass_min) < 기준($TARGET_PASS_MIN_DAYS)")
  fi

  local pwq_files=()
  [[ -r /etc/security/pwquality.conf ]] && pwq_files+=("/etc/security/pwquality.conf")
  [[ -d /etc/security/pwquality.conf.d ]] && pwq_files+=(/etc/security/pwquality.conf.d/*.conf)

  local minlen="" minclass="" ucredit="" lcredit="" dcredit="" ocredit=""
  local f line
  for f in "${pwq_files[@]}"; do
    [[ -r "$f" ]] || continue
    while IFS= read -r line; do
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      [[ "$line" =~ ^[[:space:]]*$ ]] && continue
      line="${line%%#*}"
      if [[ "$line" =~ ^[[:space:]]*minlen[[:space:]]*=[[:space:]]*([0-9]+) ]]; then minlen="${BASH_REMATCH[1]}"; fi
      if [[ "$line" =~ ^[[:space:]]*minclass[[:space:]]*=[[:space:]]*([0-9]+) ]]; then minclass="${BASH_REMATCH[1]}"; fi
      if [[ "$line" =~ ^[[:space:]]*ucredit[[:space:]]*=[[:space:]]*([+-]?[0-9]+) ]]; then ucredit="${BASH_REMATCH[1]}"; fi
      if [[ "$line" =~ ^[[:space:]]*lcredit[[:space:]]*=[[:space:]]*([+-]?[0-9]+) ]]; then lcredit="${BASH_REMATCH[1]}"; fi
      if [[ "$line" =~ ^[[:space:]]*dcredit[[:space:]]*=[[:space:]]*([+-]?[0-9]+) ]]; then dcredit="${BASH_REMATCH[1]}"; fi
      if [[ "$line" =~ ^[[:space:]]*ocredit[[:space:]]*=[[:space:]]*([+-]?[0-9]+) ]]; then ocredit="${BASH_REMATCH[1]}"; fi
    done < "$f"
  done

  local pam_pwq_args=""
  local pf
  for pf in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [[ -r "$pf" ]] || continue
    pam_pwq_args="$(grep -E '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "$pf" 2>/dev/null | tail -n 1)"
    [[ -n "$pam_pwq_args" ]] && break
  done

  if [[ -n "$pam_pwq_args" ]]; then
    [[ "$pam_pwq_args" =~ minlen=([0-9]+) ]] && minlen="${BASH_REMATCH[1]}"
    [[ "$pam_pwq_args" =~ minclass=([0-9]+) ]] && minclass="${BASH_REMATCH[1]}"
    [[ "$pam_pwq_args" =~ ucredit=([+-]?[0-9]+) ]] && ucredit="${BASH_REMATCH[1]}"
    [[ "$pam_pwq_args" =~ lcredit=([+-]?[0-9]+) ]] && lcredit="${BASH_REMATCH[1]}"
    [[ "$pam_pwq_args" =~ dcredit=([+-]?[0-9]+) ]] && dcredit="${BASH_REMATCH[1]}"
    [[ "$pam_pwq_args" =~ ocredit=([+-]?[0-9]+) ]] && ocredit="${BASH_REMATCH[1]}"
  fi

  if [[ -z "$minlen" || ! "$minlen" =~ ^[0-9]+$ ]]; then
    vuln=1; reasons+=("비밀번호 최소 길이(minlen) 설정을 확인할 수 없습니다.")
  elif (( minlen < TARGET_MINLEN )); then
    vuln=1; reasons+=("minlen($minlen) < 기준($TARGET_MINLEN)")
  fi

  local complexity_ok=0
  if [[ -n "$minclass" && "$minclass" =~ ^[0-9]+$ && "$minclass" -ge 3 ]]; then
    complexity_ok=1
  fi
  if [[ "$ucredit" =~ ^-?[0-9]+$ && "$lcredit" =~ ^-?[0-9]+$ && "$dcredit" =~ ^-?[0-9]+$ && "$ocredit" =~ ^-?[0-9]+$ ]]; then
    if (( ucredit <= TARGET_CREDIT && lcredit <= TARGET_CREDIT && dcredit <= TARGET_CREDIT && ocredit <= TARGET_CREDIT )); then
      complexity_ok=1
    fi
  fi
  if (( complexity_ok == 0 )); then
    vuln=1; reasons+=("복잡성(minclass 또는 *credit) 기준 충족 여부를 확인하지 못했습니다.")
  fi

  local remember=""
  local pwh_line=""
  for pf in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [[ -r "$pf" ]] || continue
    pwh_line="$(grep -E '^[[:space:]]*password[[:space:]].*(pam_pwhistory\.so|pam_unix\.so)' "$pf" 2>/dev/null | grep -E 'remember=' | tail -n 1)"
    [[ -n "$pwh_line" ]] && break
  done
  if [[ -n "$pwh_line" && "$pwh_line" =~ remember=([0-9]+) ]]; then
    remember="${BASH_REMATCH[1]}"
  fi
  if [[ -z "$remember" && -r /etc/security/pwhistory.conf ]]; then
    remember="$(awk 'BEGIN{v=""} $1=="remember"{gsub(" ","",$3); v=$3} END{print v}' /etc/security/pwhistory.conf 2>/dev/null)"
  fi

  if [[ -z "$remember" || ! "$remember" =~ ^[0-9]+$ ]]; then
    vuln=1; reasons+=("비밀번호 재사용 제한(remember) 설정을 확인할 수 없습니다.")
  elif (( remember < TARGET_REMEMBER )); then
    vuln=1; reasons+=("remember($remember) < 기준($TARGET_REMEMBER)")
  fi

  if (( vuln == 1 )); then
    status="취약"
    if (( ${#reasons[@]} > 0 )); then
      reason="${reasons[0]}"
    else
      reason="비밀번호 관리정책이 기준을 충족하지 않습니다."
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_03() {
  local code="U-03"
  local item="계정 잠금 임계값 설정"
  local severity="상"
  local status="양호"
  local reason="계정 잠금 임계값이 10회 이하로 설정되어 있습니다."

  local pam_files=(
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
  )
  local faillock_conf="/etc/security/faillock.conf"

  local found_any=0
  local found_from=""
  local max_deny=-1
  local file_exists_count=0

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

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

  local f deny
  for f in "${pam_files[@]}"; do
    if [ -f "$f" ]; then
      ((file_exists_count++))
      while IFS= read -r deny; do
        [ -z "$deny" ] && continue
        found_any=1
        found_from+="$f(pam):deny=$deny; "
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
      found_from+="$faillock_conf(conf):deny=$conf_deny; "
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
    reason="deny 설정을 찾지 못했습니다. (PAM 라인 또는 faillock.conf에서 deny 값 미발견)"
  elif [ "$max_deny" -eq 0 ]; then
    status="취약"
    reason="계정 잠금 임계값(deny)이 0으로 설정되어 있습니다. (잠금 미적용 가능)"
  elif [ "$max_deny" -gt 10 ]; then
    status="취약"
    reason="계정 잠금 임계값(deny)이 11회 이상으로 설정되어 있습니다. (max deny=$max_deny)"
  else
    status="양호"
    reason="계정 잠금 임계값(deny)이 10회 이하로 확인되었습니다. (max deny=$max_deny)"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_04() {
  local code="U-04"
  local item="패스워드 파일 보호"
  local severity="상"
  local status="양호"
  local reason="shadow 패스워드를 사용하거나 패스워드를 암호화하여 저장하고 있습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if [ -f /etc/passwd ]; then
    local VULN_COUNT VULN_USERS
    VULN_COUNT="$(awk -F: '$2 != "x" && $2 != "!!" && $2 != "*" {c++} END{print c+0}' /etc/passwd 2>/dev/null)"
    if [ "${VULN_COUNT:-0}" -gt 0 ]; then
      VULN_USERS="$(awk -F: '$2 != "x" && $2 != "!!" && $2 != "*" {print $1}' /etc/passwd 2>/dev/null | paste -sd "," -)"
      status="취약"
      reason="/etc/passwd 파일에 shadow 패스워드를 사용하지 않는 계정이 존재: ${VULN_USERS}"
    else
      if [ -f /etc/shadow ]; then
        status="양호"
        reason="모든 계정이 shadow 패스워드(x) 정책을 사용하며 /etc/shadow 파일이 존재합니다."
      else
        status="취약"
        reason="/etc/shadow 파일이 존재하지 않습니다."
      fi
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_05() {
  local code="U-05"
  local item="root 이외의 UID가 '0' 금지"
  local severity="상"
  local status="양호"
  local reason="root 계정과 동일한 UID(0)를 갖는 계정이 존재하지 않습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if [ -f /etc/passwd ]; then
    local dup_users
    dup_users="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | grep -vx root || true)"

    if [ -n "$dup_users" ]; then
      status="취약"
      reason="root 외 UID 0 계정 발견: $(printf '%s' "$dup_users" | paste -sd "," - 2>/dev/null || printf '%s' "$dup_users")"
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_06() {
  local code="U-06"
  local item="사용자 계정 su 기능 제한"
  local severity="상"
  local status="양호"
  local reason="su 명령어가 특정 그룹(휠 등)에 속한 사용자만 사용하도록 제한되어 있습니다."

  local VULN=0
  local REASON=""
  local PAM_SU="/etc/pam.d/su"

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if [ -f "$PAM_SU" ]; then
    local SU_RESTRICT
    SU_RESTRICT="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$PAM_SU" 2>/dev/null \
      | grep -E 'pam_wheel\.so' \
      | grep -E 'use_uid' || true)"

    if [ -z "$SU_RESTRICT" ]; then
      VULN=1
      REASON="/etc/pam.d/su 파일에 pam_wheel.so(use_uid) 설정이 없거나 주석 처리되어 있습니다."
    fi
  else
    VULN=1
    REASON="$PAM_SU 파일이 존재하지 않습니다."
  fi

  local USER_COUNT
  USER_COUNT="$(awk -F: '$3 >= 1000 && $3 < 60000 {c++} END{print c+0}' /etc/passwd 2>/dev/null)"
  if [ "$VULN" -eq 1 ] && [ "${USER_COUNT:-0}" -eq 0 ]; then
    VULN=0
    REASON="일반 사용자 계정 없이 root 계정만 사용하여 su 명령어 사용 제한이 불필요합니다."
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  else
    status="양호"
    if [ -n "$REASON" ]; then
      reason="$REASON"
    else
      reason="su 명령어가 특정 그룹(휠 등)에 속한 사용자만 사용하도록 제한되어 있습니다."
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_07() {
  local code="U-07"
  local item="불필요한 계정 제거"
  local severity="하"
  local status="양호"
  local reason="로그인 가능한 불필요한 시스템 계정이 발견되지 않았습니다."

  local vuln=0

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local system_users
  system_users="$(awk -F: '
    ($3 < 1000 && $1 != "root" && $1 != "sync" && $1 != "shutdown" && $1 != "halt") &&
    ($7 !~ /nologin|false/) {
      print $1 "(uid=" $3 ",shell=" $7 ")"
    }' /etc/passwd 2>/dev/null)"

  if [[ -n "$system_users" ]]; then
    vuln=1
    status="취약"
    reason="로그인 가능한 시스템 계정 존재: $(printf '%s\n' "$system_users" | paste -sd', ' -)"
  fi

  reason="$(printf '%s' "$reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if [ "${#reason}" -gt 250 ]; then
    reason="${reason:0:250}..."
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_08() {
  local code="U-08"
  local item="관리자 권한(그룹/ sudoers) 최소화"
  local severity="중"
  local status="양호"
  local reason="root 외 관리자 계정이 1명 이하이며, 불필요 계정이 발견되지 않았습니다."

  local ADMIN_GROUP="sudo"
  local -a offenders=()
  local admin_count=0
  local suspicious=""

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  _user_exists() { id "$1" >/dev/null 2>&1; }

  if [ ! -f /etc/group ]; then
    status="N/A"
    reason="/etc/group 파일이 없습니다."
  else
    if getent group "$ADMIN_GROUP" >/dev/null 2>&1; then
      local MEMBERS u
      MEMBERS="$(getent group "$ADMIN_GROUP" | awk -F: '{print $4}')"
      for u in $(printf '%s' "$MEMBERS" | tr ',' ' '); do
        [ -z "$u" ] && continue
        [ "$u" = "root" ] && continue
        _user_exists "$u" || continue
        offenders+=("$u")
      done
    fi

    if [ -f /etc/sudoers ]; then
      local line token
      while IFS= read -r line; do
        token="$(printf '%s' "$line" | awk '{print $1}')"
        [ -z "$token" ] && continue
        if [[ "$token" != "%" && "$token" != "root" ]]; then
          if _user_exists "$token"; then
            offenders+=("$token")
          fi
        fi
      done < <(grep -Ev '^\s*#|^\s*$|Defaults' /etc/sudoers 2>/dev/null)
    fi

    if [ "${#offenders[@]}" -gt 0 ]; then
      mapfile -t offenders < <(printf "%s\n" "${offenders[@]}" | sort -u)
    fi

    admin_count="${#offenders[@]}"
    
    local u
    for u in "${offenders[@]}"; do
      if printf '%s' "$u" | grep -Eiq 'test|temp|guest'; then
        suspicious="$suspicious $u"
      fi
    done
    suspicious="$(printf '%s' "$suspicious" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

    if [ "$admin_count" -eq 0 ]; then
      status="양호"
      reason="root 외 관리자 계정이 존재하지 않습니다."
    elif [ "$admin_count" -eq 1 ] && [ -z "$suspicious" ]; then
      status="양호"
      reason="단일 관리자 계정만 존재합니다: ${offenders[*]}"
    else
      status="취약"
      if [ -n "$suspicious" ]; then
        reason="관리자 계정이 2명 이상이거나 불필요/임시 관리자 계정 존재: $suspicious (전체: ${offenders[*]})"
      else
        reason="관리자 계정이 2명 이상 존재합니다: ${offenders[*]}"
      fi
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_09() {
  local code="U-09"
  local item="계정이 존재하지 않는 GID 금지"
  local severity="하"
  local status="양호"
  local reason="계정이 존재하지 않는 불필요한 그룹(GID 1000 이상)이 발견되지 않았습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if [ ! -f /etc/passwd ] || [ ! -f /etc/group ]; then
    status="취약"
    if [ ! -f /etc/passwd ] && [ ! -f /etc/group ]; then
      reason="/etc/passwd 및 /etc/group 파일이 존재하지 않아 점검할 수 없습니다."
    elif [ ! -f /etc/passwd ]; then
      reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
    else
      reason="/etc/group 파일이 존재하지 않아 점검할 수 없습니다."
    fi
  else
    local USED_GIDS CHECK_GIDS
    USED_GIDS="$(awk -F: '{print $4}' /etc/passwd 2>/dev/null | sort -u)"

    CHECK_GIDS="$(awk -F: '$3 >= 1000 {print $3}' /etc/group 2>/dev/null)"

    local VULN_GROUPS=""
    local gid MEMBER_EXISTS GROUP_NAME
    for gid in $CHECK_GIDS; do
      if ! printf '%s\n' "$USED_GIDS" | grep -qxw "$gid"; then
        MEMBER_EXISTS="$(awk -F: -v g="$gid" '$3==g {print $4}' /etc/group 2>/dev/null | head -n 1)"
        if [ -z "$MEMBER_EXISTS" ]; then
          GROUP_NAME="$(awk -F: -v g="$gid" '$3==g {print $1; exit}' /etc/group 2>/dev/null)"
          [ -z "$GROUP_NAME" ] && GROUP_NAME="(unknown)"
          VULN_GROUPS="$VULN_GROUPS $GROUP_NAME($gid)"
        fi
      fi
    done

    VULN_GROUPS="$(printf '%s' "$VULN_GROUPS" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

    if [ -n "$VULN_GROUPS" ]; then
      status="취약"
      reason="계정이 존재하지 않는 불필요한 그룹(GID 1000 이상) 존재: $VULN_GROUPS"
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_10() {
  local code="U-10"
  local item="동일한 UID 금지"
  local severity="중"
  local status="양호"
  local reason="동일한 UID로 설정된 사용자 계정이 존재하지 않습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if [ -f /etc/passwd ]; then
    local dup_uids dup_uid_count
    dup_uids="$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d)"
    dup_uid_count="$(printf '%s\n' "$dup_uids" | sed '/^$/d' | wc -l | tr -d ' ')"

    if [ "${dup_uid_count:-0}" -gt 0 ]; then
      status="취약"
      reason="동일한 UID로 설정된 사용자 계정이 존재합니다. (중복 UID: $(printf '%s' "$dup_uids" | paste -sd',' -))"
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_11() {
  local code="U-11"
  local item="사용자 shell 점검"
  local severity="하"
  local status="양호"
  local reason="로그인이 불필요한 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local vuln=0
  local vuln_accounts=""

  local except_users_regex='^(sync|shutdown|halt)$'

  if [ ! -f /etc/passwd ]; then
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  else
    while IFS=: read -r user pass uid gid comment home shell; do
      if { [ "$uid" -ge 1 ] && [ "$uid" -lt 1000 ]; } || [ "$user" = "nobody" ]; then
        if [[ "$user" =~ $except_users_regex ]]; then
          continue
        fi

        if [[ "$shell" != "/bin/false" ]] && \
           [[ "$shell" != "/sbin/nologin" ]] && \
           [[ "$shell" != "/usr/sbin/nologin" ]]; then
          if [ -z "$vuln_accounts" ]; then
            vuln_accounts="$user($shell)"
          else
            vuln_accounts="$vuln_accounts, $user($shell)"
          fi
        fi
      fi
    done < /etc/passwd

    if [ -n "$vuln_accounts" ]; then
      vuln=1
      status="취약"
      reason="로그인이 불필요한 계정에 쉘이 부여되어 있습니다: $vuln_accounts"
    else
      status="양호"
      reason="로그인이 불필요한 계정에 /bin/false(/sbin/nologin) 쉘이 부여되어 있습니다."
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_12() {
  local code="U-12"
  local item="세션 종료 시간 설정"
  local severity="하"
  local status="양호"
  local reason="유휴 세션 종료(TMOUT) 값이 설정되어 있고(권고: 600초 이하) 전역에 적용됩니다."

  local TARGET_TMOUT=600
  local vuln=0
  local found=()

  _json_escape() {
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\r/\\r/g' -e 's/\t/\\t/g' | tr -d '\n'
  }

  local files=("/etc/profile" "/etc/bashrc" "/etc/csh.cshrc" "/etc/csh.login")
 
  if [[ -d "/etc/profile.d" ]]; then
    while IFS= read -r -d '' x; do
      files+=("$x")
    done < <(find "/etc/profile.d" -maxdepth 1 -type f -name "*.sh" -print0 2>/dev/null)
  fi

  local f
  for f in "${files[@]}"; do
    [[ -f "$f" && -r "$f" ]] || continue
    
    local tm
    tm="$(grep -E '^[[:space:]]*(readonly[[:space:]]+)?TMOUT[[:space:]]*=' "$f" 2>/dev/null \
      | sed 's/#.*$//' \
      | tail -n 1 \
      | sed -E 's/.*TMOUT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')"
    
    if [[ "$tm" =~ ^[0-9]+$ ]]; then
      found+=("$f:$tm")
    fi
  done

  if (( ${#found[@]} == 0 )); then
    vuln=1
    reason="TMOUT 설정을 전역 설정 파일에서 찾지 못했습니다."
  else
    local ok=0
    local has_zero=0
    local e val
    for e in "${found[@]}"; do
      val="${e##*:}"
      if [[ "$val" =~ ^[0-9]+$ ]] && (( val == 0 )); then
        has_zero=1
      fi
      if [[ "$val" =~ ^[0-9]+$ ]] && (( val > 0 && val <= TARGET_TMOUT )); then
        ok=1
      fi
    done

    if (( has_zero == 1 )); then
      vuln=1
      reason="TMOUT=0 설정이 확인되었습니다(유휴 세션 종료 비활성)."
    elif (( ok == 0 )); then
      vuln=1
      reason="TMOUT 값이 1~${TARGET_TMOUT}초 조건을 충족하지 못했습니다."
    else
      status="양호"
      reason="TMOUT 값이 1~${TARGET_TMOUT}초 범위로 설정되어 있습니다."
    fi
  fi

  if (( vuln == 1 )); then
    status="취약"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_13() {
  local code="U-13"
  local item="안전한 비밀번호 암호화 알고리즘 사용 (Rocky 10.x 기준)"
  local severity="중"
  local status="양호"
  local reason="안전한 해시 알고리즘(yescrypt/SHA-2)만 사용 중입니다."

  local shadow="/etc/shadow"

  _json_escape() {
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\r/\\r/g' -e 's/\t/\\t/g' | tr -d '\n'
  }

  if [ ! -e "$shadow" ]; then
    status="N/A"
    reason="$shadow 파일이 없습니다."
  elif [ ! -r "$shadow" ]; then
    status="N/A"
    reason="$shadow 파일을 읽을 수 없습니다. (권한 부족: root 권한 필요)"
  else
    local vuln_found=0
    local checked=0
    local good_count=0
    local evidence_bad=""
    local evidence_good_sample=""

    local user hash rest

    while IFS=: read -r user hash rest; do
      [ -z "$user" ] && continue

      if [ -z "$hash" ] || [[ "$hash" =~ ^[!*]+$ ]]; then
        continue
      fi

      ((checked++))

      if [[ "$hash" == \$y\$* ]]; then
        ((good_count++))
        if [ "$(echo "$evidence_good_sample" | wc -w)" -lt 10 ]; then
          evidence_good_sample+="$user:yescrypt "
        fi
        continue
      fi

      if [[ "$hash" == \$6\$* ]]; then
        ((good_count++))
        if [ "$(echo "$evidence_good_sample" | wc -w)" -lt 10 ]; then
          evidence_good_sample+="$user:sha512 "
        fi
        continue
      fi

      if [[ "$hash" == \$5\$* ]]; then
        ((good_count++))
        if [ "$(echo "$evidence_good_sample" | wc -w)" -lt 10 ]; then
          evidence_good_sample+="$user:sha256 "
        fi
        continue
      fi

      if [[ "$hash" == \$1\$* ]]; then
        vuln_found=1
        evidence_bad+="$user:MD5(\$1\$) "
        continue
      fi

      if [[ "$hash" == \$* ]]; then
        local id
        id="$(printf '%s' "$hash" | awk -F'$' '{print $2}')"
        [ -z "$id" ] && id="UNKNOWN"
        vuln_found=1
        evidence_bad+="$user:UNKNOWN(\$$id\$) "
        continue
      fi

      vuln_found=1
      evidence_bad+="$user:LEGACY/UNKNOWN_FORMAT "
    done < "$shadow"

    if [ "$checked" -eq 0 ]; then
      status="N/A"
      reason="점검 가능한 패스워드 해시 계정이 없습니다. (모두 잠금/미설정 계정일 수 있음)"
    elif [ "$vuln_found" -eq 1 ]; then
      status="취약"
      reason="안전 기준(yescrypt/SHA-2) 미만 또는 불명확한 해시 알고리즘 계정 존재 (점검=$checked, 양호추정=$good_count, 근거=$evidence_bad)"
    else
      status="양호"
      reason="안전한 해시 알고리즘(yescrypt/SHA-2)만 사용 중입니다. (점검=$checked, 샘플=$evidence_good_sample)"
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_14() {
  local code="U-14"
  local item="root 홈, 패스 디렉터리 권한 및 패스 설정"
  local severity="상"
  local status="양호"
  local reason="PATH 환경변수에 '.' 이 맨 앞이나 중간에 포함되지 않습니다."

  local VULN_FOUND=0
  local DETAILS=""

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if printf '%s' "$PATH" | grep -qE '^\.:|:.:|^:|::|:$'; then
    VULN_FOUND=1
    DETAILS="[Runtime] 현재 PATH 내 '.' 또는 '::' 발견: $PATH"
  fi

  if [ "$VULN_FOUND" -eq 0 ]; then
    local -a path_settings_files=("/etc/profile" "/etc/bashrc" "/etc/environment")
    local file VULN_LINE

    for file in "${path_settings_files[@]}" /etc/profile.d/*.sh; do
      [ -f "$file" ] || continue
      VULN_LINE="$(grep -vE '^#|^[[:space:]]*#' "$file" 2>/dev/null \
        | grep -E 'PATH=' \
        | grep -E '=\.:|=\.|:\.:|::|:$' \
        | head -n 1)"
      if [ -n "$VULN_LINE" ]; then
        VULN_FOUND=1
        DETAILS="[System File] $file: $VULN_LINE"
        break
      fi
    done
  fi

  if [ "$VULN_FOUND" -eq 0 ]; then
    local -a user_dot_files=(".bash_profile" ".bashrc" ".shrc")
    local user_homedirs dir dotfile target VULN_LINE

    user_homedirs="$(awk -F: '$7!="/bin/false" && $7!="/sbin/nologin" {print $6}' /etc/passwd 2>/dev/null | sort -u)"

    for dir in $user_homedirs; do
      for dotfile in "${user_dot_files[@]}"; do
        target="$dir/$dotfile"
        [ -f "$target" ] || continue
        VULN_LINE="$(grep -vE '^#|^[[:space:]]*#' "$target" 2>/dev/null \
          | grep -E 'PATH=' \
          | grep -E '=\.:|=\.|:\.:|::|:$' \
          | head -n 1)"
        if [ -n "$VULN_LINE" ]; then
          VULN_FOUND=1
          DETAILS="[User File] $target: $VULN_LINE"
          break 2
        fi
      done
    done
  fi

  if [ "$VULN_FOUND" -eq 1 ]; then
    status="취약"
    reason="$DETAILS"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_15() {
  local code="U-15"
  local item="파일 및 디렉터리 소유자 설정"
  local severity="상"
  local status="양호"
  local reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local cnt
  cnt="$(find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l | tr -d ' ')"

  if [ "${cnt:-0}" -gt 0 ]; then
    status="취약"
    reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다. (개수=$cnt)"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_16() {
  local code="U-16"
  local item="/etc/passwd 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하입니다."

  local FILE="/etc/passwd"

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if [ -f "$FILE" ]; then
    local OWNER PERMIT
    OWNER="$(stat -c "%U" "$FILE" 2>/dev/null)"
    PERMIT="$(stat -c "%a" "$FILE" 2>/dev/null)"

    if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
      status="취약"
      reason="/etc/passwd 파일의 소유자 또는 권한 정보를 확인할 수 없습니다."
    else
      if [ "$OWNER" != "root" ] || [ "$PERMIT" -gt 644 ]; then
        status="취약"
        reason=""
        if [ "$OWNER" != "root" ]; then
          reason="/etc/passwd 파일의 소유자가 root가 아닙니다 (현재: $OWNER)."
        fi
        if [ "$PERMIT" -gt 644 ]; then
          if [ -n "$reason" ]; then
            reason="$reason / 권한이 644보다 높습니다 (현재: $PERMIT)."
          else
            reason="권한이 644보다 높습니다 (현재: $PERMIT)."
          fi
        fi
      fi
    fi
  else
    status="취약"
    reason="$FILE 파일이 존재하지 않습니다."
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_17() {
  local code="U-17"
  local item="시스템 시작 스크립트 권한 설정"
  local severity="상"
  local status="양호"
  local reason="시스템 시작 스크립트(초기화 스크립트/서비스 유닛)의 소유자 및 권한이 적절합니다."

  local vuln=0
  local offenders=()

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  check_path_perm() {
    local path="$1"
    [[ -e "$path" ]] || return 0

    local owner perm mode oct
    owner="$(stat -Lc '%U' "$path" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$path" 2>/dev/null)"
    mode="$perm"

    if [[ -n "$owner" && "$owner" != "root" ]]; then
      offenders+=("$path (owner=$owner, perm=$perm)")
      return 0
    fi

    [[ "$mode" =~ ^[0-9]+$ ]] || return 0

    oct="0$mode"
    if (( (oct & 18) != 0 )); then
      offenders+=("$path (group/other writable, perm=$perm)")
    fi
  }

  local candidates=(
    "/etc/rc.d/rc.local" "/etc/rc.local"
    "/etc/init.d" "/etc/rc.d/init.d"
    "/etc/systemd/system" "/usr/lib/systemd/system"
  )

  local p f
  for p in "${candidates[@]}"; do
    [[ -e "$p" ]] || continue
    if [[ -d "$p" ]]; then
      while IFS= read -r -d '' f; do
        check_path_perm "$f"
      done < <(find "$p" -maxdepth 2 -type f -print0 2>/dev/null)
    else
      check_path_perm "$p"
    fi
  done

  if (( ${#offenders[@]} > 0 )); then
    vuln=1
    status="취약"
    reason="시스템 시작 스크립트/유닛 파일에서 root 미소유 또는 그룹/기타 쓰기 권한이 있는 항목이 존재합니다. (예: ${offenders[0]})"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_18() {
  local code="U-18"
  local item="/etc/shadow 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/shadow 소유자(root) 및 권한(400)이 기준을 만족합니다."

  local target="/etc/shadow"

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if [ ! -e "$target" ]; then
    status="N/A"
    reason="$target 파일이 없습니다."
  elif [ ! -f "$target" ]; then
    status="N/A"
    reason="$target 가 일반 파일이 아닙니다."
  else
    local owner perm
    owner="$(stat -c '%U' "$target" 2>/dev/null)"
    perm="$(stat -c '%a' "$target" 2>/dev/null)"

    if [ -z "$owner" ] || [ -z "$perm" ]; then
      status="N/A"
      reason="stat 명령으로 $target 정보를 읽지 못했습니다."
    else
      if [ "$owner" != "root" ]; then
        status="취약"
        reason="$target 파일의 소유자가 root가 아닙니다. (owner=$owner)"
      else
        if [[ "$perm" =~ ^[0-7]{4}$ ]]; then
          perm="${perm:1:3}"
        elif [[ "$perm" =~ ^[0-7]{1,3}$ ]]; then
          perm="$(printf "%03d" "$perm")"
        fi

        if ! [[ "$perm" =~ ^[0-7]{3}$ ]]; then
          status="N/A"
          reason="$target 파일 권한 형식이 예상과 다릅니다. (perm=$perm)"
        else
          if [ "$perm" != "400" ]; then
            status="취약"
            reason="$target 파일 권한이 400이 아닙니다. (perm=$perm)"
          else
            status="양호"
            reason="$target 소유자(root) 및 권한(perm=$perm)이 기준(400)을 만족합니다."
          fi
        fi
      fi
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_19() {
  local code="U-19"
  local item="/etc/hosts 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하입니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if [ -f "/etc/hosts" ]; then
    local FILE_OWNER_UID FILE_OWNER_NAME FILE_PERM
    FILE_OWNER_UID="$(stat -c "%u" /etc/hosts 2>/dev/null)"
    FILE_OWNER_NAME="$(stat -c "%U" /etc/hosts 2>/dev/null)"
    FILE_PERM="$(stat -c "%a" /etc/hosts 2>/dev/null)"

    if [ -z "$FILE_OWNER_UID" ] || [ -z "$FILE_PERM" ]; then
      status="취약"
      reason="/etc/hosts 파일의 소유자 또는 권한 정보를 확인할 수 없습니다."
    else
      local USER_PERM GROUP_PERM OTHER_PERM
      USER_PERM="${FILE_PERM:0:1}"
      GROUP_PERM="${FILE_PERM:1:1}"
      OTHER_PERM="${FILE_PERM:2:1}"

      if [ "$FILE_OWNER_UID" -ne 0 ] 2>/dev/null; then
        status="취약"
        reason="소유자(owner)가 root가 아님 (현재: ${FILE_OWNER_NAME:-unknown}, uid=$FILE_OWNER_UID)"
      elif [ "$USER_PERM" -gt 6 ] || [ "$GROUP_PERM" -gt 4 ] || [ "$OTHER_PERM" -gt 4 ]; then
        status="취약"
        reason="권한이 644보다 큼 (현재: $FILE_PERM)"
      else
        status="양호"
        reason="/etc/hosts 파일의 소유자가 root이고, 권한이 644 이하입니다. (perm=$FILE_PERM)"
      fi
    fi
  else
    status="N/A"
    reason="/etc/hosts 파일이 존재하지 않습니다."
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_20() {
  local code="U-20"
  local item="systemd *.socket, *.service 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="systemd socket/service 파일의 소유자가 root이고, 권한이 644 이하입니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local dirs=("/usr/lib/systemd/system" "/etc/systemd/system")
  local found_any=0
  local checked=0
  local offenders=0
  local first_offender=""

  local d file owner perm

  for d in "${dirs[@]}"; do
    [ -d "$d" ] || continue

    if find "$d" -type f \( -name "*.socket" -o -name "*.service" \) -print -quit 2>/dev/null | grep -q .; then
      found_any=1
    else
      continue
    fi

    while IFS= read -r file; do
      [ -z "$file" ] && continue
      checked=$((checked + 1))

      owner="$(stat -c %U "$file" 2>/dev/null)"
      perm="$(stat -c %a "$file" 2>/dev/null)"

      if [ -z "$owner" ] || [ -z "$perm" ]; then
        offenders=$((offenders + 1))
        [ -z "$first_offender" ] && first_offender="$file (stat 확인 실패)"
        continue
      fi

      if [ "$owner" != "root" ]; then
        offenders=$((offenders + 1))
        [ -z "$first_offender" ] && first_offender="$file (owner=$owner, perm=$perm)"
        continue
      fi

      if [ "$perm" -gt 644 ] 2>/dev/null; then
        offenders=$((offenders + 1))
        [ -z "$first_offender" ] && first_offender="$file (perm=$perm)"
        continue
      fi
    done < <(find "$d" -type f \( -name "*.socket" -o -name "*.service" \) 2>/dev/null)
  done

  if [ "$found_any" -eq 0 ]; then
    status="N/A"
    reason="systemd socket/service 파일이 없습니다."
  elif [ "$offenders" -gt 0 ]; then
    status="취약"
    reason="root 미소유 또는 권한 644 초과 항목이 존재합니다. (예: $first_offender, offenders=$offenders, checked=$checked)"
  else
    status="양호"
    reason="점검 대상 파일이 모두 root 소유이고 권한이 644 이하입니다. (checked=$checked)"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}
U_21() {
  local code="U-21"
  local item="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/(r)syslog.conf 파일의 소유자가 root/bin/sys이고, 권한이 640 이하입니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local target=""
  if [ -f "/etc/rsyslog.conf" ]; then
    target="/etc/rsyslog.conf"
  elif [ -f "/etc/syslog.conf" ]; then
    target="/etc/syslog.conf"
  else
    status="N/A"
    reason="/etc/rsyslog.conf 또는 /etc/syslog.conf 파일이 존재하지 않습니다."
  fi

  if [ -n "$target" ]; then
    local OWNER PERMIT
    OWNER="$(stat -c '%U' "$target" 2>/dev/null)"
    PERMIT="$(stat -c '%a' "$target" 2>/dev/null)"

    if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
      status="N/A"
      reason="stat 명령으로 $target 정보를 읽지 못했습니다. (권한 문제 등)"
    else
      if [[ ! "$OWNER" =~ ^(root|bin|sys)$ ]]; then
        status="취약"
        reason="$target 파일의 소유자가 root, bin, sys가 아닙니다. (owner=$OWNER)"
      elif [ "$PERMIT" -gt 640 ] 2>/dev/null; then
        status="취약"
        reason="$target 파일의 권한이 640보다 큽니다. (perm=$PERMIT)"
      else
        status="양호"
        reason="$target 파일의 소유자($OWNER) 및 권한($PERMIT)이 기준에 적합합니다."
      fi
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_22() {
  local code="U-22"
  local item="/etc/services 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/services 파일 소유자가 root이고, 그룹/기타 쓰기 권한이 없습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local f="/etc/services"

  if [[ ! -e "$f" ]]; then
    status="취약"
    reason="/etc/services 파일이 존재하지 않습니다."
  else
    local owner perm oct
    owner="$(stat -Lc '%U' "$f" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$f" 2>/dev/null)"

    if [ -z "$owner" ] || [ -z "$perm" ]; then
      status="취약"
      reason="/etc/services 파일의 소유자 또는 권한 정보를 확인할 수 없습니다."
    elif [[ "$owner" != "root" ]]; then
      status="취약"
      reason="/etc/services 소유자가 root가 아닙니다 (owner=$owner)."
    else
      oct="0$perm"
      if (( (oct & 18) != 0 )); then
        status="취약"
        reason="/etc/services에 그룹/기타 쓰기 권한이 존재합니다 (perm=$perm)."
      else
        status="양호"
        reason="/etc/services 파일 소유자가 root이고, 그룹/기타 쓰기 권한이 없습니다. (perm=$perm)"
      fi
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_23() {
  local code="U-23"
  local item="SUID, SGID, Sticky bit 설정 파일 점검"
  local severity="상"
  local status="양호"
  local reason="비정상/사용자쓰기가능 경로 또는 패키지 미소유 SUID/SGID 파일이 발견되지 않았습니다."

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

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

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
  local warn_found=0
  local evidence_vuln=""
  local evidence_warn=""
  local count_v=0
  local count_w=0

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
        evidence_vuln+=" - $mode $owner:$group $f (BAD_PATH);"
        count_v=$((count_v+1))
      fi
      continue
    fi

    if _is_whitelisted "$f"; then
      warn_found=1
      if (( count_w < MAX_EVIDENCE )); then
        evidence_warn+=" - $mode $owner:$group $f (WHITELIST);"
        count_w=$((count_w+1))
      fi
      continue
    fi

    if command -v rpm >/dev/null 2>&1; then
      if ! rpm -qf "$f" >/dev/null 2>&1; then
        vuln_found=1
        if (( count_v < MAX_EVIDENCE )); then
          evidence_vuln+=" - $mode $owner:$group $f (NOT_OWNED_BY_RPM);"
          count_v=$((count_v+1))
        fi
        continue
      fi
    fi

    warn_found=1
    if (( count_w < MAX_EVIDENCE )); then
      evidence_warn+=" - $mode $owner:$group $f (CHECK);"
      count_w=$((count_w+1))
    fi
  done < <(find "$SEARCH_ROOT" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

  if (( vuln_found == 1 )); then
    status="취약"
    if [ -n "$evidence_vuln" ]; then
      reason="비정상/사용자쓰기가능 경로 또는 패키지 미소유 SUID/SGID 파일이 존재합니다. (예: ${evidence_vuln%%;*})"
    else
      reason="비정상/사용자쓰기가능 경로 또는 패키지 미소유 SUID/SGID 파일이 존재합니다."
    fi
  else
    status="양호"
    if (( warn_found == 1 )) && [ -n "$evidence_warn" ]; then
      reason="취약 조건(BAD_PATH/패키지 미소유) 항목은 없으며, 기타 SUID/SGID 파일은 확인 대상입니다. (예: ${evidence_warn%%;*})"
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_24() {
  local code="U-24"
  local item="사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="홈 디렉터리 환경파일의 소유자가 root 또는 해당 계정이며, 그룹/기타 쓰기 권한이 통제되어 있습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local -a CHECK_FILES=(
    ".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login" ".bash_logout"
    ".exrc" ".vimrc" ".netrc" ".forward" ".rhosts" ".shosts"
  )

  local VULN=0
  local REASON=""
  local first_offender=""

  local USER_LIST USER_INFO USER_NAME USER_HOME
  USER_LIST="$(awk -F: '$7!~/(nologin|false)/ {print $1":"$6}' /etc/passwd 2>/dev/null)"

  for USER_INFO in $USER_LIST; do
    USER_NAME="${USER_INFO%%:*}"
    USER_HOME="${USER_INFO#*:}"

    [ -d "$USER_HOME" ] || continue

    local FILE TARGET FILE_OWNER PERM_OCT
    for FILE in "${CHECK_FILES[@]}"; do
      TARGET="$USER_HOME/$FILE"
      [ -f "$TARGET" ] || continue

      FILE_OWNER="$(stat -c "%U" "$TARGET" 2>/dev/null)"
      PERM_OCT="$(stat -c "%a" "$TARGET" 2>/dev/null)"

      if [ -z "$FILE_OWNER" ] || [ -z "$PERM_OCT" ]; then
        VULN=1
        REASON="$REASON [정보 확인 실패] $TARGET |"
        [ -z "$first_offender" ] && first_offender="$TARGET (stat 확인 실패)"
        continue
      fi

      if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USER_NAME" ]; then
        VULN=1
        REASON="$REASON [소유자 불일치] $TARGET (owner=$FILE_OWNER) |"
        [ -z "$first_offender" ] && first_offender="$TARGET (owner=$FILE_OWNER)"
      fi

      if [[ "$PERM_OCT" =~ .[2367]. ]] || [[ "$PERM_OCT" =~ ..[2367] ]]; then
        VULN=1
        REASON="$REASON [권한 취약] $TARGET (perm=$PERM_OCT) |"
        [ -z "$first_offender" ] && first_offender="$TARGET (perm=$PERM_OCT)"
      fi
    done
  done

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    if [ -n "$first_offender" ]; then
      reason="홈 디렉터리 환경파일에서 소유자 불일치 또는 그룹/기타 쓰기 권한이 확인되었습니다. (예: $first_offender)"
    else
      reason="홈 디렉터리 환경파일에서 소유자 불일치 또는 그룹/기타 쓰기 권한이 확인되었습니다."
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_25() {
  local code="U-25"
  local item="world writable 파일 점검"
  local severity="상"
  local status="양호"
  local reason="world writable 파일이 발견되지 않았습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local found=0
  local sample=""

  sample="$(find / -xdev -type f -perm -0002 -print -quit 2>/dev/null || true)"
  if [ -n "$sample" ]; then
    found=1
  fi

  if [ "$found" -eq 1 ]; then
    status="취약"
    reason="world writable 파일이 존재합니다. (샘플: $sample)"
  else
    status="양호"
    reason="world writable 파일이 발견되지 않았습니다."
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_26() {
  local code="U-26"
  local item="/dev에 존재하지 않는 device 파일 점검"
  local severity="상"
  local status="양호"
  local reason="/dev 디렉터리에서 존재하지 않아야 할 일반 파일이 발견되지 않았습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local target_dir="/dev"

  if [ ! -d "$target_dir" ]; then
    status="N/A"
    reason="$target_dir 디렉터리가 존재하지 않습니다."
  else
    local vul_files
    vul_files="$(find /dev \( -path /dev/mqueue -o -path /dev/shm \) -prune -o -type f -print 2>/dev/null || true)"

    if [ -n "$vul_files" ]; then
      status="취약"
      local first
      first="$(printf '%s\n' "$vul_files" | head -n 1)"
      reason="/dev 내부에 존재하지 않아야 할 일반 파일이 발견되었습니다. (예: $first)"
    else
      status="양호"
      reason="/dev 디렉터리에서 존재하지 않아야 할 일반 파일이 발견되지 않았습니다."
    fi
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
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
  local status="취약"
  local reason="SSH/방화벽에서 특정 IP/대역 제한 정책이 확인되지 않습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    status="N/A"
    reason="root 권한 필요(sudo로 실행해야 SSH/방화벽 정책 확인 가능)"
    local esc_item esc_sev esc_status esc_reason
    esc_item="$(printf '%s' "$item" | _json_escape)"
    esc_sev="$(printf '%s' "$severity" | _json_escape)"
    esc_status="$(printf '%s' "$status" | _json_escape)"
    esc_reason="$(printf '%s' "$reason" | _json_escape)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
    return 0
  fi

  local good=0
  local hit_type=""
  local evidence_short=""

  _norm_grep() {
    local f="$1" r="$2"
    [ -f "$f" ] || return 1
    grep -Eiv '^[[:space:]]*#' "$f" 2>/dev/null | grep -Eiv '^[[:space:]]*$' | grep -Eqi "$r"
  }

  local sshd_cfg="/etc/ssh/sshd_config"
  local sshd_dropin_dir="/etc/ssh/sshd_config.d"

  _list_sshd_files() {
    echo "$sshd_cfg"
    if [ -d "$sshd_dropin_dir" ]; then
      ls -1 "$sshd_dropin_dir"/*.conf 2>/dev/null | sort
    fi
  }

  local f
  for f in $(_list_sshd_files); do
    [ -f "$f" ] || continue
    if _norm_grep "$f" '^[[:space:]]*Match[[:space:]]+Address[[:space:]]+'; then
      good=1
      hit_type="SSHD"
      evidence_short="sshd 설정에서 Match Address(IP/대역 제한) 확인: $f"
      break
    fi
  done

  if [ "$good" -eq 0 ] && command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state >/dev/null 2>&1; then
      local zones z
      zones="$(firewall-cmd --get-active-zones 2>/dev/null | awk 'NF{print $1}' | grep -v ':')"

      for z in $zones; do
        local rr srcs svc ports
        rr="$(firewall-cmd --zone="$z" --list-rich-rules 2>/dev/null)"

        if echo "$rr" | grep -Eqi 'source[[:space:]]+address=' && \
           echo "$rr" | grep -Eqi '(service[[:space:]]+name="ssh"|service[[:space:]]+name=ssh|port[[:space:]]+port="22"|port[[:space:]]+port=22)'; then
          good=1
          hit_type="FIREWALLD"
          evidence_short="firewalld rich-rule에서 source+ssh/22 조건 확인: zone=$z"
          break
        fi

        srcs="$(firewall-cmd --zone="$z" --list-sources 2>/dev/null)"
        if [ -n "$srcs" ]; then
          svc="$(firewall-cmd --zone="$z" --list-services 2>/dev/null)"
          ports="$(firewall-cmd --zone="$z" --list-ports 2>/dev/null)"
          if echo "$svc" | grep -qw ssh || echo "$ports" | grep -Eq '(^|[[:space:]])22/tcp([[:space:]]|$)'; then
            good=1
            hit_type="FIREWALLD"
            evidence_short="firewalld zone sources 지정 + SSH(22) 허용 확인: zone=$z, sources=$srcs"
            break
          fi
        fi
      done
    fi
  fi

  if [ "$good" -eq 0 ] && command -v nft >/dev/null 2>&1; then
    local nft_hit
    nft_hit="$(nft list ruleset 2>/dev/null | awk '
      BEGIN {in_input=0}
      $0 ~ /^[[:space:]]*chain[[:space:]]+input[[:space:]]*\{/ {in_input=1; next}
      in_input && $0 ~ /^[[:space:]]*}\s*$/ {in_input=0; next}
      in_input {
        line=$0
        has_dport22 = (line ~ /(tcp[[:space:]]+dport[[:space:]]+22|dport[[:space:]]+22|port[[:space:]]+22)/)
        has_saddr   = (line ~ /(ip6?[[:space:]]+saddr|ip[[:space:]]+saddr|ip6[[:space:]]+saddr|[[:space:]]saddr[[:space:]]+)/)
        has_action  = (line ~ /(accept|drop|reject)/)
        if (has_dport22 && has_saddr && has_action) { print line; exit 0 }
      }
      END { exit 1 }
    ')"
    if [ -n "$nft_hit" ]; then
      good=1
      hit_type="NFT"
      evidence_short="nftables input chain에서 SSH(22) source 제한 규칙 확인: $(echo "$nft_hit" | sed 's/^[[:space:]]*//')"
    fi
  fi

  if [ "$good" -eq 0 ] && command -v iptables >/dev/null 2>&1; then
    local ipt_hit
    ipt_hit="$(iptables -S INPUT 2>/dev/null | awk '
      {
        line=$0
        has_dport = (line ~ /--dport[[:space:]]+22/ || line ~ /dport[[:space:]]+22/)
        has_src   = (line ~ /(^|[[:space:]])-s[[:space:]]+[0-9]+\./ || line ~ /(^|[[:space:]])-s[[:space:]]+[0-9a-fA-F:]+/)
        has_act   = (line ~ /-j[[:space:]]+(ACCEPT|DROP|REJECT)/)
        if (has_dport && has_src && has_act) { print line; exit 0 }
      }
      END { exit 1 }
    ')"
    if [ -n "$ipt_hit" ]; then
      good=1
      hit_type="IPTABLES"
      evidence_short="iptables INPUT에서 SSH(22) source 제한 규칙 확인: $ipt_hit"
    fi
  fi

  if [ "$good" -eq 1 ]; then
    status="양호"
    reason="접속 IP/대역 제한 정책이 확인되었습니다. (type=$hit_type, 예: $evidence_short)"
  else
    status="취약"
    reason="SSH/방화벽에서 특정 IP/대역 제한 정책이 확인되지 않습니다."
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_29() {
  local code="U-29"
  local item="hosts.lpd 파일 소유자 및 권한 설정"
  local severity="하"
  local status="양호"
  local reason="/etc/hosts.lpd 파일이 존재하지 않거나, 소유자(root) 및 권한(600 이하)이 기준에 적합합니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local target="/etc/hosts.lpd"

  if [ -f "$target" ]; then
    local owner permit
    owner="$(stat -c "%U" "$target" 2>/dev/null)"
    permit="$(stat -c "%a" "$target" 2>/dev/null)"

    if [ -z "$owner" ] || [ -z "$permit" ]; then
      status="취약"
      reason="stat 명령으로 $target 정보를 읽지 못했습니다."
    else
      local bad_reason=""
      if [ "$owner" != "root" ]; then
        bad_reason="소유자가 root가 아닙니다(현재: $owner)."
      fi
      if [ "$permit" -gt 600 ]; then
        if [ -n "$bad_reason" ]; then
          bad_reason="$bad_reason / 권한이 600보다 큽니다(현재: $permit)."
        else
          bad_reason="권한이 600보다 큽니다(현재: $permit)."
        fi
      fi

      if [ -n "$bad_reason" ]; then
        status="취약"
        reason="$target 파일이 존재하며 기준을 위반합니다. $bad_reason"
      else
        status="양호"
        reason="$target 파일이 존재하며 소유자(root) 및 권한($permit)이 기준(600 이하)에 적합합니다."
      fi
    fi
  else
    status="양호"
    reason="$target 파일이 존재하지 않습니다."
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_30() {
  local code="U-30"
  local item="UMASK 설정 관리"
  local severity="중"
  local status="양호"
  local reason="시스템/서비스/사용자 환경 전반에 UMASK 022 이상 적용 상태로 확인되었습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local vuln=0
  local reasons=()

  check_umask_value() {
    local value="$1"
    value="${value#0}"  
    if [[ "$value" =~ ^[0-7]{3,4}$ ]]; then
      [ $((8#$value)) -ge 18 ] && return 0
    fi
    return 1
  }

  local cur_umask
  cur_umask="$(umask 2>/dev/null)"
  if ! check_umask_value "$cur_umask"; then
    vuln=1
    reasons+=("현재 세션 umask 값이 기준(022) 미만입니다(cur=$cur_umask).")
  fi

  local login_umask
  login_umask="$(grep -E "^[[:space:]]*UMASK[[:space:]]+[0-7]+" /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -n 1)"
  if [ -z "$login_umask" ]; then
    vuln=1
    reasons+=("/etc/login.defs 에 UMASK 설정을 확인할 수 없습니다.")
  elif ! check_umask_value "$login_umask"; then
    vuln=1
    reasons+=("/etc/login.defs 의 UMASK 값이 기준(022) 미만입니다(val=$login_umask).")
  fi

  local file umask_val
  for file in /etc/profile /etc/bashrc; do
    [ -f "$file" ] || continue
    umask_val="$(grep -E "^[[:space:]]*umask[[:space:]]+[0-7]+" "$file" 2>/dev/null | awk '{print $2}' | tail -n 1)"
    if [ -n "$umask_val" ] && ! check_umask_value "$umask_val"; then
      vuln=1
      reasons+=("$file 에 설정된 umask 값이 기준(022) 미만입니다(val=$umask_val).")
    fi
  done

  if command -v systemctl >/dev/null 2>&1; then
    local svc svc_umask
    while read -r svc; do
      [ -n "$svc" ] || continue
      svc_umask="$(systemctl show "$svc" -p UMask 2>/dev/null | awk -F= '{print $2}')"
      svc_umask="${svc_umask#0}"
      if [[ "$svc_umask" =~ ^[0-7]{3,4}$ ]]; then
        if ! check_umask_value "$svc_umask"; then
          vuln=1
          reasons+=("systemd 서비스 UMask가 기준(022) 미만인 항목이 있습니다(svc=$svc, UMask=$svc_umask).")
          break
        fi
      fi
    done < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="${reasons[0]}"
  else
    status="양호"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_31() {
  local code="U-31"
  local item="홈 디렉토리 소유자 및 권한 설정"
  local severity="중"
  local status="양호"
  local reason="홈 디렉토리 소유자가 해당 계정이며, 타 사용자 쓰기 권한이 제거된 것으로 확인되었습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local vuln=0
  local reasons=()

  local user_list
  user_list="$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /nologin|false/ { print $1 ":" $6 }' /etc/passwd 2>/dev/null)"

  if [ -z "$user_list" ]; then
    vuln=1
    reasons+=("점검 대상 일반 사용자 계정을 /etc/passwd에서 추출하지 못했습니다.")
  else
    local user username homedir owner permit others_permit
    for user in $user_list; do
      username="${user%%:*}"
      homedir="${user#*:}"

      if [ -z "$username" ] || [ -z "$homedir" ]; then
        vuln=1
        reasons+=("계정/홈 디렉토리 정보 파싱에 실패했습니다(entry=$user).")
        continue
      fi

      if [ ! -d "$homedir" ]; then
        vuln=1
        reasons+=("$username 계정의 홈 디렉토리가 존재하지 않습니다(home=$homedir).")
        continue
      fi

      owner="$(stat -c '%U' "$homedir" 2>/dev/null)"
      permit="$(stat -c '%a' "$homedir" 2>/dev/null)"

      if [ -z "$owner" ] || [ -z "$permit" ]; then
        vuln=1
        reasons+=("$username 홈 디렉토리 정보를 stat으로 확인하지 못했습니다(home=$homedir).")
        continue
      fi

      if [ "$owner" != "$username" ]; then
        vuln=1
        reasons+=("홈 디렉토리 소유자 불일치: user=$username, home=$homedir, owner=$owner.")
      fi

      others_permit="${permit: -1}"
      if [[ "$others_permit" =~ [2367] ]]; then
        vuln=1
        reasons+=("타 사용자 쓰기 권한 존재: user=$username, home=$homedir, perm=$permit.")
      fi
    done
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="${reasons[0]}"
  else
    status="양호"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}

U_32() {
  local code="U-32"
  local item="홈 디렉토리로 지정한 디렉토리의 존재 관리"
  local severity="중"
  local status="양호"
  local reason="로그인 가능한 계정의 홈 디렉토리가 존재하며, 부적절한 홈 디렉토리 지정이 없는 것으로 확인되었습니다."

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local vuln=0
  local missing=()

  if [ ! -f /etc/passwd ]; then
    vuln=1
    missing+=("/etc/passwd 파일이 존재하지 않습니다.")
  else
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
  fi

  if (( ${#missing[@]} > 0 )); then
    vuln=1
  fi

  if (( vuln == 1 )); then
    status="취약"
    reason="로그인 가능한 계정 중 홈 디렉토리가 없거나 존재하지 않는 항목이 있습니다(예: ${missing[0]})."
  else
    status="양호"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}
U_33() {
  local code="U-33"
  local item="숨겨진 파일 및 디렉토리 검색 및 제거"
  local severity="하"
  local status="양호"
  local reason="의심 징후 숨김파일이 발견되지 않았습니다. (count=0)"

  _json_escape() {
    sed -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g'  \
        -e ':a;N;$!ba;s/\n/\\n/g' \
        -e 's/\r/\\r/g' \
        -e 's/\t/\\t/g'
  }

  local prune_paths=(
    "/proc"
    "/sys"
    "/run"
  )

  local whitelist_regex='^/etc/\.pwd\.lock$|^/etc/\.updated$|^/var/\.updated$|^/usr/lib/sysimage/rpm/\.rpm\.lock$|^/usr/lib/sysimage/rpm/\.rpmdbdirsymlink_created$|^/var/lib/\.ssh-host-keys-migration$|^/usr/lib/modules/[^/]+/\.vmlinuz\.hmac$|^/boot/\.vmlinuz-[^/]+\.hmac$|^/etc/skel/\.(bashrc|bash_profile|bash_logout)$|^/root/\.(bashrc|bash_profile|bash_logout|cshrc|tcshrc|bash_history)$|^/home/[^/]+/\.(bashrc|bash_profile|bash_logout|bash_history|lesshst)$'

  local recent_exclude_regex='^/var/log/|^/var/cache/|^/var/lib/(rpm|dnf)/|^/usr/lib/debug/|^/usr/lib/modules/|^/boot/'

  local WL_ONELINE EX_ONELINE
  WL_ONELINE="$(printf "%s" "$whitelist_regex" | tr -d '\n')"
  EX_ONELINE="$(printf "%s" "$recent_exclude_regex" | tr -d '\n')"

  local PRUNE_EXPR=()
  local p
  for p in "${prune_paths[@]}"; do
    PRUNE_EXPR+=( -path "$p" -prune -o )
  done

  local SUS_STRONG
  SUS_STRONG="$(
    find / \
      "${PRUNE_EXPR[@]}" \
      -name ".*" -type f \
      \( -executable -o -perm -4000 -o -perm -2000 \) \
      -print 2>/dev/null \
    | awk -v wl="$WL_ONELINE" '
        $0 ~ wl { next }
        { print }
      ' \
    | sort -u
  )"

  local SUS_HIGHRISK
  SUS_HIGHRISK="$(
    find /tmp /var/tmp /dev/shm -xdev \
      -name ".*" -type f \
      \( -mtime -7 -o -executable -o -perm -4000 -o -perm -2000 \) \
      -print 2>/dev/null \
    | awk -v wl="$WL_ONELINE" '
        $0 ~ wl { next }
        { print }
      ' \
    | sort -u
  )"

  local SUS_RECENT
  SUS_RECENT="$(
    find /etc /usr /root /home /var -xdev \
      -name ".*" -type f -mtime -7 \
      -print 2>/dev/null \
    | awk -v wl="$WL_ONELINE" -v ex="$EX_ONELINE" '
        $0 ~ ex { next }
        $0 ~ wl { next }
        { print }
      ' \
    | sort -u
  )"

  local SUS_HIDDEN_FILES
  SUS_HIDDEN_FILES="$(
    printf "%s\n%s\n%s\n" "$SUS_STRONG" "$SUS_HIGHRISK" "$SUS_RECENT" \
    | sed '/^[[:space:]]*$/d' \
    | sort -u
  )"

  local SUS_COUNT=0
  if [ -n "$SUS_HIDDEN_FILES" ]; then
    SUS_COUNT="$(echo "$SUS_HIDDEN_FILES" | wc -l | tr -d ' ')"
  fi

  if [ "$SUS_COUNT" -gt 0 ]; then
    status="취약"
    reason="의심 징후 숨김파일이 발견되었습니다. (count=$SUS_COUNT)"
  else
    status="양호"
    reason="의심 징후 숨김파일이 발견되지 않았습니다. (count=0)"
  fi

  local esc_item esc_sev esc_status esc_reason
  esc_item="$(printf '%s' "$item" | _json_escape)"
  esc_sev="$(printf '%s' "$severity" | _json_escape)"
  esc_status="$(printf '%s' "$status" | _json_escape)"
  esc_reason="$(printf '%s' "$reason" | _json_escape)"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$esc_item" "$esc_sev" "$esc_status" "$esc_reason"
}


U_34() {
  local code="U-34"
  local item="Finger 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="Finger 서비스가 비활성화되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local reasons=()

  if command -v systemctl >/dev/null 2>&1; then
    local services=("finger" "fingerd" "in.fingerd" "finger.socket")
    local svc
    for svc in "${services[@]}"; do
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        reasons+=("systemd에서 ${svc}가 active 상태입니다")
      fi
    done
  else
    reasons+=("systemctl을 사용할 수 없어 서비스 상태를 확인할 수 없습니다")
  fi

  if ps -ef | grep -v grep | grep -Eiq '(^|[[:space:]/])(in\.)?fingerd([[:space:]]|$)'; then
    reasons+=("fingerd 프로세스가 실행 중입니다")
  fi

  local port_check=""
  if command -v ss >/dev/null 2>&1; then
    port_check="$(ss -nlpt 2>/dev/null | awk '$4 ~ /:79$/ {print $0}' | head -n 1)"
  elif command -v netstat >/dev/null 2>&1; then
    port_check="$(netstat -natp 2>/dev/null | awk '$4 ~ /:79$/ {print $0}' | head -n 1)"
  else
    reasons+=("ss/netstat 명령이 없어 79/tcp 리스닝 여부를 확인할 수 없습니다")
  fi

  if [ -n "$port_check" ]; then
    reasons+=("79/tcp 포트가 리스닝 중입니다: ${port_check}")
  fi

  if [ "${#reasons[@]}" -gt 0 ]; then
    status="취약"
    reason="$(IFS='; '; echo "${reasons[*]}")"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_35() {
  local code="U-35"
  local item="공유 서비스에 대한 익명 접근 제한 설정"
  local severity="상"
  local status="양호"
  local reason="공유 서비스에서 익명(Anonymous/Guest) 접근을 유발하는 설정이 발견되지 않았습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local reasons=()

  is_listening_port() { ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$"; }
  is_active_service() { systemctl is-active "$1" >/dev/null 2>&1; }
  dedup() { printf "%s\n" "$@" | awk 'NF && !seen[$0]++'; }

  local ftp_checked=0 ftp_running=0 ftp_pkg=0 ftp_conf_found=0
  local VSFTPD_FILES=() PROFTPD_FILES=()

  if command -v rpm >/dev/null 2>&1; then
    rpm -q vsftpd >/dev/null 2>&1 && ftp_pkg=1
    rpm -q proftpd >/dev/null 2>&1 && ftp_pkg=1
    rpm -q proftpd-core >/dev/null 2>&1 && ftp_pkg=1
  fi

  if is_active_service vsftpd || is_active_service proftpd; then
    ftp_running=1
  fi
  if command -v ss >/dev/null 2>&1 && is_listening_port 21; then
    ftp_running=1
  fi

  for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do [ -f "$f" ] && VSFTPD_FILES+=("$f"); done
  for f in /etc/proftpd/proftpd.conf /etc/proftpd.conf /etc/proftpd.d/proftpd.conf; do [ -f "$f" ] && PROFTPD_FILES+=("$f"); done

  if command -v rpm >/dev/null 2>&1; then
    if rpm -q vsftpd >/dev/null 2>&1; then
      while IFS= read -r f; do [ -f "$f" ] && VSFTPD_FILES+=("$f"); done < <(rpm -qc vsftpd 2>/dev/null)
    fi
    for pkg in proftpd proftpd-core; do
      if rpm -q "$pkg" >/dev/null 2>&1; then
        while IFS= read -r f; do [ -f "$f" ] && PROFTPD_FILES+=("$f"); done < <(rpm -qc "$pkg" 2>/dev/null)
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
        reasons+=("${conf}: 익명(Anonymous) FTP 설정 블록이 존재합니다")
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
        reasons+=("${conf}: 익명 FTP 접속 허용(anonymous_enable=YES)")
      fi
    done

    if [ "$ftp_conf_found" -eq 0 ] && [ "$ftp_running" -eq 1 ]; then
      reasons+=("FTP 서비스가 동작 중이나(vsftpd/proftpd 또는 21/tcp 리슨), 설정 파일을 확인할 수 없습니다")
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
          | wc -l
      )"
      if [ "$cnt_no_root" -gt 0 ]; then
        reasons+=("/etc/exports: no_root_squash 설정이 존재합니다")
      fi

      cnt_star="$(
        grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null \
          | grep -E '(^|[[:space:]])\*([[:space:]\(]|$)' \
          | wc -l
      )"
      if [ "$cnt_star" -gt 0 ]; then
        reasons+=("/etc/exports: 전체 호스트(*) 공유 설정이 존재합니다")
      fi
    else
      if [ "$nfs_running" -eq 1 ]; then
        reasons+=("NFS 서비스가 동작 중이나(nfs-server active), /etc/exports 파일이 존재하지 않습니다")
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
      local smb_hits
      smb_hits="$(
        grep -v '^[[:space:]]*#' /etc/samba/smb.conf 2>/dev/null \
          | grep -Ei '^[[:space:]]*(guest[[:space:]]+ok|public|map[[:space:]]+to[[:space:]]+guest|security)[[:space:]]*='
      )"
      if [ -n "$smb_hits" ]; then
        local cnt_guest cnt_public cnt_share cnt_map
        cnt_guest="$(echo "$smb_hits" | grep -Ei '^[[:space:]]*guest[[:space:]]+ok[[:space:]]*=[[:space:]]*yes' | wc -l)"
        cnt_public="$(echo "$smb_hits" | grep -Ei '^[[:space:]]*public[[:space:]]*=[[:space:]]*yes' | wc -l)"
        cnt_share="$(echo "$smb_hits" | grep -Ei '^[[:space:]]*security[[:space:]]*=[[:space:]]*share' | wc -l)"
        cnt_map="$(echo "$smb_hits" | grep -Ei '^[[:space:]]*map[[:space:]]+to[[:space:]]+guest[[:space:]]*=' | wc -l)"

        if [ "$cnt_guest" -gt 0 ] || [ "$cnt_public" -gt 0 ] || [ "$cnt_share" -gt 0 ] || [ "$cnt_map" -gt 0 ]; then
          local first5
          first5="$(echo "$smb_hits" | head -n 5 | tr '\n' '; ')"
          reasons+=("/etc/samba/smb.conf: 익명/게스트 접근 유발 가능 설정이 존재합니다: ${first5}")
        fi
      fi
    else
      if [ "$smb_running" -eq 1 ]; then
        reasons+=("Samba 서비스가 동작 중이나(smb/nmb active), /etc/samba/smb.conf 파일이 존재하지 않습니다")
      fi
    fi
  fi

  if [ "${#reasons[@]}" -gt 0 ]; then
    status="취약"
    reason="$(IFS=' | '; echo "${reasons[*]}")"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_36() {
  local code="U-36"
  local item="r 계열 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="r 계열 서비스(rlogin/rsh/rexec 등)가 비활성화되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local reasons=()

  local check_port=""
  if command -v ss >/dev/null 2>&1; then
    check_port="$(ss -antl 2>/dev/null | grep -E ':(512|513|514)\b' | head -n 3)"
  elif command -v netstat >/dev/null 2>&1; then
    check_port="$(netstat -antp 2>/dev/null | grep -E ':(512|513|514)\b' | head -n 3)"
  else
    reasons+=("ss/netstat 명령이 없어 512/513/514 포트 리스닝 여부를 확인할 수 없습니다")
  fi

  if [ -n "$check_port" ]; then
    reasons+=("r-command 관련 포트(512/513/514)가 리스닝 중입니다: $(echo "$check_port" | tr '\n' '; ')")
  fi

  if command -v systemctl >/dev/null 2>&1; then
    local services=("rlogin" "rsh" "rexec" "shell" "login" "exec")
    local svc
    for svc in "${services[@]}"; do
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        reasons+=("systemd에서 ${svc} 서비스가 active 상태입니다")
      fi
    done
  else
    reasons+=("systemctl을 사용할 수 없어 systemd 서비스 상태를 확인할 수 없습니다")
  fi

  if [ -d "/etc/xinetd.d" ]; then
    local xinetd_vul=""
    xinetd_vul="$(
      grep -lE "disable[[:space:]]*=[[:space:]]*no" \
        /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec \
        /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec \
        2>/dev/null | tr '\n' ' '
    )"
    if [ -n "$xinetd_vul" ]; then
      reasons+=("xinetd 설정에서 r 계열 서비스가 활성화(disable=no) 되어 있습니다: ${xinetd_vul}")
    fi
  fi

  if [ "${#reasons[@]}" -gt 0 ]; then
    status="취약"
    reason="$(IFS=' | '; echo "${reasons[*]}")"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
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
  local item="DoS 공격에 취약한 서비스 비활성화 (Rocky 10.x 기준)"
  local severity="상"
  local status="양호"
  local reason="DoS 공격에 취약한 전통 서비스(echo/discard/daytime/chargen)가 비활성화되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local CHECK_SNMP=0
  local CHECK_DNS=0
  local CHECK_NTP=0

  local inetd_services=("echo" "discard" "daytime" "chargen")
  local systemd_sockets=("echo.socket" "discard.socket" "daytime.socket" "chargen.socket")

  local snmp_units=("snmpd.service")
  local dns_units=("named.service" "bind9.service")
  local ntp_units=("chronyd.service" "ntpd.service" "systemd-timesyncd.service")

  local in_scope_used=0
  local vulnerable=0
  local evidences=()

  _unit_exists() {
    systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$1"
  }

  _unit_enabled_or_active() {
    systemctl is-enabled --quiet "$1" 2>/dev/null && return 0
    systemctl is-active  --quiet "$1" 2>/dev/null && return 0
    return 1
  }

  if [ -d /etc/xinetd.d ]; then
    local svc
    for svc in "${inetd_services[@]}"; do
      if [ -f "/etc/xinetd.d/${svc}" ]; then
        in_scope_used=1
        local disable_yes_count
        disable_yes_count="$(
          grep -vE '^\s*#' "/etc/xinetd.d/${svc}" 2>/dev/null \
            | grep -iE '^\s*disable\s*=\s*yes\s*$' | wc -l
        )"
        if [ "$disable_yes_count" -eq 0 ]; then
          vulnerable=1
          evidences+=("xinetd: ${svc} 서비스가 비활성화(disable=yes) 되어 있지 않습니다 (/etc/xinetd.d/${svc})")
        else
          evidences+=("xinetd: ${svc} 서비스가 disable=yes 로 비활성화되어 있습니다")
        fi
      fi
    done
  fi

  if [ -f /etc/inetd.conf ]; then
    local svc
    for svc in "${inetd_services[@]}"; do
      local enable_count
      enable_count="$(
        grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -w "$svc" | wc -l
      )"
      if [ "$enable_count" -gt 0 ]; then
        in_scope_used=1
        vulnerable=1
        evidences+=("inetd: ${svc} 서비스가 /etc/inetd.conf 에서 활성화되어 있습니다")
      fi
    done
  fi

  if command -v systemctl >/dev/null 2>&1; then
    local sock
    for sock in "${systemd_sockets[@]}"; do
      if _unit_exists "$sock"; then
        in_scope_used=1
        if _unit_enabled_or_active "$sock"; then
          vulnerable=1
          evidences+=("systemd: ${sock} 가 활성화되어 있습니다 (enabled/active)")
        else
          evidences+=("systemd: ${sock} 는 설치되어 있으나 비활성화 상태입니다")
        fi
      fi
    done

    local unit

    if [ "$CHECK_SNMP" -eq 1 ]; then
      for unit in "${snmp_units[@]}"; do
        if _unit_exists "$unit"; then
          in_scope_used=1
          if _unit_enabled_or_active "$unit"; then
            vulnerable=1
            evidences+=("SNMP: ${unit} 가 활성화되어 있습니다 (정책상 점검 포함)")
          else
            evidences+=("SNMP: ${unit} 는 설치되어 있으나 비활성화 상태입니다")
          fi
        fi
      done
    else
      for unit in "${snmp_units[@]}"; do
        if _unit_exists "$unit" && _unit_enabled_or_active "$unit"; then
          evidences+=("info: SNMP(${unit}) 활성화 감지(취약 판정 미포함)")
        fi
      done
    fi

    if [ "$CHECK_DNS" -eq 1 ]; then
      for unit in "${dns_units[@]}"; do
        if _unit_exists "$unit"; then
          in_scope_used=1
          if _unit_enabled_or_active "$unit"; then
            vulnerable=1
            evidences+=("DNS: ${unit} 가 활성화되어 있습니다 (정책상 점검 포함)")
          else
            evidences+=("DNS: ${unit} 는 설치되어 있으나 비활성화 상태입니다")
          fi
        fi
      done
    else
      for unit in "${dns_units[@]}"; do
        if _unit_exists "$unit" && _unit_enabled_or_active "$unit"; then
          evidences+=("info: DNS(${unit}) 활성화 감지(취약 판정 미포함)")
        fi
      done
    fi

    if [ "$CHECK_NTP" -eq 1 ]; then
      for unit in "${ntp_units[@]}"; do
        if _unit_exists "$unit"; then
          in_scope_used=1
          if _unit_enabled_or_active "$unit"; then
            vulnerable=1
            evidences+=("NTP: ${unit} 가 활성화되어 있습니다 (정책상 점검 포함)")
          else
            evidences+=("NTP: ${unit} 는 설치되어 있으나 비활성화 상태입니다")
          fi
        fi
      done
    else
      for unit in "${ntp_units[@]}"; do
        if _unit_exists "$unit" && _unit_enabled_or_active "$unit"; then
          evidences+=("info: NTP(${unit}) 활성화 감지(시간동기 서비스, 일반적으로 필요)")
        fi
      done
    fi
  else
    evidences+=("systemctl을 사용할 수 없어 systemd socket/서비스 상태를 확인할 수 없습니다")
  fi

  if [ "$in_scope_used" -eq 0 ]; then
    status="N/A"
    reason="전통 DoS 취약 서비스(echo/discard/daytime/chargen)가 설치/사용되지 않아 점검 대상이 아닙니다."
  else
    if [ "$vulnerable" -eq 1 ]; then
      status="취약"
      if [ "${#evidences[@]}" -gt 0 ]; then
        reason="${evidences[0]}"
        local extra=$(( ${#evidences[@]} - 1 ))
        if [ "$extra" -gt 0 ]; then
          reason="${reason} 외 ${extra}건"
        fi
      else
        reason="DoS 공격에 취약한 전통 서비스가 활성화되어 있습니다."
      fi
    else
      status="양호"
      reason="DoS 공격에 취약한 전통 서비스가 비활성화되어 있습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"

  return 0
}

U_39() {
  local code="U-39"
  local item="불필요한 NFS 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="불필요한 NFS 관련 서비스가 비활성화되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local found=0
  local details=()

  if command -v systemctl >/dev/null 2>&1; then
    local nfs_units=("nfs-server" "rpcbind" "nfs-mountd" "rpc-statd" "rpc-idmapd")
    local u
    for u in "${nfs_units[@]}"; do
      if systemctl is-active --quiet "$u" 2>/dev/null; then
        found=1
        details+=("${u} active")
      fi
    done
  else
    details+=("systemctl을 사용할 수 없어 서비스 상태를 확인할 수 없습니다")
  fi

  if ps -ef | grep -v "grep" | grep -iwE "nfsd|mountd|rpcbind|statd|lockd|idmapd" >/dev/null 2>&1; then
    if [ "$found" -eq 0 ]; then
      found=1
      details+=("NFS 관련 커널 스레드 또는 프로세스 실행 감지")
    fi
  fi

  if [ "$found" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="${details[0]}"
      local extra=$(( ${#details[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="불필요한 NFS 관련 서비스가 구동 중입니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"

  return 0
}


U_40() {
  local code="U-40"
  local item="NFS 접근 통제"
  local severity="상"
  local status="양호"
  local reason="불필요한 NFS 서비스를 사용하지 않거나, everyone(*) 공유가 제한되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln=0
  local details=()

  if ps -ef | grep -iE 'nfs|rpc.statd|statd|rpc.lockd|lockd' \
      | grep -ivE 'grep|kblockd|rstatd|' >/dev/null 2>&1; then

    if [ -f /etc/exports ]; then
      local etc_exports_all_count
      local etc_exports_insecure_count
      local etc_exports_directory_count
      local etc_exports_squash_count

      etc_exports_all_count="$(
        grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | grep '\*' | wc -l
      )"
      etc_exports_insecure_count="$(
        grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | grep -i 'insecure' | wc -l
      )"
      etc_exports_directory_count="$(
        grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | wc -l
      )"
      etc_exports_squash_count="$(
        grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | grep -iE 'root_squash|all_squash' | wc -l
      )"

      if [ "$etc_exports_all_count" -gt 0 ]; then
        vuln=1
        details+=("/etc/exports 파일에 '*' 설정이 있습니다")
      elif [ "$etc_exports_insecure_count" -gt 0 ]; then
        vuln=1
        details+=("/etc/exports 파일에 'insecure' 옵션이 설정되어 있습니다")
      else
        if [ "$etc_exports_directory_count" -ne "$etc_exports_squash_count" ]; then
          vuln=1
          details+=("/etc/exports 파일에 'root_squash' 또는 'all_squash' 옵션이 설정되어 있지 않습니다")
        fi
      fi
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="${details[0]}"
      local extra=$(( ${#details[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="NFS 접근 통제 기준을 충족하지 않습니다."
    fi
  else
    status="양호"
    reason="everyone(*) 공유가 없고, insecure 옵션이 없으며, squash 옵션이 적절히 적용되어 있습니다(또는 NFS 미사용)."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_41() {
  local code="U-41"
  local item="불필요한 automountd 제거"
  local severity="상"
  local status="양호"
  local reason="automountd(autofs) 서비스가 비활성화되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln=0
  local details=()

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet autofs 2>/dev/null; then
      vuln=1
      details+=("autofs 서비스가 active 상태입니다")
    fi
  else
    details+=("systemctl을 사용할 수 없어 autofs 서비스 상태를 확인할 수 없습니다")
  fi

  if ps -ef | grep -v grep | grep -Ei "automount|autofs" >/dev/null 2>&1; then
    if [ "$vuln" -eq 0 ]; then
      vuln=1
      details+=("automount/autofs 관련 프로세스가 실행 중입니다")
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="${details[0]}"
      local extra=$(( ${#details[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="automountd(autofs) 서비스가 활성화되어 있습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_42() {
  local code="U-42"
  local item="불필요한 RPC 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="rpcbind(RPC) 서비스가 비활성(미실행) 상태입니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local rpc_active=0

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet rpcbind.service 2>/dev/null || systemctl is-active --quiet rpcbind.socket 2>/dev/null; then
      rpc_active=1
    fi
  else
    rpc_active=1
    reason="systemctl을 사용할 수 없어 rpcbind 상태를 확인할 수 없습니다."
  fi

  if [ "$rpc_active" -eq 1 ]; then
    status="취약"
    if [ "$reason" = "rpcbind(RPC) 서비스가 비활성(미실행) 상태입니다." ]; then
      reason="rpcbind(RPC) 서비스가 활성 상태입니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_43() {
  local code="U-43"
  local item="NIS, NIS+ 점검"
  local severity="상"
  local status="양호"
  local reason="NIS 서비스가 비활성화되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
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
          evidences+=("systemd: ${unit} 가 active/enabled 상태입니다")
        fi
      fi
    done

    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "rpcbind.service"; then
      if systemctl is-active --quiet "rpcbind.service" 2>/dev/null || systemctl is-enabled --quiet "rpcbind.service" 2>/dev/null; then
        evidences+=("info: rpcbind.service 가 active/enabled 입니다(단독으로 NIS 사용 증거는 아님)")
      fi
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE "$nis_procs_regex" | grep -vE 'grep|U_43\(|U_28\(' >/dev/null 2>&1; then
    nis_in_use=1
    vulnerable=1
    evidences+=("process: NIS 관련 프로세스(yp*)가 실행 중입니다")
  fi

  if command -v ss >/dev/null 2>&1; then
    if ss -lntup 2>/dev/null | grep -E ':(111)\b' >/dev/null 2>&1; then
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(ss)")
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lntup 2>/dev/null | grep -E ':(111)\b' >/dev/null 2>&1; then
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(netstat)")
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE "$nisplus_procs_regex" | grep -v grep >/dev/null 2>&1; then
    evidences+=("info: NIS+ 관련 프로세스 흔적 감지(환경에 따라 양호 조건 충족 가능)")
  fi

  if [ "$nis_in_use" -eq 0 ]; then
    status="N/A"
    reason="NIS 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다(yp* 서비스/프로세스 미검출)."
  else
    if [ "$vulnerable" -eq 1 ]; then
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
      reason="NIS 사용 흔적은 있으나 활성화(실행/enable) 상태는 확인되지 않았습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_44() {
  local code="U-44"
  local item="tftp, talk 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="tftp/talk/ntalk 서비스가 비활성화되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local services=("tftp" "talk" "ntalk")
  local findings=()

  if command -v systemctl >/dev/null 2>&1; then
    local s u
    for s in "${services[@]}"; do
      local units=(
        "$s" "$s.service" "${s}d" "${s}d.service"
        "${s}-server" "${s}-server.service"
        "tftp-server.service" "tftpd.service" "talkd.service"
      )
      for u in "${units[@]}"; do
        if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
          if systemctl is-active --quiet "$u" 2>/dev/null; then
            findings+=("${s} 서비스가 systemd에서 활성 상태입니다(unit=${u})")
            break
          fi
        fi
      done
    done
  else
    findings+=("systemctl을 사용할 수 없어 systemd 서비스 상태를 확인할 수 없습니다")
  fi

  if [ -d /etc/xinetd.d ]; then
    local s
    for s in "${services[@]}"; do
      if [ -f "/etc/xinetd.d/$s" ]; then
        local disable_line
        disable_line="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "/etc/xinetd.d/$s" 2>/dev/null \
          | grep -Ei '^[[:space:]]*disable[[:space:]]*=' | tail -n 1)"
        if ! echo "$disable_line" | grep -Eiq 'disable[[:space:]]*=[[:space:]]*yes'; then
          findings+=("${s} 서비스가 /etc/xinetd.d/${s} 에서 비활성화(disable=yes)되어 있지 않습니다")
        fi
      fi
    done
  fi

  if [ -f /etc/inetd.conf ]; then
    local s
    for s in "${services[@]}"; do
      if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null \
        | grep -Eiq "(^|[[:space:]])$s([[:space:]]|$)"; then
        findings+=("${s} 서비스가 /etc/inetd.conf 파일에서 활성 상태(주석 아님)로 존재합니다")
      fi
    done
  fi

  if [ "${#findings[@]}" -gt 0 ]; then
    status="취약"
    reason="${findings[0]}"
    local extra=$(( ${#findings[@]} - 1 ))
    if [ "$extra" -gt 0 ]; then
      reason="${reason} 외 ${extra}건"
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"

  return 0
}

U_45() {
  local code="U-45"
  local item="메일 서비스 버전 점검"
  local severity="상"
  local status="양호"
  local reason="메일 서비스 버전이 최신 기준(8.18.2)에 부합하거나, 서비스 사용 흔적이 없습니다."

  local LATEST="8.18.2"

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local mail_detected=0
  local detected_hint=""

  if [ -f /etc/services ]; then
    local smtp_ports=()
    while IFS= read -r p; do
      [ -n "$p" ] && smtp_ports+=("$p")
    done < <(
      grep -vE '^#|^\s#' /etc/services 2>/dev/null \
        | awk 'tolower($1)=="smtp"{print $2}' \
        | awk -F/ 'tolower($2)=="tcp"{print $1}' \
        | awk 'NF'
    )

    if [ "${#smtp_ports[@]}" -gt 0 ]; then
      local p
      for p in "${smtp_ports[@]}"; do
        local hit=0
        if command -v netstat >/dev/null 2>&1; then
          hit="$(netstat -nat 2>/dev/null \
            | grep -w 'tcp' \
            | grep -Ei 'listen|established|syn_sent|syn_received' \
            | grep ":${p} " \
            | wc -l)"
        elif command -v ss >/dev/null 2>&1; then
          hit="$(ss -ant 2>/dev/null \
            | grep -Ei 'LISTEN|ESTAB|SYN-SENT|SYN-RECV' \
            | grep -E "[:.]${p}\b" \
            | wc -l)"
        fi

        if [ "${hit:-0}" -gt 0 ]; then
          mail_detected=1
          detected_hint="smtp port ${p} 활동/리스닝 감지"
          break
        fi
      done
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE 'smtp|sendmail' | grep -v 'grep' >/dev/null 2>&1; then
    mail_detected=1
    if [ -z "$detected_hint" ]; then
      detected_hint="smtp/sendmail 관련 프로세스 감지"
    fi
  fi

  if [ "$mail_detected" -eq 1 ]; then
    local rpm_smtp_version=""
    local dnf_smtp_version=""

    if command -v rpm >/dev/null 2>&1; then
      rpm_smtp_version="$(rpm -q sendmail 2>/dev/null | head -n 1)"
    fi
    if command -v dnf >/dev/null 2>&1; then
      dnf_smtp_version="$(dnf list installed sendmail 2>/dev/null \
        | grep -v 'Installed Packages' \
        | awk '{print $2}' | head -n 1)"
    fi

    if [[ "$rpm_smtp_version" != *"$LATEST"* ]] && [[ "$dnf_smtp_version" != "$LATEST"* ]]; then
      status="취약"
      reason="메일 서비스 버전이 최신 버전(${LATEST})이 아닙니다(${detected_hint}; rpm=${rpm_smtp_version:-N/A}, dnf=${dnf_smtp_version:-N/A})."
    else
      status="양호"
      reason="메일 서비스 버전이 최신 기준(${LATEST})에 부합합니다(${detected_hint}; rpm=${rpm_smtp_version:-N/A}, dnf=${dnf_smtp_version:-N/A})."
    fi
  else
    status="양호"
    reason="SMTP/메일 서비스 사용 흔적이 없어 버전 점검 대상이 아니거나 영향이 없습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_46() {
  local code="U-46"
  local item="일반 사용자의 메일 서비스 실행 방지"
  local severity="상"
  local status="양호"
  local reason="Sendmail이 실행 중이지 않거나, 일반 사용자의 메일 서비스 실행 방지가 설정되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln=0
  local details=()

  if ps -ef 2>/dev/null | grep -v grep | grep -q "sendmail"; then
    if [ -f "/etc/mail/sendmail.cf" ]; then
      local check_line
      check_line="$(grep -i "PrivacyOptions" /etc/mail/sendmail.cf 2>/dev/null | grep -i "restrictqrun" | head -n 1)"
      if [ -z "$check_line" ]; then
        vuln=1
        details+=("Sendmail 실행 중이며 /etc/mail/sendmail.cf 에 restrictqrun 설정이 없습니다")
      fi
    else
      vuln=1
      details+=("Sendmail 실행 중이나 /etc/mail/sendmail.cf 설정파일이 존재하지 않습니다")
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="${details[0]}"
      local extra=$(( ${#details[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="일반 사용자의 메일 서비스 실행 방지 기준을 충족하지 않습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_47() {
  local code="U-47"
  local item="스팸메일 릴레이 제한"
  local severity="상"
  local status="양호"
  local reason="오픈 릴레이(open relay) 방지 설정이 적용되어 있거나, 메일 서비스를 사용하지 않습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln=0
  local details=()

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet postfix.service 2>/dev/null; then
      details+=("postfix.service active")
    fi
  fi

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
      reason="Postfix 설정에 reject_unauth_destination 이 포함되어 있고, mynetworks 가 과다(0.0.0.0/0, ::/0) 설정이 아닙니다."
      printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
        "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
      return 0
    fi

    vuln=1
    details+=("reject_unauth_destination 설정 누락 또는 mynetworks 과다(0.0.0.0/0, ::/0) 설정 가능성")
  fi

  if [ "$vuln" -eq 0 ]; then
    local sendmail_active=0
    if command -v systemctl >/dev/null 2>&1; then
      systemctl is-active --quiet sendmail.service 2>/dev/null && sendmail_active=1
    fi
    if [ "$sendmail_active" -eq 1 ] || command -v sendmail >/dev/null 2>&1; then
      status="양호"
      reason="Sendmail 사용 가능성이 있으나, 본 점검 로직에서는 오픈 릴레이 여부를 자동 확정하지 않아 취약으로 판정하지 않습니다."
      printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
        "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
      return 0
    fi
  fi

  if [ "$vuln" -eq 0 ]; then
    status="양호"
    reason="메일 서비스를 사용하지 않거나(Postfix/Sendmail 미사용), 점검 도구(postconf 등)가 없어 확인 대상이 아닙니다."
  else
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="${details[0]}"
      local extra=$(( ${#details[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="오픈 릴레이 방지 설정이 확인되지 않습니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_48() {
  local code="U-48"
  local item="expn, vrfy 명령어 제한"
  local severity="중"
  local status="양호"
  local reason="메일(SMTP) 서비스 사용 중이며 expn/vrfy 제한 설정이 확인되었습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
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
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local ok_cnt=0
  local bad_cnt=0

  if [ "$has_sendmail" -eq 1 ]; then
    local sendmail_ok=0
    local sendmail_cf_candidates=("/etc/mail/sendmail.cf" "/etc/sendmail.cf")
    local cf found_cf=""

    for cf in "${sendmail_cf_candidates[@]}"; do
      if [ -f "$cf" ]; then
        found_cf="$cf"

        local goaway_count noexpn_novrfy_count
        goaway_count="$(grep -vE '^\s*#' "$cf" 2>/dev/null | grep -iE 'PrivacyOptions' | grep -i 'goaway' | wc -l)"
        noexpn_novrfy_count="$(grep -vE '^\s*#' "$cf" 2>/dev/null | grep -iE 'PrivacyOptions' | grep -i 'noexpn' | grep -i 'novrfy' | wc -l)"

        if [ "$goaway_count" -gt 0 ] || [ "$noexpn_novrfy_count" -gt 0 ]; then
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
      evidences+=("sendmail: 실행 흔적은 있으나 sendmail.cf 파일을 찾지 못했습니다(설정 점검 불가)")
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
      postfix_vrfy="$(
        grep -vE '^\s*#' /etc/postfix/main.cf 2>/dev/null \
          | grep -iE '^\s*disable_vrfy_command\s*=\s*yes\s*$' | wc -l
      )"
      if [ "$postfix_vrfy" -gt 0 ]; then
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
      evidences+=("postfix: postfix 사용 흔적은 있으나 /etc/postfix/main.cf 파일이 없습니다(설정 점검 불가)")
    fi
  fi

  if [ "$has_exim" -eq 1 ]; then
    evidences+=("exim: exim 사용 흔적 감지(구성 파일 기반 vrfy/expn 제한 수동 확인 필요)")
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
      reason="메일(SMTP) 서비스 사용 중이며 expn/vrfy 제한 설정이 미흡합니다."
    fi
  else
    status="양호"
    reason="메일(SMTP) 서비스 사용 중이며 expn/vrfy 제한 설정이 확인되었습니다(ok=${ok_cnt})."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"

  return 0
}

U_49() {
  local code="U-49"
  local item="DNS 보안 버전 패치"
  local severity="상"
  local status="양호"
  local reason="DNS 서비스를 사용하지 않거나, BIND 관련 보안 업데이트 대기 항목이 확인되지 않습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local named_active=0
  local named_running=0
  local bind_ver=""
  local pending_sec=0

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
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  if command -v named >/dev/null 2>&1; then
    bind_ver="$(named -v 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  fi
  if [ -z "$bind_ver" ] && command -v rpm >/dev/null 2>&1; then
    bind_ver="$(rpm -q bind 2>/dev/null | grep -Eo '([0-9]+\.){2}[0-9]+' | head -n 1)"
  fi
  [ -z "$bind_ver" ] && bind_ver="unknown"

  if ! command -v dnf >/dev/null 2>&1; then
    status="취약"
    reason="DNS 서비스는 사용 중이나 dnf 미존재로 보안 패치 적용 여부를 확인할 수 없습니다(BIND=${bind_ver})."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  if dnf -q updateinfo list --updates security 2>/dev/null | grep -Eiq '(^|[[:space:]])bind([[:space:]]|-)'; then
    pending_sec=1
  else
    pending_sec=0
  fi

  if [ "$pending_sec" -eq 1 ]; then
    status="취약"
    reason="BIND 보안 업데이트(SECURITY) 미적용 대기 항목이 존재합니다(BIND=${bind_ver})."
  else
    status="양호"
    reason="DNS 서비스 사용 중이며 BIND 관련 보안 업데이트 대기 항목이 확인되지 않습니다(BIND=${bind_ver})."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"

  return 0
}


U_50() {
  local code="U-50"
  local item="DNS Zone Transfer 설정"
  local severity="상"
  local status="양호"
  local reason="Zone Transfer가 전체(any) 허용으로 설정되어 있지 않습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local dns_in_use=0

  if ps -ef 2>/dev/null | grep -i 'named' | grep -v 'grep' >/dev/null 2>&1; then
    dns_in_use=1
  fi

  if [ "$dns_in_use" -eq 1 ]; then
    if [ -f /etc/named.conf ]; then
      local bad_count
      bad_count="$(grep -vE '^#|^\s#' /etc/named.conf 2>/dev/null \
        | grep -i 'allow-transfer' \
        | grep -i 'any' \
        | wc -l)"
      if [ "${bad_count:-0}" -gt 0 ]; then
        status="취약"
        reason="/etc/named.conf 파일에 allow-transfer { any; } 와 유사한 전체 허용 설정이 존재합니다."
      fi
    else
      status="양호"
      reason="DNS(named) 사용 흔적은 있으나 /etc/named.conf 파일이 없어 Zone Transfer 설정을 확인할 수 없습니다."
    fi
  else
    status="양호"
    reason="DNS(named) 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_51() {
  local code="U-51"
  local item="DNS 서비스의 취약한 동적 업데이트 설정 금지"
  local severity="중"
  local status="양호"
  local reason="DNS(named) 서비스를 사용하지 않거나, 동적 업데이트(allow-update)가 전체(any) 허용으로 설정되어 있지 않습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln=0
  local findings=()

  if ps -ef 2>/dev/null | grep -v grep | grep -q "named"; then
    local CONF="/etc/named.conf"
    local CONF_FILES=("$CONF")

    if [ -f "$CONF" ]; then
      local extracted_paths in_file
      extracted_paths="$(grep -E '^\s*(include|file)\s*' "$CONF" 2>/dev/null | awk -F'"' '{print $2}' | awk 'NF')"
      for in_file in $extracted_paths; do
        if [ -f "$in_file" ]; then
          CONF_FILES+=("$in_file")
        elif [ -f "/etc/$in_file" ]; then
          CONF_FILES+=("/etc/$in_file")
        elif [ -f "/var/named/$in_file" ]; then
          CONF_FILES+=("/var/named/$in_file")
        fi
      done
    else
      findings+=("DNS(named) 실행 중이나 /etc/named.conf 파일이 존재하지 않습니다(점검 불가)")
      vuln=1
    fi

    local file
    for file in "${CONF_FILES[@]}"; do
      [ -f "$file" ] || continue
      local check
      check="$(grep -vE '^\s*//|^\s*#|^\s*/\*' "$file" 2>/dev/null \
        | grep -i "allow-update" \
        | grep -Ei 'any|\{\s*any\s*;\s*\}')"
      if [ -n "$check" ]; then
        vuln=1
        findings+=("${file} 파일에서 동적 업데이트(allow-update)가 전체(any) 허용으로 설정되어 있습니다")
      fi
    done
  else
    status="양호"
    reason="DNS(named) 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#findings[@]}" -gt 0 ]; then
      reason="${findings[0]}"
      local extra=$(( ${#findings[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="DNS 동적 업데이트 설정이 기준을 충족하지 않습니다."
    fi
  else
    status="양호"
    reason="DNS(named) 실행 중이나 allow-update 전체(any) 허용 설정이 발견되지 않았습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_52() {
  local code="U-52"
  local item="Telnet 서비스 비활성화"
  local severity="중"
  local status="양호"
  local reason="Telnet(23/tcp) 서비스가 비활성화되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln=0
  local details=()

  local listen23=""
  if command -v ss >/dev/null 2>&1; then
    listen23="$(ss -lntp 2>/dev/null | awk '$4 ~ /:23$/ {print}' | head -n 1)"
  elif command -v netstat >/dev/null 2>&1; then
    listen23="$(netstat -lntp 2>/dev/null | awk '$4 ~ /:23$/ {print}' | head -n 1)"
  fi
  if [ -n "$listen23" ]; then
    vuln=1
    details+=("23/tcp LISTEN 감지")
  fi

  if command -v systemctl >/dev/null 2>&1; then
    local units=("telnet.socket" "telnet.service" "telnet@.service" "telnetd.service")
    local u
    for u in "${units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$u"; then
        local is_act="inactive" is_en="disabled"
        systemctl is-active  --quiet "$u" 2>/dev/null && is_act="active"
        systemctl is-enabled --quiet "$u" 2>/dev/null && is_en="enabled"
        if [ "$is_act" = "active" ] || [ "$is_en" = "enabled" ]; then
          vuln=1
          details+=("${u} 상태: ${is_act}/${is_en}")
        fi
      fi
    done
  fi

  if [ -r /etc/xinetd.d/telnet ]; then
    local disabled=""
    disabled="$(awk 'tolower($1)=="disable"{print tolower($3)}' /etc/xinetd.d/telnet 2>/dev/null | tail -n 1)"
    if [ "$disabled" != "yes" ]; then
      vuln=1
      details+=("/etc/xinetd.d/telnet 존재: disable=${disabled:-unknown}")
    fi
  fi

  if [ -r /etc/inetd.conf ]; then
    if grep -Eq '^[[:space:]]*telnet[[:space:]]' /etc/inetd.conf 2>/dev/null; then
      vuln=1
      details+=("/etc/inetd.conf: telnet 설정 존재")
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="${details[0]}"
      local extra=$(( ${#details[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="Telnet 활성화 가능 징후가 확인되었습니다."
    fi
  else
    status="양호"
    reason="Telnet 활성화(23/tcp 리슨, systemd/xinetd/inetd 설정) 징후가 확인되지 않았습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_53() {
  local code="U-53"
  local item="FTP 서비스 정보 노출 제한"
  local severity="하"
  local status="양호"
  local reason="FTP 접속 배너에 서비스명/버전 등 불필요한 정보 노출 징후가 확인되지 않았습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local listen_info=""
  if command -v ss >/dev/null 2>&1; then
    listen_info="$(ss -ltnp 2>/dev/null | awk '$4 ~ /:21$/ {print}' | head -n 1)"
  elif command -v netstat >/dev/null 2>&1; then
    listen_info="$(netstat -ltnp 2>/dev/null | awk '$4 ~ /:21$/ {print}' | head -n 1)"
  fi

  if [ -z "$listen_info" ]; then
    status="N/A"
    reason="FTP 서비스(21/tcp)가 리스닝 상태가 아니므로 점검 대상이 아닙니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
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
    echo "$banner" | grep -Eqi '(vsftpd|proftpd|pure-?ftpd|wu-?ftpd|ftp server|version|[0-9]+\.[0-9]+(\.[0-9]+)?)' \
      && banner_leak=1
  fi

  if [ "$config_leak" -eq 1 ] || [ "$banner_leak" -eq 1 ]; then
    status="취약"
    if [ "$banner_leak" -eq 1 ] && [ -n "$banner" ]; then
      reason="FTP 배너에 서비스명/버전 등 정보가 노출됩니다: ${banner}"
    else
      reason="FTP 설정 또는 배너에서 서비스명/버전 등 정보 노출 가능성이 확인되었습니다."
    fi
  else
    status="양호"
    reason="FTP 접속 배너에 서비스명/버전 등 불필요한 정보 노출 징후가 확인되지 않았습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"

  return 0
}


U_54() {
  local code="U-54"
  local item="암호화되지 않는 FTP 서비스 비활성화"
  local severity="중"
  local status="양호"
  local reason="vsftpd/proftpd/xinetd/inetd 기반 FTP 서비스가 모두 비활성 상태입니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local ftp_active=0
  local why=()

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "vsftpd.service"; then
      if systemctl is-active --quiet vsftpd 2>/dev/null; then
        ftp_active=1
        why+=("vsftpd active")
      fi
    fi
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "proftpd.service"; then
      if systemctl is-active --quiet proftpd 2>/dev/null; then
        ftp_active=1
        why+=("proftpd active")
      fi
    fi
  fi

  if [ -f /etc/xinetd.d/ftp ]; then
    if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/xinetd.d/ftp 2>/dev/null \
      | grep -iq "disable[[:space:]]*=[[:space:]]*no"; then
      ftp_active=1
      why+=("xinetd ftp disable=no")
    fi
  fi

  if [ -f /etc/inetd.conf ]; then
    if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null | grep -iq "(^|[[:space:]])ftp([[:space:]]|$)"; then
      ftp_active=1
      why+=("inetd.conf ftp enabled")
    fi
  fi

  if [ "$ftp_active" -eq 1 ]; then
    status="취약"
    if [ "${#why[@]}" -gt 0 ]; then
      reason="${why[0]}"
      local extra=$(( ${#why[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="암호화되지 않은 FTP 서비스가 활성 상태입니다."
    fi
  else
    status="양호"
    reason="vsftpd/proftpd/xinetd/inetd 기반 FTP 서비스가 모두 비활성 상태입니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"

  return 0
}

U_55() {
  local code="U-55"
  local item="FTP 계정 Shell 제한"
  local severity="중"
  local status="양호"
  local reason="ftp 계정에 /bin/false 또는 nologin 쉘이 부여되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local has_rpm=0
  command -v rpm >/dev/null 2>&1 && has_rpm=1

  if [ "$has_rpm" -eq 1 ]; then
    if ! rpm -qa 2>/dev/null | grep -Eqi 'vsftpd|proftpd'; then
      status="양호"
      reason="FTP 서비스가 미설치되어 있습니다."
      printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
        "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
      return 0
    fi
  else
    :
  fi

  local ftp_users=("ftp" "vsftpd" "proftpd")
  local ftp_exist=0
  local ftp_vuln=0
  local bad_user=""
  local bad_shell=""

  local user shell
  for user in "${ftp_users[@]}"; do
    if id "$user" >/dev/null 2>&1; then
      ftp_exist=1
      shell="$(awk -F: -v u="$user" '$1==u{print $7}' /etc/passwd 2>/dev/null | head -n 1)"
      if [ "$shell" != "/bin/false" ] && [ "$shell" != "/sbin/nologin" ] && [ -n "$shell" ]; then
        ftp_vuln=1
        bad_user="$user"
        bad_shell="$shell"
        break
      fi
    fi
  done

  if [ "$ftp_exist" -eq 0 ]; then
    status="양호"
    reason="FTP 계정이 존재하지 않습니다."
  elif [ "$ftp_vuln" -eq 1 ]; then
    status="취약"
    if [ -n "$bad_user" ] && [ -n "$bad_shell" ]; then
      reason="FTP 계정(${bad_user})에 제한 쉘이 부여되어 있지 않습니다. (shell=${bad_shell})"
    else
      reason="FTP 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되어 있지 않습니다."
    fi
  else
    status="양호"
    reason="FTP 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되어 있습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_56() {
  local code="U-56"
  local item="FTP 서비스 접근 제어 설정"
  local severity="하"
  local status="양호"
  local reason="FTP 서비스 접근 제어 설정이 확인되지 않았거나, FTP 서비스를 사용하지 않습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln=0
  local why=()

  if ps -ef 2>/dev/null | grep -v grep | grep -q "vsftpd"; then
    local conf="/etc/vsftpd/vsftpd.conf"
    [ -f "$conf" ] || conf="/etc/vsftpd.conf"

    if [ -f "$conf" ]; then
      local userlist_enable
      userlist_enable="$(grep -vE '^\s*#' "$conf" 2>/dev/null \
        | grep -iE '^\s*userlist_enable\s*=' \
        | tail -n 1 | awk -F= '{gsub(/[[:space:]]/,"",$2); print toupper($2)}')"

      if [ "$userlist_enable" = "YES" ]; then
        if [ ! -f "/etc/vsftpd/user_list" ] && [ ! -f "/etc/vsftpd.user_list" ]; then
          vuln=1
          why+=("vsftpd(userlist_enable=YES) 사용 중이나 접근 제어 파일(user_list)이 없습니다.")
        fi
      else
        if [ ! -f "/etc/vsftpd/ftpusers" ] && [ ! -f "/etc/vsftpd.ftpusers" ]; then
          vuln=1
          why+=("vsftpd(userlist_enable!=YES) 사용 중이나 접근 제어 파일(ftpusers)이 없습니다.")
        fi
      fi
    else
      vuln=1
      why+=("vsftpd 서비스가 실행 중이나 설정 파일을 찾을 수 없습니다.")
    fi

  elif ps -ef 2>/dev/null | grep -v grep | grep -q "proftpd"; then
    local conf="/etc/proftpd.conf"
    [ -f "$conf" ] || conf="/etc/proftpd/proftpd.conf"

    if [ -f "$conf" ]; then
      local useftpusers
      useftpusers="$(grep -vE '^\s*#' "$conf" 2>/dev/null \
        | grep -iE '^\s*UseFtpUsers\b' \
        | tail -n 1 | awk '{print tolower($2)}')"

      if [ -z "$useftpusers" ] || [ "$useftpusers" = "on" ]; then
        if [ ! -f "/etc/ftpusers" ] && [ ! -f "/etc/ftpd/ftpusers" ]; then
          vuln=1
          why+=("proftpd(UseFtpUsers=on) 사용 중이나 접근 제어 파일(/etc/ftpusers)이 없습니다.")
        fi
      else
        if ! grep -iE '<Limit[[:space:]]+LOGIN>' "$conf" >/dev/null 2>&1; then
          vuln=1
          why+=("proftpd(UseFtpUsers=off) 사용 중이나 <Limit LOGIN> 접근 제어 설정이 없습니다.")
        fi
      fi
    else
      vuln=1
      why+=("proftpd 서비스가 실행 중이나 설정 파일을 찾을 수 없습니다.")
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#why[@]}" -gt 0 ]; then
      reason="${why[0]}"
      local extra=$(( ${#why[@]} - 1 ))
      if [ "$extra" -gt 0 ]; then
        reason="${reason} 외 ${extra}건"
      fi
    else
      reason="FTP 서비스 접근 제어 설정이 미흡합니다."
    fi
  else
    status="양호"
    reason="FTP 서비스 접근 제어 설정이 확인되었거나 FTP 서비스를 사용하지 않습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_57() {
  local code="U-57"
  local item="Ftpusers 파일 설정"
  local severity="중"
  local status="양호"
  local reason="FTP 사용 시 접속 금지 사용자(root 등)가 적절히 설정되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln=0

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
    reason="FTP 서비스가 비활성/미사용 상태입니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
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
    reason="FTP 사용 중이며 ftpusers/user_list 차단 파일을 찾지 못했습니다."
  else
    local has_root=0
    grep -Eq '^[[:space:]]*root([[:space:]]|$)' "$file_found" && has_root=1

    local owner perm oct
    owner="$(stat -Lc '%U' "$file_found" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$file_found" 2>/dev/null)"
    oct="0$perm"

    if [ "$owner" != "root" ]; then
      vuln=1
      reason="차단 파일 소유자가 root가 아닙니다(file=$file_found, owner=$owner)."
    elif (( (oct & 18) != 0 )); then
      vuln=1
      reason="차단 파일에 그룹/기타 쓰기 권한이 존재합니다(file=$file_found, perm=$perm)."
    elif [ "$has_root" -eq 0 ]; then
      vuln=1
      reason="차단 파일에 root 계정이 포함되어 있지 않습니다(file=$file_found)."
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
  else
    status="양호"
    reason="FTP 사용 중이며 차단 파일이 존재하고(root 포함), 파일 소유/권한이 적절합니다(file=$file_found)."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_58() {
  local code="U-58"
  local item="불필요한 SNMP 서비스 구동 점검"
  local severity="중"
  local status="양호"
  local reason="SNMP 서비스를 사용하지 않습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local found=0

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "snmpd.service"; then
      if systemctl is-active --quiet snmpd.service 2>/dev/null || systemctl is-enabled --quiet snmpd.service 2>/dev/null; then
        found=1
      fi
    fi

    if [ "$found" -eq 0 ] && systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "snmptrapd.service"; then
      if systemctl is-active --quiet snmptrapd.service 2>/dev/null || systemctl is-enabled --quiet snmptrapd.service 2>/dev/null; then
        found=1
      fi
    fi
  fi

  if [ "$found" -eq 0 ] && command -v pgrep >/dev/null 2>&1; then
    if pgrep -x snmpd >/dev/null 2>&1 || pgrep -x snmptrapd >/dev/null 2>&1; then
      found=1
    fi
  fi

  if [ "$found" -eq 0 ] && command -v ss >/dev/null 2>&1; then
    if ss -lunp 2>/dev/null | awk '$5 ~ /:(161|162)$/ {print; exit 0} END{exit 1}' >/dev/null 2>&1; then
      found=1
    fi
  fi

  if [ "$found" -eq 1 ]; then
    status="취약"
    reason="SNMP 서비스를 사용하고 있습니다."
  else
    status="양호"
    reason="SNMP 서비스가 비활성화되어 있습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_59() {
  local code="U-59"
  local item="안전한 SNMP 버전 사용"
  local severity="상"
  local status="양호"
  local reason="SNMP 서비스(snmpd)가 비활성 상태입니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local snmp_active=0
  if systemctl is-active --quiet snmpd 2>/dev/null; then
    snmp_active=1
  fi

  if [ "$snmp_active" -eq 0 ]; then
    status="양호"
    reason="SNMP 서비스(snmpd)가 비활성 상태입니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local v1v2_found=0
  local v3_valid=0
  local cfg_files=("/etc/snmp/snmpd.conf" "/var/lib/net-snmp/snmpd.conf")

  local f
  for f in "${cfg_files[@]}"; do
    [ -f "$f" ] || continue

    if grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -Ei 'rocommunity|rwcommunity|com2sec' >/dev/null; then
      v1v2_found=1
    fi

    if grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -Ei 'rouser|rwuser|createUser' | grep -Ei 'SHA|AES' >/dev/null; then
      v3_valid=1
    fi
  done

  if [ "$v1v2_found" -eq 1 ]; then
    status="취약"
    reason="SNMP v1/v2c 취약 설정(rocommunity/rwcommunity/com2sec)이 발견되었습니다."
  elif [ "$v3_valid" -eq 1 ]; then
    status="양호"
    reason="SNMPv3 보안 설정(rouser/rwuser/createUser 및 SHA/AES)이 확인되었습니다."
  else
    status="취약"
    reason="SNMP 서비스는 사용 중이나 SNMPv3 보안 설정(SHA/AES)이 미흡합니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_60() {
  local code="U-60"
  local item="SNMP Community String 복잡성 설정"
  local severity="중"
  local status="양호"
  local reason="SNMP 서비스가 미설치되어있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln_flag=0
  local community_found=0

  local ps_snmp_count
  ps_snmp_count="$(ps -ef 2>/dev/null | grep -iE 'snmpd|snmptrapd' | grep -v 'grep' | wc -l)"
  if [ "${ps_snmp_count:-0}" -eq 0 ]; then
    status="양호"
    reason="SNMP 서비스가 미설치되어있습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local -a snmpdconf_files=()
  [ -f /etc/snmp/snmpd.conf ] && snmpdconf_files+=("/etc/snmp/snmpd.conf")
  [ -f /usr/local/etc/snmp/snmpd.conf ] && snmpdconf_files+=("/usr/local/etc/snmp/snmpd.conf")

  local f
  while IFS= read -r f; do
    snmpdconf_files+=("$f")
  done < <(find /etc -maxdepth 4 -type f -name 'snmpd.conf' 2>/dev/null | sort -u)

  if [ "${#snmpdconf_files[@]}" -gt 0 ]; then
    mapfile -t snmpdconf_files < <(printf "%s\n" "${snmpdconf_files[@]}" | awk '!seen[$0]++')
  fi

  if [ "${#snmpdconf_files[@]}" -eq 0 ]; then
    status="취약"
    reason="SNMP 서비스를 사용하고, Community String을 설정하는 파일(snmpd.conf)이 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
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

  local i comm
  for ((i=0; i<${#snmpdconf_files[@]}; i++)); do
    while IFS= read -r comm; do
      [ -n "$comm" ] || continue
      community_found=1
      if ! is_strong_community "$comm"; then
        vuln_flag=1
      fi
    done < <(
      grep -vE '^\s*#|^\s*$' "${snmpdconf_files[$i]}" 2>/dev/null \
        | awk 'tolower($1) ~ /^(rocommunity6?|rwcommunity6?)$/ {print $2}'
    )

    while IFS= read -r comm; do
      [ -n "$comm" ] || continue
      community_found=1
      if ! is_strong_community "$comm"; then
        vuln_flag=1
      fi
    done < <(
      grep -vE '^\s*#|^\s*$' "${snmpdconf_files[$i]}" 2>/dev/null \
        | awk 'tolower($1)=="com2sec" {print $4}'
    )
  done

  if [ "$community_found" -eq 0 ]; then
    status="취약"
    reason="SNMP 서비스를 사용하나 Community String 설정(rocommunity/rwcommunity/com2sec)을 확인할 수 없습니다."
  elif [ "$vuln_flag" -eq 1 ]; then
    status="취약"
    reason="SNMP Community String이 public/private 이거나 복잡성 기준을 만족하지 않습니다."
  else
    status="양호"
    reason="SNMP Community String이 복잡성 기준을 만족합니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_61() {
  local code="U-61"
  local item="SNMP Access Control 설정"
  local severity="상"
  local status="양호"
  local reason="SNMP 서비스(snmpd)가 비활성 상태입니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local VULN=0
  local REASON=""

  if ps -ef 2>/dev/null | grep -v grep | grep -q "snmpd"; then
    local CONF="/etc/snmp/snmpd.conf"

    if [ -f "$CONF" ]; then
      local CHECK_COM2SEC
      CHECK_COM2SEC="$(grep -vE "^\s*#" "$CONF" 2>/dev/null | grep -E "^\s*com2sec" | awk '$3=="default" {print $0}')"

      local CHECK_COMM
      CHECK_COMM="$(grep -vE "^\s*#" "$CONF" 2>/dev/null | grep -Ei "^\s*(ro|rw)community6?|^\s*(ro|rw)user")"

      local IS_COMM_VULN=0
      if [ -n "$CHECK_COMM" ]; then
        while IFS= read -r line; do
          [ -n "$line" ] || continue
          local COMM_STR SOURCE_IP
          COMM_STR="$(echo "$line" | awk '{print $2}')"
          SOURCE_IP="$(echo "$line" | awk '{print $3}')"

          if [[ "$SOURCE_IP" == "default" ]] || [[ "$COMM_STR" =~ public|private ]]; then
            IS_COMM_VULN=1
            break
          fi
        done <<< "$CHECK_COMM"
      fi

      if [ -n "$CHECK_COM2SEC" ] || [ "$IS_COMM_VULN" -eq 1 ]; then
        VULN=1
        REASON="SNMP 설정 파일($CONF)에 모든 호스트 접근을 허용하는 설정이 존재합니다."
      fi
    else
      VULN=1
      REASON="SNMP 서비스가 실행 중이고, 설정 파일($CONF)을 찾을 수 없습니다."
    fi
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  else
    status="양호"
    if ps -ef 2>/dev/null | grep -v grep | grep -q "snmpd"; then
      reason="SNMP 서비스에 대한 접근 제어 설정의 취약 징후가 확인되지 않았습니다."
    else
      reason="SNMP 서비스(snmpd)가 비활성 상태입니다."
    fi
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}


U_62() {
  local code="U-62"
  local item="로그인 시 경고 메시지 설정"
  local severity="하"
  local status="취약"
  local reason="로그인 배너(/etc/issue, /etc/issue.net, SSH Banner)에서 비인가 사용 금지 경고 문구를 확인하지 못했습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
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
    reason="로그인 배너(/etc/issue, /etc/issue.net, SSH Banner)에 비인가 사용 금지 경고 문구가 설정되어 있습니다."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_63() {
  local code="U-63"
  local item="sudo 명령어 접근 관리"
  local severity="중"
  local status="양호"
  local reason="/etc/sudoers 파일 소유자가 root이고, 파일 권한이 640입니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  if [ ! -e /etc/sudoers ]; then
    status="N/A"
    reason="/etc/sudoers 파일이 존재하지 않아 점검 대상이 아닙니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  local owner perm
  owner="$(stat -c %U /etc/sudoers 2>/dev/null)"
  perm="$(stat -c %a /etc/sudoers 2>/dev/null)"

  if [ -z "$owner" ] || [ -z "$perm" ]; then
    status="점검불가"
    reason="/etc/sudoers 권한 정보를 숫자(예: 640)로 확인할 수 없습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
    return 0
  fi

  if [ "$owner" = "root" ] && [ "$perm" = "640" ]; then
    status="양호"
    reason="/etc/sudoers 소유자: ${owner}, 권한: ${perm}"
  else
    status="취약"
    reason="/etc/sudoers 소유자 또는 권한이 기준에 부합하지 않습니다. (현재 소유자=${owner}, 권한=${perm}; 기준: owner=root, perm=640)"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
}

U_64() {
  local code="U-64"
  local item="주기적 보안 패치 및 벤더 권고사항 적용"
  local severity="상"
  local status="양호"
  local reason="보안 업데이트 미적용 항목이 없고 최신 커널로 부팅되어 있습니다."

  _json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
  }

  local vuln=0
  local details=()

  if command -v dnf >/dev/null 2>&1; then
    local security_updates
    security_updates="$(dnf updateinfo list security 2>/dev/null | grep -v -E 'Last metadata|메타자료|^$' || true)"

    if [ -n "$security_updates" ]; then
      vuln=1
      details+=("보안 업데이트 미적용 항목이 존재합니다(dnf updateinfo list security 기준).")
    fi
  else
    vuln=1
    details+=("dnf 명령이 없어 보안 업데이트 대기 여부를 확인할 수 없습니다.")
  fi

  local running_kernel latest_kernel
  running_kernel="$(uname -r 2>/dev/null)"

  if command -v rpm >/dev/null 2>&1; then
    latest_kernel="$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -1)"
  else
    latest_kernel=""
  fi

  if [ -n "$latest_kernel" ] && [ -n "$running_kernel" ]; then
    if [ "$running_kernel" != "$latest_kernel" ]; then
      vuln=1
      details+=("최신 커널로 재부팅 필요: running=${running_kernel}, latest=${latest_kernel}.")
    fi
  elif [ -z "$latest_kernel" ]; then
    vuln=1
    details+=("최신 커널 설치 목록을 확인할 수 없습니다(rpm kernel 조회 실패).")
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="$(printf '%s ' "${details[@]}")"
    reason="${reason% }"
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$(_json_escape "$item")" "$severity" "$status" "$(_json_escape "$reason")"
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
