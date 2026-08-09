#!/bin/bash

U_01() {
  local code="U-01"
  local item="root 계정 원격접속 제한"
  local severity="상"
  local status="양호"
  local reason="원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속이 차단되어 있습니다."

  local VULN=0
  local REASON=""

  local BAD_SERVICES=("telnet.socket" "rsh.socket" "rlogin.socket" "rexec.socket")

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
    local telnet_running=0

    if ps -ef | grep -i '[t]elnet' &>/dev/null; then
      telnet_running=1
    fi

    if [ "$telnet_running" -eq 0 ]; then
      if command -v netstat >/dev/null 2>&1; then
        if netstat -nat 2>/dev/null | grep -w 'tcp' | grep -i 'LISTEN' | grep -q ':23 '; then
          telnet_running=1
        fi
      elif command -v ss >/dev/null 2>&1; then
        if ss -lnt 2>/dev/null | awk 'NR>1{print $4}' | grep -qE '(:|\])23$'; then
          telnet_running=1
        fi
      fi
    fi

    if [ "$telnet_running" -eq 1 ]; then
      if [ -f /etc/pam.d/login ]; then
        if ! grep -vE '^#|^\s#' /etc/pam.d/login | grep -qi 'pam_securetty\.so'; then
          VULN=1
          REASON="Telnet 서비스 사용 중이며, /etc/pam.d/login에 pam_securetty.so 설정이 없습니다."
        fi
      else
        VULN=1
        REASON="Telnet 서비스 사용 중이나 /etc/pam.d/login 파일이 없어 pam_securetty.so 적용 여부를 확인할 수 없습니다."
      fi

      if [ "$VULN" -eq 0 ]; then
        if [ -f /etc/securetty ]; then
          if grep -vE '^#|^\s#' /etc/securetty | grep -qE '^[[:space:]]*pts'; then
            VULN=1
            REASON="Telnet 서비스 사용 중이며, /etc/securetty에 pts 터미널이 허용되어 있습니다."
          fi
        else
          VULN=1
          REASON="Telnet 서비스 사용 중이나 /etc/securetty 파일이 없어 pts 허용 여부를 확인할 수 없습니다."
        fi
      fi
    fi
  fi

  if [ "$VULN" -eq 0 ] && (systemctl is-active sshd &>/dev/null || ps -ef | grep -q '[s]shd'); then
    local ROOT_LOGIN=""
    ROOT_LOGIN="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitrootlogin"{print $2; exit}')"

    if [ -z "$ROOT_LOGIN" ]; then
      VULN=1
      REASON="SSH 설정(PermitRootLogin)을 확인할 수 없습니다 (sshd -T 실패 또는 결과 없음)."
    elif [ "$ROOT_LOGIN" != "no" ]; then
      VULN=1
      REASON="SSH root 접속이 허용 중입니다 (PermitRootLogin: $ROOT_LOGIN)."
    fi
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  fi

  _json_escape_u01() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u01 "$code")" \
    "$(_json_escape_u01 "$item")" \
    "$(_json_escape_u01 "$severity")" \
    "$(_json_escape_u01 "$status")" \
    "$(_json_escape_u01 "$reason")"
}

U_02() {
  local code="U-02"
  local item="비밀번호 관리정책 설정"
  local severity="상"
  local status="양호"
  local reason="PASS_MAX_DAYS, PASS_MIN_DAYS, 비밀번호 최소 길이, 복잡성, 재사용 제한 정책이 기준을 충족합니다."

  local TARGET_PASS_MAX_DAYS=90
  local TARGET_PASS_MIN_DAYS=1
  local TARGET_MINLEN=8
  local TARGET_REMEMBER=4

  local vuln=0
  local reasons=()
  local pass_max pass_min
  pass_max="$(awk 'BEGIN{v=""} $1=="PASS_MAX_DAYS"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"
  pass_min="$(awk 'BEGIN{v=""} $1=="PASS_MIN_DAYS"{v=$2} END{print v}' /etc/login.defs 2>/dev/null)"

  if [[ -z "$pass_max" || "$pass_max" -gt "$TARGET_PASS_MAX_DAYS" ]]; then
    vuln=1
    reasons+=("/etc/login.defs: PASS_MAX_DAYS가 기준(<=${TARGET_PASS_MAX_DAYS})을 충족하지 않습니다. (현재: ${pass_max:-미설정})")
  fi
  if [[ -z "$pass_min" || "$pass_min" -lt "$TARGET_PASS_MIN_DAYS" ]]; then
    vuln=1
    reasons+=("/etc/login.defs: PASS_MIN_DAYS가 기준(>=${TARGET_PASS_MIN_DAYS})을 충족하지 않습니다. (현재: ${pass_min:-미설정})")
  fi
  local minlen="" minclass="" remember=""
  local has_credit=0

  if [[ -r /etc/security/pwquality.conf ]]; then
    minlen="$(awk -F= 'tolower($1)~"minlen"{gsub(/[[:space:]]/,"",$2); v=$2} END{print v}' /etc/security/pwquality.conf 2>/dev/null)"
    minclass="$(awk -F= 'tolower($1)~"minclass"{gsub(/[[:space:]]/,"",$2); v=$2} END{print v}' /etc/security/pwquality.conf 2>/dev/null)"
  fi

  local pamline
  for f in "/etc/pam.d/system-auth" "/etc/pam.d/password-auth"; do
    [[ -r "$f" ]] || continue

    pamline="$(grep -E '^[[:space:]]*password[[:space:]]+.*pam_pwquality\.so' "$f" 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -n 1)"
    if [[ -n "$pamline" ]]; then
      [[ -z "$minlen" ]] && minlen="$(echo "$pamline" | sed -nE 's/.*minlen=([0-9]+).*/\1/p')"
      [[ -z "$minclass" ]] && minclass="$(echo "$pamline" | sed -nE 's/.*minclass=([0-9]+).*/\1/p')"
      echo "$pamline" | grep -Eq '(ucredit=|lcredit=|dcredit=|ocredit=)' && has_credit=1
    fi

    pamline="$(grep -E '^[[:space:]]*password[[:space:]]+.*pam_pwhistory\.so' "$f" 2>/dev/null | grep -vE '^[[:space:]]*#' | tail -n 1)"
    if [[ -n "$pamline" ]]; then
      remember="$(echo "$pamline" | sed -nE 's/.*remember=([0-9]+).*/\1/p')"
    fi
  done

  if [[ -z "$minlen" || "$minlen" -lt "$TARGET_MINLEN" ]]; then
    vuln=1
    reasons+=("비밀번호 최소 길이(minlen)가 기준(>=${TARGET_MINLEN})을 충족하지 않습니다. (현재: ${minlen:-미설정})")
  fi

  if [[ -n "$minclass" ]]; then
    if [[ "$minclass" -lt 3 ]]; then
      vuln=1
      reasons+=("비밀번호 복잡성(minclass)이 기준(>=3)을 충족하지 않습니다. (현재: $minclass)")
    fi
  else
    if [[ "$has_credit" -eq 0 ]]; then
      vuln=1
      reasons+=("비밀번호 복잡성(minclass 또는 u/l/d/o credit) 설정을 확인할 수 없습니다.")
    fi
  fi

  if [[ -z "$remember" || "$remember" -lt "$TARGET_REMEMBER" ]]; then
    vuln=1
    reasons+=("비밀번호 재사용 제한(remember)이 기준(>=${TARGET_REMEMBER})을 충족하지 않습니다. (현재: ${remember:-미설정})")
  fi

  if (( vuln == 1 )); then
    status="취약"
    local r="${reasons[0]:-기준 미충족}"
    r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if (( ${#r} > 250 )); then r="${r:0:250}..."; fi
    reason="$r"
  fi

  _json_escape_u02() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u02 "$code")" \
    "$(_json_escape_u02 "$item")" \
    "$(_json_escape_u02 "$severity")" \
    "$(_json_escape_u02 "$status")" \
    "$(_json_escape_u02 "$reason")"
}


U_03() {
  local code="U-03"
  local item="계정 잠금 임계값 설정"
  local severity="상"
  local status="양호"
  local reason="계정 잠금 임계값이 10회 이하로 설정되어 있습니다."

  local ca="/etc/pam.d/common-auth"
  local cc="/etc/pam.d/common-account"

  local vuln=0
  local reasons=()

  _u03_lines() {
    local f="$1"
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" 2>/dev/null
  }

  _u03_starts_with() {
    local line="$1"
    local word="$2"
    echo "$line" | grep -qiE "^[[:space:]]*${word}[[:space:]]+"
  }

  _u03_has_all_tokens() {
    local line="$1"; shift
    local t
    for t in "$@"; do
      echo "$line" | grep -qi -- "$t" || return 1
    done
    return 0
  }

  if [[ ! -f "$ca" || ! -f "$cc" ]]; then
    vuln=1
    reasons+=("필수 PAM 파일이 없습니다. ($ca 또는 $cc 미존재)")
  else
    local tally_auth_ok=0
    local tally_acct_ok=0
    local line

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if _u03_starts_with "$line" "auth" \
        && echo "$line" | grep -Eqi 'pam_tally2\.so|pam_tally\.so' \
        && echo "$line" | grep -qi 'required' \
        && _u03_has_all_tokens "$line" "deny=10" "unlock_time=120" "no_magic_root"; then
        tally_auth_ok=1
        break
      fi
    done < <(_u03_lines "$ca")

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if _u03_starts_with "$line" "account" \
        && echo "$line" | grep -Eqi 'pam_tally2\.so|pam_tally\.so' \
        && echo "$line" | grep -qi 'required' \
        && _u03_has_all_tokens "$line" "no_magic_root" "reset"; then
        tally_acct_ok=1
        break
      fi
    done < <(_u03_lines "$cc")

    local tally_ok=0
    if [[ "$tally_auth_ok" -eq 1 && "$tally_acct_ok" -eq 1 ]]; then
      tally_ok=1
    fi

    local fl_preauth_ok=0
    local fl_authfail_ok=0
    local fl_authsucc_ok=0
    local fl_account_ok=0

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if _u03_starts_with "$line" "auth" \
        && echo "$line" | grep -qi 'pam_faillock\.so' \
        && _u03_has_all_tokens "$line" "preauth" "audit" "deny=10" "unlock_time=120"; then
        fl_preauth_ok=1
      fi
      if _u03_starts_with "$line" "auth" \
        && echo "$line" | grep -qi 'pam_faillock\.so' \
        && _u03_has_all_tokens "$line" "authfail" "audit" "deny=10" "unlock_time=120"; then
        fl_authfail_ok=1
      fi
      if _u03_starts_with "$line" "auth" \
        && echo "$line" | grep -qi 'pam_faillock\.so' \
        && _u03_has_all_tokens "$line" "authsucc" "audit" "deny=10" "unlock_time=120"; then
        fl_authsucc_ok=1
      fi
    done < <(_u03_lines "$ca")

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if _u03_starts_with "$line" "account" \
        && echo "$line" | grep -qi 'pam_faillock\.so' \
        && echo "$line" | grep -qi 'required'; then
        fl_account_ok=1
        break
      fi
    done < <(_u03_lines "$cc")

    local faillock_ok=0
    if [[ "$fl_preauth_ok" -eq 1 && "$fl_authfail_ok" -eq 1 && "$fl_authsucc_ok" -eq 1 && "$fl_account_ok" -eq 1 ]]; then
      faillock_ok=1
    fi

    if [[ "$tally_ok" -eq 1 || "$faillock_ok" -eq 1 ]]; then
      vuln=0
    else
      vuln=1
      reasons+=("가이드 Step 패턴과 일치하는 설정이 없습니다. (common-auth/common-account에 pam_tally(2) 또는 pam_faillock 설정이 예시와 동일 옵션으로 존재해야 함)")
    fi
  fi

  if (( vuln == 1 )); then
    status="취약"
    local r="${reasons[0]:-기준 미충족}"
    r="$(echo "$r" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if (( ${#r} > 250 )); then r="${r:0:250}..."; fi
    reason="$r"
  fi

  _json_escape_u03() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u03 "$code")" \
    "$(_json_escape_u03 "$item")" \
    "$(_json_escape_u03 "$severity")" \
    "$(_json_escape_u03 "$status")" \
    "$(_json_escape_u03 "$reason")"
}

U_04() {
  local code="U-04"
  local item="패스워드 파일 보호"
  local severity="상"
  local status="양호"
  local reason="shadow 패스워드를 사용하고 있으며, /etc/shadow 파일이 존재합니다."

  local VULN_COUNT=0
  local VULN_USERS=""

  if [ -f /etc/passwd ]; then
    VULN_COUNT="$(awk -F: '$2 != "x" && $2 != "!!" && $2 != "*"' /etc/passwd 2>/dev/null | wc -l | tr -d ' ')"
    if [ "$VULN_COUNT" -gt 0 ]; then
      VULN_USERS="$(awk -F: '$2 != "x" && $2 != "!!" && $2 != "*"' /etc/passwd 2>/dev/null | cut -d: -f1 | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
      status="취약"
      reason="/etc/passwd 파일에 shadow 패스워드를 사용하지 않는 계정이 존재: ${VULN_USERS:-확인불가}"
    else
      if [ ! -f /etc/shadow ]; then
        status="취약"
        reason="/etc/shadow 파일이 존재하지 않습니다."
      fi
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  _json_escape_u04() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u04 "$code")" \
    "$(_json_escape_u04 "$item")" \
    "$(_json_escape_u04 "$severity")" \
    "$(_json_escape_u04 "$status")" \
    "$(_json_escape_u04 "$reason")"
}

U_05() {
  local code="U-05"
  local item="root 이외의 UID가 '0' 금지"
  local severity="상"
  local status="양호"
  local reason="root 계정과 동일한 UID(0)를 갖는 계정이 존재하지 않습니다."

  local dup_users=""

  if [ -f /etc/passwd ]; then
    dup_users="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | grep -vx 'root' || true)"
    if [ -n "$dup_users" ]; then
      status="취약"
      reason="root 외 UID 0 계정 발견: ${dup_users}"
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  fi

  _json_escape_u05() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u05 "$code")" \
    "$(_json_escape_u05 "$item")" \
    "$(_json_escape_u05 "$severity")" \
    "$(_json_escape_u05 "$status")" \
    "$(_json_escape_u05 "$reason")"
}

U_06() {
  local code="U-06"
  local item="사용자 계정 su 기능 제한"
  local severity="상"
  local status="양호"
  local reason="su 명령어가 특정 그룹(pam_wheel) 사용자로 제한되어 있습니다."

  local VULN=0
  local REASON=""
  local PAM_SU="/etc/pam.d/su"

  if [ -f "$PAM_SU" ]; then
    local SU_RESTRICT=""
    SU_RESTRICT="$(grep -vE '^#|^[[:space:]]*#' "$PAM_SU" 2>/dev/null | grep -E 'pam_wheel\.so' | grep -E 'use_uid' || true)"

    if [ -z "$SU_RESTRICT" ]; then
      VULN=1
      REASON="/etc/pam.d/su 파일에 pam_wheel.so 모듈 설정이 없거나 주석 처리되어 있습니다."
    fi
  else
    VULN=1
    REASON="$PAM_SU 파일이 존재하지 않습니다."
  fi

  local USER_COUNT=0
  if [ -f /etc/passwd ]; then
    USER_COUNT="$(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd 2>/dev/null | wc -l | tr -d ' ')"
  fi

  if [ "$VULN" -eq 1 ] && [ "$USER_COUNT" -eq 0 ]; then
    VULN=0
    REASON="일반 사용자 계정 없이 root 계정만 사용하여 su 명령어 사용 제한이 불필요합니다."
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  fi

  _json_escape_u06() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u06 "$code")" \
    "$(_json_escape_u06 "$item")" \
    "$(_json_escape_u06 "$severity")" \
    "$(_json_escape_u06 "$status")" \
    "$(_json_escape_u06 "$reason")"
}

U_07() {
  local code="U-07"
  local item="불필요한 계정 제거"
  local severity="하"
  local status="양호"
  local reason="불필요한 시스템 계정이 존재하지 않습니다."

  local vuln=0
  local _reason=""

  local system_shells=""
  system_shells="$(awk '!/^(#|$)/ && $1!~/nologin|false/ {print $1}' /etc/shells 2>/dev/null | paste -sd'|' -)"

  if [[ -z "$system_shells" ]]; then
    vuln=1
    _reason="불필요 계정 기준/로그인 가능 쉘 판별이 애매하여 자동 판단이 어려움 (확인 필요)"
  else
    local system_users=""
    system_users="$(awk -F: -v shells="|'"$system_shells"'$" \
      '($3<1000 && $1!="root") && $7 ~ shells {print $1 "(uid="$3",shell="$7")"}' \
      /etc/passwd 2>/dev/null)"

    if [[ -n "$system_users" ]]; then
      vuln=1
      _reason="로그인 가능한 시스템 계정 존재: $(echo "$system_users" | paste -sd', ' -) (확인 필요)"
    else
      vuln=1
      _reason="불필요 계정의 정의가 환경/정책에 따라 달라 자동으로 양호 확정 불가 (확인 필요)"
    fi
  fi

  if (( vuln == 1 )); then
    status="취약"
    _reason="$(echo "$_reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if (( ${#_reason} > 250 )); then _reason="${_reason:0:250}..."; fi
    reason="$_reason"
  fi

  _json_escape_u07() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u07 "$code")" \
    "$(_json_escape_u07 "$item")" \
    "$(_json_escape_u07 "$severity")" \
    "$(_json_escape_u07 "$status")" \
    "$(_json_escape_u07 "$reason")"
}


U_08() {
  local code="U-08"
  local item="관리자 권한(그룹/ sudoers) 최소화"
  local severity="중"
  local status="양호"
  local reason="root 외 관리자 계정이 1명 이하이며, 불필요/임시 관리자 계정이 없습니다."

  _user_exists() { id "$1" >/dev/null 2>&1; }

  local ADMIN_GROUP="sudo"
  local offenders=()
  local suspicious=""

  if [ ! -f /etc/group ]; then
    status="취약"
    reason="/etc/group 파일이 없습니다."
  else
    if getent group "$ADMIN_GROUP" >/dev/null 2>&1; then
      local MEMBERS=""
      MEMBERS="$(getent group "$ADMIN_GROUP" | awk -F: '{print $4}')"

      local u
      for u in $(echo "$MEMBERS" | tr ',' ' '); do
        [ -z "$u" ] && continue
        [ "$u" = "root" ] && continue
        _user_exists "$u" || continue
        offenders+=("$u")
      done
    fi

    if [ -f /etc/sudoers ]; then
      while read -r line; do
        local token=""
        token="$(echo "$line" | awk '{print $1}')"

        [ -z "$token" ] && continue

        if [[ "$token" == %* || "$token" == "root" ]]; then
          continue
        fi

        if _user_exists "$token"; then
          offenders+=("$token")
        fi
      done < <(grep -Ev '^\s*#|^\s*$|^\s*Defaults' /etc/sudoers 2>/dev/null)
    fi

    if [ "${#offenders[@]}" -gt 0 ]; then
      mapfile -t offenders < <(printf "%s\n" "${offenders[@]}" | sort -u)
    fi

    local admin_count=0
    admin_count="${#offenders[@]}"

    local u2
    for u2 in "${offenders[@]}"; do
      if echo "$u2" | grep -Eiq 'test|temp|guest'; then
        suspicious="$suspicious $u2"
      fi
    done
    suspicious="$(echo "$suspicious" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

    if [ "$admin_count" -eq 0 ]; then
      status="양호"
      reason="root 외 관리자 계정이 존재하지 않습니다."
    elif [ "$admin_count" -eq 1 ] && [ -z "$suspicious" ]; then
      status="양호"
      reason="단일 관리자 계정만 존재합니다: ${offenders[*]}"
    else
      status="취약"
      if [ -n "$suspicious" ]; then
        reason="불필요/임시 관리자 계정 존재: $suspicious"
      else
        reason="root 외 관리자 계정이 2명 이상입니다: ${offenders[*]}"
      fi
    fi
  fi

  _json_escape_u08() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u08 "$code")" \
    "$(_json_escape_u08 "$item")" \
    "$(_json_escape_u08 "$severity")" \
    "$(_json_escape_u08 "$status")" \
    "$(_json_escape_u08 "$reason")"
}

U_09() {
  local code="U-09"
  local item="계정이 존재하지 않는 GID 금지"
  local severity="하"
  local status="양호"
  local reason="계정이 존재하지 않는 불필요한 그룹(GID 1000 이상)이 존재하지 않습니다."

  local VULN_GROUPS=""

  if [ ! -f /etc/passwd ]; then
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  elif [ ! -f /etc/group ]; then
    status="취약"
    reason="/etc/group 파일이 존재하지 않아 점검할 수 없습니다."
  else
    local USED_GIDS=""
    USED_GIDS="$(awk -F: '{print $4}' /etc/passwd 2>/dev/null | sort -u)"

    local CHECK_GIDS=""
    CHECK_GIDS="$(awk -F: '$3 >= 1000 {print $3}' /etc/group 2>/dev/null)"

    local gid
    for gid in $CHECK_GIDS; do
      if ! echo "$USED_GIDS" | grep -qxw "$gid"; then
        local MEMBER_EXISTS=""
        MEMBER_EXISTS="$(awk -F: -v g="$gid" '$3==g{print $4}' /etc/group 2>/dev/null)"

        if [ -z "$MEMBER_EXISTS" ]; then
          local GROUP_NAME=""
          GROUP_NAME="$(awk -F: -v g="$gid" '$3==g{print $1}' /etc/group 2>/dev/null | head -n 1)"
          [ -z "$GROUP_NAME" ] && GROUP_NAME="(unknown)"
          VULN_GROUPS="$VULN_GROUPS $GROUP_NAME($gid)"
        fi
      fi
    done

    VULN_GROUPS="$(echo "$VULN_GROUPS" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

    if [ -n "$VULN_GROUPS" ]; then
      status="취약"
      reason="계정이 존재하지 않는 불필요한 그룹(GID 1000 이상) 존재: $VULN_GROUPS"
    fi
  fi

  _json_escape_u09() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u09 "$code")" \
    "$(_json_escape_u09 "$item")" \
    "$(_json_escape_u09 "$severity")" \
    "$(_json_escape_u09 "$status")" \
    "$(_json_escape_u09 "$reason")"
}


U_10() {
  local code="U-10"
  local item="동일한 UID 금지"
  local severity="중"
  local status="양호"
  local reason="동일한 UID로 설정된 사용자 계정이 존재하지 않습니다."

  if [ -f /etc/passwd ]; then
    local dup_uids=""
    local dup_uid_count=0

    dup_uids="$(awk -F: '{print $3}' /etc/passwd 2>/dev/null | sort | uniq -d || true)"
    dup_uid_count="$(echo "$dup_uids" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"

    if [ "$dup_uid_count" -gt 0 ]; then
      status="취약"
      reason="동일한 UID가 중복으로 설정되어 있습니다: $(echo "$dup_uids" | paste -sd', ' -)"
    fi
  else
    status="취약"
    reason="/etc/passwd 파일이 존재하지 않습니다."
  fi

  _json_escape_u10() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u10 "$code")" \
    "$(_json_escape_u10 "$item")" \
    "$(_json_escape_u10 "$severity")" \
    "$(_json_escape_u10 "$status")" \
    "$(_json_escape_u10 "$reason")"
}

U_11() {
  local code="U-11"
  local item="사용자 shell 점검"
  local severity="하"
  local status="양호"
  local reason="로그인이 불필요한 계정에 /bin/false 또는 nologin 쉘이 부여되어 있습니다."

  local VULN=0
  local REASON=""
  local VUL_ACCOUNTS=""

  local EXCEPT_USERS="^(sync|shutdown|halt)$"

  if [ ! -f /etc/passwd ]; then
    VULN=1
    REASON="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  else
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
      REASON="로그인이 불필요한 계정에 쉘이 부여되어 있습니다: $VUL_ACCOUNTS"
    fi
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  fi

  _json_escape_u11() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u11 "$code")" \
    "$(_json_escape_u11 "$item")" \
    "$(_json_escape_u11 "$severity")" \
    "$(_json_escape_u11 "$status")" \
    "$(_json_escape_u11 "$reason")"
}

U_12() {
  local code="U-12"
  local item="세션 종료 시간 설정"
  local severity="하"
  local status="양호"
  local reason="TMOUT 값이 설정되어 있고(권고: 600초 이하) 전역 설정 파일을 통해 적용됩니다."

  local TARGET_TMOUT=600
  local vuln=0
  local _reason=""
  local found=()

  local files=("/etc/profile" "/etc/bashrc" "/etc/profile.d" "/etc/csh.cshrc" "/etc/csh.login")
  local f
  for f in "${files[@]}"; do
    if [[ -d "$f" ]]; then
      while IFS= read -r -d '' x; do
        files+=("$x")
      done < <(find "$f" -maxdepth 1 -type f -name "*.sh" -print0 2>/dev/null)
    fi
  done

  for f in "${files[@]}"; do
    [[ -r "$f" && -f "$f" ]] || continue
    local tm=""
    tm="$(grep -E '^[[:space:]]*(readonly[[:space:]]+)?TMOUT[[:space:]]*=' "$f" 2>/dev/null \
      | sed 's/#.*$//' | tail -n 1 \
      | sed -E 's/.*TMOUT[[:space:]]*=[[:space:]]*([0-9]+).*/\1/')"
    if [[ "$tm" =~ ^[0-9]+$ ]]; then
      found+=("$f:$tm")
    fi
  done

  if (( ${#found[@]} == 0 )); then
    vuln=1
    _reason="TMOUT 설정을 전역 설정 파일에서 찾지 못했습니다."
  else
    local ok=0
    local has_zero=0
    local e
    for e in "${found[@]}"; do
      local val="${e##*:}"

      if [[ "$val" =~ ^[0-9]+$ ]] && (( val == 0 )); then
        has_zero=1
      fi
      if [[ "$val" =~ ^[0-9]+$ ]] && (( val > 0 && val <= TARGET_TMOUT )); then
        ok=1
      fi
    done

    if (( has_zero == 1 )); then
      vuln=1
      _reason="TMOUT=0 설정이 확인되었습니다(유휴 세션 종료 비활성)."
    elif (( ok == 0 )); then
      vuln=1
      _reason="TMOUT 값이 1~${TARGET_TMOUT}초 조건을 충족하지 못했습니다."
    fi
  fi

  if (( vuln == 1 )); then
    status="취약"
    _reason="$(echo "$_reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if (( ${#_reason} > 250 )); then _reason="${_reason:0:250}..."; fi
    reason="$_reason"
  fi

  _json_escape_u12() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u12 "$code")" \
    "$(_json_escape_u12 "$item")" \
    "$(_json_escape_u12 "$severity")" \
    "$(_json_escape_u12 "$status")" \
    "$(_json_escape_u12 "$reason")"
}

U_13() {
  local code="U-13"
  local item="안전한 비밀번호 암호화 알고리즘 사용"
  local severity="중"
  local status="양호"
  local reason="SHA-2 기반 알고리즘(SHA-256:$5 또는 SHA-512:$6)을 사용합니다."

  local shadow="/etc/shadow"

  if [ ! -e "$shadow" ]; then
    status="취약"
    reason="$shadow 파일이 없습니다."
  elif [ ! -r "$shadow" ]; then
    status="취약"
    reason="$shadow 파일을 읽을 수 없습니다. (권한 부족: root 권한 필요)"
  else
    local vuln_found=0
    local checked=0
    local evidence=""

    while IFS=: read -r user hash rest; do
      [ -z "$user" ] && continue

  
      if [ -z "$hash" ] || [[ "$hash" =~ ^[!*]+$ ]]; then
        continue
      fi

      ((checked++))

      if [[ "$hash" != \$* ]]; then
        vuln_found=1
        evidence+="$user:UNKNOWN_FORMAT; "
        continue
      fi

      local id=""
      id="$(echo "$hash" | awk -F'$' '{print $2}')"
      [ -z "$id" ] && id="UNKNOWN"

      if [ "$id" = "5" ] || [ "$id" = "6" ]; then
        : # good
      else
        vuln_found=1
        evidence+="$user:\$$id\$; "
      fi
    done < "$shadow"

    if [ "$checked" -eq 0 ]; then
      status="취약"
      reason="점검 가능한 패스워드 해시 계정이 없습니다. (모두 잠금/미설정 계정일 수 있음)"
    elif [ "$vuln_found" -eq 1 ]; then
      status="취약"
      evidence="$(echo "$evidence" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      if (( ${#evidence} > 200 )); then evidence="${evidence:0:200}..."; fi
      reason="취약하거나 기준(SHA-2) 미만의 해시 알고리즘을 사용하는 계정이 존재합니다. (${evidence})"
    fi
  fi

  _json_escape_u13() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u13 "$code")" \
    "$(_json_escape_u13 "$item")" \
    "$(_json_escape_u13 "$severity")" \
    "$(_json_escape_u13 "$status")" \
    "$(_json_escape_u13 "$reason")"
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
    s="$(printf '%s' "$s" | tr '\n' ' ' | tr '\r' ' ' | tr '\t' ' ')"
    printf '%s' "$s"
  }

  local ROOT_PATH="$PATH"

  if [ -z "$ROOT_PATH" ]; then
    status="N/A"
    reason="root 계정 PATH를 확인할 수 없습니다."
  elif echo "$ROOT_PATH" | grep -Eq '(^|:)\.(:|$)|::|^:|:$'; then
    status="취약"
    reason="root PATH 환경변수 내 취약 경로 포함: $ROOT_PATH"
  else
    status="양호"
    reason="PATH 환경변수에 '.'(현재 디렉터리)가 맨 앞이나 중간에 포함되어 있지 않습니다."
  fi

  local r="$reason"
  r="$(printf '%s' "$r" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

  if [ "$(printf '%s' "$r" | wc -c)" -gt 250 ]; then
    r="$(printf '%s' "$r" | cut -c1-250)..."
  fi

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$(_json_escape "$r")"
}


U_15() {
  local code="U-15"
  local item="파일 및 디렉터리 소유자 설정"
  local severity="상"
  local status="양호"
  local reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재하지 않습니다."

  local orphan_count=0

  orphan_count="$(find / \( -nouser -o -nogroup \) 2>/dev/null | wc -l | tr -d ' ')"

  if [ "$orphan_count" -gt 0 ]; then
    status="취약"
    reason="소유자가 존재하지 않는 파일 및 디렉터리가 존재합니다. (개수: $orphan_count)"
  fi

  _json_escape_u15() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u15 "$code")" \
    "$(_json_escape_u15 "$item")" \
    "$(_json_escape_u15 "$severity")" \
    "$(_json_escape_u15 "$status")" \
    "$(_json_escape_u15 "$reason")"
}

U_16() {
  local code="U-16"
  local item="/etc/passwd 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/passwd 파일의 소유자가 root이고 권한이 644 이하입니다."

  local FILE="/etc/passwd"
  local VULN=0
  local REASON=""

  if [ -f "$FILE" ]; then
    local OWNER=""
    local PERMIT=""

    OWNER="$(stat -c "%U" "$FILE" 2>/dev/null)"
    PERMIT="$(stat -c "%a" "$FILE" 2>/dev/null)"

    if [ "$OWNER" != "root" ] || [ "$PERMIT" -gt 644 ]; then
      VULN=1
      if [ "$OWNER" != "root" ]; then
        REASON="/etc/passwd 파일의 소유자가 root가 아닙니다 (현재: $OWNER)."
      fi
      if [ "$PERMIT" -gt 644 ]; then
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
  fi

  _json_escape_u16() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u16 "$code")" \
    "$(_json_escape_u16 "$item")" \
    "$(_json_escape_u16 "$severity")" \
    "$(_json_escape_u16 "$status")" \
    "$(_json_escape_u16 "$reason")"
}

U_17() {
  local code="U-17"
  local item="시스템 시작 스크립트 권한 설정"
  local severity="상"
  local status="양호"
  local reason="시스템 시작 스크립트/서비스 유닛의 소유자 및 권한이 적절하며 일반 사용자가 변경할 수 없습니다."

  local vuln=0
  local offenders=()

  check_path_perm() {
    local path="$1"
    [[ -e "$path" ]] || return 0

    local owner perm mode
    owner="$(stat -Lc '%U' "$path" 2>/dev/null)"
    perm="$(stat -Lc '%a' "$path" 2>/dev/null)"
    mode="$perm"
    [[ "$mode" =~ ^[0-9]+$ ]] || return 0

    if [[ "$owner" != "root" ]]; then
      offenders+=("$path (owner=$owner, perm=$perm)")
      return 0
    fi

    local oct="0$mode"
    if (( (oct & 18) != 0 )); then
      offenders+=("$path (group/other writable, perm=$perm)")
    fi
  }

  local candidates=(
    "/etc/rc.d/rc.local" "/etc/rc.local"
    "/etc/init.d" "/etc/rc.d/init.d"
    "/etc/systemd/system" "/usr/lib/systemd/system"
  )

  local p
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
  fi

  if (( vuln == 1 )); then
    status="취약"
    reason="시스템 시작 스크립트/유닛 파일에서 root 미소유 또는 그룹/기타 쓰기 권한이 있는 항목이 존재합니다(예: ${offenders[0]})."
  fi

  _json_escape_u17() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u17 "$code")" \
    "$(_json_escape_u17 "$item")" \
    "$(_json_escape_u17 "$severity")" \
    "$(_json_escape_u17 "$status")" \
    "$(_json_escape_u17 "$reason")"
}
U_18() {
  local code="U-18"
  local item="/etc/shadow 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/shadow 파일의 소유자가 root이고 권한이 400입니다."

  local target="/etc/shadow"

  if [ ! -e "$target" ]; then
    status="취약"
    reason="$target 파일이 없습니다."
  elif [ ! -f "$target" ]; then
    status="취약"
    reason="$target 가 일반 파일이 아닙니다."
  else
    local owner perm
    owner="$(stat -c '%U' "$target" 2>/dev/null)"
    perm="$(stat -c '%a' "$target" 2>/dev/null)"

    if [ -z "$owner" ] || [ -z "$perm" ]; then
      status="취약"
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
          status="취약"
          reason="$target 파일 권한 형식이 예상과 다릅니다. (perm=$perm)"
        else
          if [ "$perm" != "400" ]; then
            status="취약"
            reason="$target 파일 권한이 400이 아닙니다. (perm=$perm)"
          else
            local o g oth
            o="${perm:0:1}"; g="${perm:1:1}"; oth="${perm:2:1}"
            if [ "$o" != "4" ] || [ "$g" != "0" ] || [ "$oth" != "0" ]; then
              status="취약"
              reason="$target 파일 권한 구성(owner/group/other)이 기준과 다릅니다. (perm=$perm)"
            fi
          fi
        fi
      fi
    fi
  fi

  _json_escape_u18() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u18 "$code")" \
    "$(_json_escape_u18 "$item")" \
    "$(_json_escape_u18 "$severity")" \
    "$(_json_escape_u18 "$status")" \
    "$(_json_escape_u18 "$reason")"
}

U_19() {
  local code="U-19"
  local item="/etc/hosts 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/hosts 파일의 소유자가 root이고 권한이 644 이하입니다."

  local VULN_FOUND=0
  local DETAILS=""

  if [ -f "/etc/hosts" ]; then
    local FILE_OWNER_UID=""
    local FILE_OWNER_NAME=""
    local FILE_PERM=""

    FILE_OWNER_UID="$(stat -c "%u" /etc/hosts 2>/dev/null)"
    FILE_OWNER_NAME="$(stat -c "%U" /etc/hosts 2>/dev/null)"
    FILE_PERM="$(stat -c "%a" /etc/hosts 2>/dev/null)"

    if [ -z "$FILE_OWNER_UID" ] || [ -z "$FILE_PERM" ]; then
      VULN_FOUND=1
      DETAILS="stat 명령으로 /etc/hosts 정보를 읽지 못했습니다."
    else
      local USER_PERM="${FILE_PERM:0:1}"
      local GROUP_PERM="${FILE_PERM:1:1}"
      local OTHER_PERM="${FILE_PERM:2:1}"

      if [ "$FILE_OWNER_UID" -ne 0 ]; then
        VULN_FOUND=1
        DETAILS="소유자(owner)가 root가 아님 (현재: $FILE_OWNER_NAME)"
      elif [ "$USER_PERM" -gt 6 ] || [ "$GROUP_PERM" -gt 4 ] || [ "$OTHER_PERM" -gt 4 ]; then
        VULN_FOUND=1
        DETAILS="권한이 644보다 큼 (현재: $FILE_PERM)"
      fi
    fi
  else
    status="취약"
    reason="/etc/hosts 파일이 존재하지 않습니다."
  fi

  if [ "$VULN_FOUND" -eq 1 ]; then
    status="취약"
    DETAILS="$(echo "$DETAILS" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if (( ${#DETAILS} > 250 )); then DETAILS="${DETAILS:0:250}..."; fi
    reason="$DETAILS"
  fi

  _json_escape_u19() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u19 "$code")" \
    "$(_json_escape_u19 "$item")" \
    "$(_json_escape_u19 "$severity")" \
    "$(_json_escape_u19 "$status")" \
    "$(_json_escape_u19 "$reason")"
}

U_20() {
  local code="U-20"
  local item="systemd *.socket, *.service 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="systemd socket/service 파일의 소유자가 root이고 권한이 644 이하입니다."

  local found_any=0
  local offenders=()

  _scan_dir_u20() {
    local d="$1"
    [ -d "$d" ] || return 0

    local f owner perm
    while IFS= read -r -d '' f; do
      [ -f "$f" ] || continue
      found_any=1

      owner="$(stat -c %U "$f" 2>/dev/null)"
      perm="$(stat -c %a "$f" 2>/dev/null)"

      if [ "$owner" != "root" ]; then
        offenders+=("$f (owner=$owner)")
      elif [ -n "$perm" ] && [ "$perm" -gt 644 ]; then
        offenders+=("$f (perm=$perm)")
      fi
    done < <(find "$d" -type f \( -name "*.socket" -o -name "*.service" \) -print0 2>/dev/null)
  }

  _scan_dir_u20 "/usr/lib/systemd/system"
  _scan_dir_u20 "/etc/systemd/system"

  if [ "$found_any" -eq 0 ]; then
    status="취약"
    reason="systemd socket/service 파일이 없습니다."
  else
    if [ "${#offenders[@]}" -gt 0 ]; then
      status="취약"
      reason="root 미소유 또는 권한 644 초과 파일이 존재합니다(예: ${offenders[0]})."
    fi
  fi

  _json_escape_u20() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u20 "$code")" \
    "$(_json_escape_u20 "$item")" \
    "$(_json_escape_u20 "$severity")" \
    "$(_json_escape_u20 "$status")" \
    "$(_json_escape_u20 "$reason")"
}

U_21() {
  local code="U-21"
  local item="/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/(r)syslog.conf 파일의 소유자가 root/bin/sys이고 권한이 640 이하입니다."

  local target=""
  if [ -f "/etc/rsyslog.conf" ]; then
    target="/etc/rsyslog.conf"
  elif [ -f "/etc/syslog.conf" ]; then
    target="/etc/syslog.conf"
  else
    status="취약"
    reason="/etc/rsyslog.conf 또는 /etc/syslog.conf 파일이 존재하지 않습니다."
  fi

  if [ -n "$target" ]; then
    local OWNER=""
    local PERMIT=""

    OWNER="$(stat -c '%U' "$target" 2>/dev/null)"
    PERMIT="$(stat -c '%a' "$target" 2>/dev/null)"

    if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
      status="취약"
      reason="stat 명령으로 $target 정보를 읽지 못했습니다. (권한 문제 등)"
    else
      if [[ ! "$OWNER" =~ ^(root|bin|sys)$ ]]; then
        status="취약"
        reason="$target 파일의 소유자가 root, bin, sys가 아닙니다. (owner=$OWNER)"
      elif [ "$PERMIT" -gt 640 ]; then
        status="취약"
        reason="$target 파일의 권한이 640보다 큽니다. (permit=$PERMIT)"
      else
        status="양호"
        reason="$target 파일의 소유자($OWNER) 및 권한($PERMIT)이 기준에 적합합니다."
      fi
    fi
  fi

  _json_escape_u21() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u21 "$code")" \
    "$(_json_escape_u21 "$item")" \
    "$(_json_escape_u21 "$severity")" \
    "$(_json_escape_u21 "$status")" \
    "$(_json_escape_u21 "$reason")"
}

U_22() {
  local code="U-22"
  local item="/etc/services 파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="/etc/services 파일이 root 소유이고 권한이 644 이하이며 기타 사용자 쓰기 권한이 없습니다."

  local target="/etc/services"
  local uid="" perm=""
  local bad=0

  if [[ ! -e "$target" ]]; then
    status="취약"
    reason="$target 파일이 존재하지 않습니다."
  else
    uid="$(stat -c '%u' "$target" 2>/dev/null || echo "")"
    perm="$(stat -c '%a' "$target" 2>/dev/null || echo "")"

    if [[ -z "$uid" || -z "$perm" ]]; then
      status="취약"
      reason="$target 파일 정보를 확인할 수 없습니다."
    else
      local mode=$((8#$perm))

      [[ "$uid" != "0" ]] && bad=1
      (( (mode & 0020) != 0 )) && bad=1   
      (( (mode & 0002) != 0 )) && bad=1   
      (( perm > 644 )) && bad=1

      if [[ "$bad" -ne 0 ]]; then
        status="취약"
        reason="owner_uid=$uid, perm=$perm (기준: root 소유, 644 이하, group/other 쓰기 금지)"
      fi
    fi
  fi

  _json_escape_u22() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u22 "$code")" \
    "$(_json_escape_u22 "$item")" \
    "$(_json_escape_u22 "$severity")" \
    "$(_json_escape_u22 "$status")" \
    "$(_json_escape_u22 "$reason")"
}

U_23() {
  local code="U-23"
  local item="SUID, SGID, Sticky bit 설정 파일 점검"
  local severity="상"
  local status="양호"
  local reason="비정상/사용자 쓰기 가능 경로 또는 패키지 미소유 SUID/SGID 파일이 존재하지 않습니다."

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

  _is_whitelisted_u23() {
    local f="$1" w
    for w in "${whitelist[@]}"; do
      [ "$f" = "$w" ] && return 0
    done
    return 1
  }

  _is_bad_path_u23() {
    local f="$1"
    case "$f" in
      /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/run/user/*)
        return 0 ;;
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

    if _is_bad_path_u23 "$f"; then
      vuln_found=1
      if (( count_v < MAX_EVIDENCE )); then
        evidence_vuln+="  - $mode $owner:$group $f (BAD_PATH)\n"
        count_v=$((count_v+1))
      fi
      continue
    fi

    if _is_whitelisted_u23 "$f"; then
      warn_found=1
      if (( count_w < MAX_EVIDENCE )); then
        evidence_warn+="  - $mode $owner:$group $f (WHITELIST)\n"
        count_w=$((count_w+1))
      fi
      continue
    fi

    if command -v rpm >/dev/null 2>&1; then
      if ! rpm -qf "$f" >/dev/null 2>&1; then
        vuln_found=1
        if (( count_v < MAX_EVIDENCE )); then
          evidence_vuln+="  - $mode $owner:$group $f (NOT_OWNED_BY_RPM)\n"
          count_v=$((count_v+1))
        fi
        continue
      fi
    fi

    warn_found=1
    if (( count_w < MAX_EVIDENCE )); then
      evidence_warn+="  - $mode $owner:$group $f (CHECK)\n"
      count_w=$((count_w+1))
    fi
  done < <(find "$SEARCH_ROOT" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

  if (( vuln_found == 1 )); then
    status="취약"
    reason="비정상/사용자 쓰기 가능 경로 또는 패키지 미소유 SUID/SGID 파일이 존재합니다."
    if [ -n "$evidence_vuln" ]; then
      local first_v
      first_v="$(echo -e "$evidence_vuln" | sed -n '1p' | tr -d '\r')"
      first_v="$(echo "$first_v" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      if [ -n "$first_v" ]; then
        reason="$reason (예: $first_v)"
      fi
    fi
  fi

  _json_escape_u23() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u23 "$code")" \
    "$(_json_escape_u23 "$item")" \
    "$(_json_escape_u23 "$severity")" \
    "$(_json_escape_u23 "$status")" \
    "$(_json_escape_u23 "$reason")"
}

U_24() {
  local code="U-24"
  local item="사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
  local severity="상"
  local status="양호"
  local reason="홈 디렉터리 환경/시작 파일의 소유자가 root 또는 해당 계정이며 group/other 쓰기 권한이 통제되어 있습니다."

  local VULN=0
  local REASON=""

  local CHECK_FILES=(
    ".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login" ".bash_logout"
    ".exrc" ".vimrc" ".netrc" ".forward" ".rhosts" ".shosts"
  )

  if [ ! -f /etc/passwd ]; then
    VULN=1
    REASON="/etc/passwd 파일이 존재하지 않아 점검할 수 없습니다."
  else
    local USER_LIST
    USER_LIST="$(awk -F: '$7!~/(nologin|false)/ {print $1":"$6}' /etc/passwd 2>/dev/null)"

    local USER_INFO USER_NAME USER_HOME
    for USER_INFO in $USER_LIST; do
      USER_NAME="${USER_INFO%%:*}"
      USER_HOME="${USER_INFO#*:}"

      [ -n "$USER_NAME" ] || continue
      [ -n "$USER_HOME" ] || continue
      [ -d "$USER_HOME" ] || continue

      local FILE TARGET
      for FILE in "${CHECK_FILES[@]}"; do
        TARGET="$USER_HOME/$FILE"
        [ -f "$TARGET" ] || continue

        local FILE_OWNER PERMSTR GROUP_WRITE OTHER_WRITE
        FILE_OWNER="$(stat -c '%U' "$TARGET" 2>/dev/null)"
        PERMSTR="$(stat -c '%A' "$TARGET" 2>/dev/null)"

        if [ -z "$FILE_OWNER" ] || [ -z "$PERMSTR" ]; then
          VULN=1
          REASON="$REASON 파일 정보 확인 실패: $TARGET |"
          continue
        fi

        if [ "$FILE_OWNER" != "root" ] && [ "$FILE_OWNER" != "$USER_NAME" ]; then
          VULN=1
          REASON="$REASON 파일 소유자 불일치: $TARGET (owner=$FILE_OWNER) |"
        fi

        GROUP_WRITE="${PERMSTR:5:1}"
        OTHER_WRITE="${PERMSTR:8:1}"
        if [ "$GROUP_WRITE" = "w" ] || [ "$OTHER_WRITE" = "w" ]; then
          VULN=1
          REASON="$REASON 권한 취약: $TARGET (perm=$PERMSTR, group/other write) |"
        fi
      done
    done
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    REASON="$(echo "$REASON" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if (( ${#REASON} > 250 )); then REASON="${REASON:0:250}..."; fi
    reason="${REASON:-기준 미충족}"
  fi

  _json_escape_u24() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u24 "$code")" \
    "$(_json_escape_u24 "$item")" \
    "$(_json_escape_u24 "$severity")" \
    "$(_json_escape_u24 "$status")" \
    "$(_json_escape_u24 "$reason")"
}

U_25() {
  local code="U-25"
  local item="world writable 파일 점검"
  local severity="상"
  local status="양호"
  local reason="world writable 파일이 존재하지 않습니다."

  local first_file=""
  first_file="$(find / -xdev -type f -perm -0002 2>/dev/null | head -n 1)"

  if [ -n "$first_file" ]; then
    status="취약"
    reason="world writable 설정이 되어있는 파일이 존재합니다. (예: $first_file)"
  fi

  _json_escape_u25() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u25 "$code")" \
    "$(_json_escape_u25 "$item")" \
    "$(_json_escape_u25 "$severity")" \
    "$(_json_escape_u25 "$status")" \
    "$(_json_escape_u25 "$reason")"
}

U_26() {
  local code="U-26"
  local item="/dev에 존재하지 않는 device 파일 점검"
  local severity="상"
  local status="양호"
  local reason="/dev 디렉터리 내 존재하지 않아야 할 일반 파일이 발견되지 않았습니다."

  local target_dir="/dev"
  local VULN=0
  local REASON=""

  if [ ! -d "$target_dir" ]; then
    VULN=1
    REASON="$target_dir 디렉터리가 존재하지 않습니다."
  else
    local VUL_FILES=""
    VUL_FILES="$(find /dev \( -path /dev/mqueue -o -path /dev/shm \) -prune -o -type f -print 2>/dev/null)"

    if [ -n "$VUL_FILES" ]; then
      VULN=1
      local first_v
      first_v="$(echo "$VUL_FILES" | head -n 1)"
      REASON="/dev 내부에 존재하지 않아야 할 일반 파일이 발견되었습니다. (예: $first_v)"
    fi
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  fi

  _json_escape_u26() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u26 "$code")" \
    "$(_json_escape_u26 "$item")" \
    "$(_json_escape_u26 "$severity")" \
    "$(_json_escape_u26 "$status")" \
    "$(_json_escape_u26 "$reason")"
}

U_27() {
  local code="U-27"
  local item="\$HOME/.rhosts, /etc/hosts.equiv 사용 금지"
  local severity="상"
  local status="양호"
  local reason="rlogin/rsh/rexec 서비스를 사용하지 않습니다."

  local used=0
  local why_used=""

  if command -v ss >/dev/null 2>&1; then
    if ss -lntup 2>/dev/null | awk '$5 ~ /:(512|513|514)$/ {f=1} END{exit (f?0:1)}'; then
      used=1
      why_used="512/513/514 포트가 리스닝 중"
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lntup 2>/dev/null | awk '$4 ~ /:(512|513|514)$/ {f=1} END{exit (f?0:1)}'; then
      used=1
      why_used="512/513/514 포트가 리스닝 중"
    fi
  fi

  if [ "$used" -eq 0 ]; then
    if pgrep -f '(in\.rshd|rshd|in\.rlogind|rlogind|in\.rexecd|rexecd)' >/dev/null 2>&1; then
      used=1
      why_used="r-command 데몬 프로세스가 실행 중"
    fi
  fi

  if [ "$used" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    local units=("rsh.socket" "rsh.service" "rlogin.socket" "rlogin.service" "rexec.socket" "rexec.service" "rshd.service" "rlogind.service" "rexecd.service")
    local u
    for u in "${units[@]}"; do
      if systemctl list-unit-files "$u" >/dev/null 2>&1; then
        if systemctl is-active "$u" >/dev/null 2>&1 || systemctl is-enabled "$u" >/dev/null 2>&1; then
          used=1
          why_used="$u 유닛이 active/enabled"
          break
        fi
      fi
    done
  fi

  if [ "$used" -eq 0 ]; then
    local inetd_hit=0 xinetd_hit=0

    if [ -f /etc/inetd.conf ] && grep -Eqi '^[[:space:]]*[^#].*\b(shell|login|exec)\b' /etc/inetd.conf 2>/dev/null; then
      inetd_hit=1
    fi
    if [ -d /etc/inetd.d ] && grep -RsiEq '^[[:space:]]*[^#].*\b(shell|login|exec)\b' /etc/inetd.d 2>/dev/null; then
      inetd_hit=1
    fi

    if [ -d /etc/xinetd.d ]; then
      local f
      for f in /etc/xinetd.d/*; do
        [ -f "$f" ] || continue
        if grep -qiE 'service[[:space:]]+(shell|login|exec|rsh|rlogin|rexec)' "$f" 2>/dev/null && \
           grep -qiE 'disable[[:space:]]*=[[:space:]]*no' "$f" 2>/dev/null; then
          xinetd_hit=1
          break
        fi
      done
    fi

    if [ "$inetd_hit" -eq 1 ]; then
      if pgrep -x inetd >/dev/null 2>&1 || pgrep -x openbsd-inetd >/dev/null 2>&1 || pgrep -f inetd >/dev/null 2>&1; then
        used=1
        why_used="inetd 설정(shell/login/exec) 및 inetd 프로세스 실행 확인"
      elif command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active openbsd-inetd >/dev/null 2>&1 || systemctl is-enabled openbsd-inetd >/dev/null 2>&1; then
          used=1
          why_used="inetd 설정(shell/login/exec) 및 openbsd-inetd 유닛 active/enabled"
        fi
      fi
    fi

    if [ "$used" -eq 0 ] && [ "$xinetd_hit" -eq 1 ]; then
      if pgrep -x xinetd >/dev/null 2>&1; then
        used=1
        why_used="xinetd 설정(disable=no) 및 xinetd 프로세스 실행 확인"
      elif command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active xinetd >/dev/null 2>&1 || systemctl is-enabled xinetd >/dev/null 2>&1; then
          used=1
          why_used="xinetd 설정(disable=no) 및 xinetd 유닛 active/enabled"
        fi
      fi
    fi
  fi

  if [ "$used" -eq 1 ]; then
    local THRESH_DEC=$((8#600))

    has_plus_token() {
      local file="$1"
      sed 's/#.*//' "$file" 2>/dev/null | tr -d '\r' | grep -Eq '(^|[[:space:]])\+([[:space:]]|$)'
    }

    check_perm_le_600() {
      local perm="$1"
      [[ "$perm" =~ ^[0-7]+$ ]] || return 2
      local dec=$((8#$perm))
      [ "$dec" -le "$THRESH_DEC" ]
    }

    local f="/etc/hosts.equiv"
    if [ -f "$f" ]; then
      local OWNER PERMIT
      OWNER="$(stat -c '%U' "$f" 2>/dev/null)"
      PERMIT="$(stat -c '%a' "$f" 2>/dev/null)"

      if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
        status="취약"
        reason="stat 명령으로 $f 정보를 읽지 못했습니다. (권한 문제 등, 사용근거=$why_used)"
      elif [ "$OWNER" != "root" ]; then
        status="취약"
        reason="r-command 사용 중이며 $f 소유자가 root가 아닙니다. (owner=$OWNER, permit=$PERMIT, 사용근거=$why_used)"
      elif ! check_perm_le_600 "$PERMIT"; then
        status="취약"
        reason="r-command 사용 중이며 $f 권한이 600보다 큽니다. (owner=$OWNER, permit=$PERMIT, 사용근거=$why_used)"
      elif has_plus_token "$f"; then
        status="취약"
        reason="r-command 사용 중이며 $f 파일에 '+' 옵션이 존재합니다. (사용근거=$why_used)"
      fi
    fi

    if [ "$status" != "취약" ]; then
      local user uid home shell
      while IFS=: read -r user _ uid _ _ home shell; do
        [ -n "$home" ] || continue
        [ -d "$home" ] || continue

        if [ "$uid" -ne 0 ] && [ "$uid" -lt 1000 ]; then
          continue
        fi

        local rf="$home/.rhosts"
        if [ -f "$rf" ]; then
          local OWNER PERMIT
          OWNER="$(stat -c '%U' "$rf" 2>/dev/null)"
          PERMIT="$(stat -c '%a' "$rf" 2>/dev/null)"

          if [ -z "$OWNER" ] || [ -z "$PERMIT" ]; then
            status="취약"
            reason="stat 명령으로 $rf 정보를 읽지 못했습니다. (권한 문제 등, 사용근거=$why_used)"
            break
          elif [ "$OWNER" != "$user" ]; then
            status="취약"
            reason="r-command 사용 중이며 $rf 소유자가 해당 계정과 다릅니다. (expected=$user, owner=$OWNER, permit=$PERMIT, 사용근거=$why_used)"
            break
          elif ! check_perm_le_600 "$PERMIT"; then
            status="취약"
            reason="r-command 사용 중이며 $rf 권한이 600보다 큽니다. (owner=$OWNER, permit=$PERMIT, 사용근거=$why_used)"
            break
          elif has_plus_token "$rf"; then
            status="취약"
            reason="r-command 사용 중이며 $rf 파일에 '+' 옵션이 존재합니다. (사용근거=$why_used)"
            break
          else
            :
          fi
        fi
      done < /etc/passwd
    fi

    if [ "$status" != "취약" ]; then
      status="양호"
      reason="r-command 사용 중이나 /etc/hosts.equiv 및 \$HOME/.rhosts 사용 조건(소유자/권한 600 이하, '+' 옵션 없음)을 충족합니다. (사용근거=$why_used)"
    fi
  fi

  _json_escape_u27() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u27 "$code")" \
    "$(_json_escape_u27 "$item")" \
    "$(_json_escape_u27 "$severity")" \
    "$(_json_escape_u27 "$status")" \
    "$(_json_escape_u27 "$reason")"
}

U_28() {
  local code="U-28"
  local item="접속 IP 및 포트 제한"
  local severity="상"
  local status="양호"
  local reason="TCP Wrapper(/etc/hosts.allow, /etc/hosts.deny) 기반 접근 제한 설정이 확인되었습니다."

  local deny="/etc/hosts.deny"
  local allow="/etc/hosts.allow"

  local libwrap_exists=0
  if ls /lib*/libwrap.so* /usr/lib*/libwrap.so* >/dev/null 2>&1; then
    libwrap_exists=1
  fi

  local sshd_uses_wrap="unknown"
  if command -v sshd >/dev/null 2>&1; then
    local sshd_path
    sshd_path="$(command -v sshd 2>/dev/null)"
    if command -v ldd >/dev/null 2>&1; then
      if ldd "$sshd_path" 2>/dev/null | grep -qi 'libwrap'; then
        sshd_uses_wrap="yes"
      else
        sshd_uses_wrap="no"
      fi
    fi
  fi

  _normalized_lines() {
    local f="$1"
    sed -e 's/[[:space:]]//g' -e '/^#/d' -e '/^$/d' "$f" 2>/dev/null
  }

  if [ "$libwrap_exists" -eq 0 ]; then
    status="N/A"
    reason="TCP Wrapper(libwrap) 라이브러리가 확인되지 않습니다."
  else
    if [ ! -f "$deny" ]; then
      status="취약"
      reason="$deny 파일이 없습니다. (기본 차단 정책 없음)"
    else
      local deny_allall_count
      deny_allall_count="$(_normalized_lines "$deny" | tr '[:upper:]' '[:lower:]' | grep -c '^all:all')"

      local allow_allall_count=0
      if [ -f "$allow" ]; then
        allow_allall_count="$(_normalized_lines "$allow" | tr '[:upper:]' '[:lower:]' | grep -c '^all:all')"
      fi

      if [ "$allow_allall_count" -gt 0 ]; then
        status="취약"
        reason="$allow 파일에 'ALL:ALL' 설정이 있습니다. (전체 허용)"
      else
        if [ "$deny_allall_count" -eq 0 ]; then
          local deny_has_rules
          deny_has_rules="$(_normalized_lines "$deny" | grep -Eci '^[^:]+:[^:]+')"

          if [ "$deny_has_rules" -gt 0 ]; then
            status="양호"
            reason="기본 ALL:ALL은 없지만, 서비스별 접근 제한 규칙이 존재합니다."
          else
            status="취약"
            reason="접근 제한 규칙이 설정되어 있지 않습니다."
          fi
        else
          status="양호"
          reason="기본 차단 정책(ALL:ALL)이 적용되어 있으며 전체 허용 설정이 없습니다."
        fi
      fi
    fi
  fi

  if [ "$sshd_uses_wrap" != "unknown" ]; then
    reason="$reason (sshd libwrap 사용여부: $sshd_uses_wrap)"
  fi

  _json_escape_u28() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u28 "$code")" \
    "$(_json_escape_u28 "$item")" \
    "$(_json_escape_u28 "$severity")" \
    "$(_json_escape_u28 "$status")" \
    "$(_json_escape_u28 "$reason")"
}

U_29() {
  local code="U-29"
  local item="hosts.lpd 파일 소유자 및 권한 설정"
  local severity="하"
  local status="양호"
  local reason="/etc/hosts.lpd 파일이 존재하지 않거나, root 소유 및 600 이하 권한으로 설정되어 있습니다."

  local target="/etc/hosts.lpd"

  if [ -f "$target" ]; then
    local owner permit
    owner="$(stat -c "%U" "$target" 2>/dev/null)"
    permit="$(stat -c "%a" "$target" 2>/dev/null)"

    if [ -z "$owner" ] || [ -z "$permit" ]; then
      status="취약"
      reason="stat 명령으로 /etc/hosts.lpd 정보를 확인할 수 없습니다."
    else
      if [ "$owner" != "root" ]; then
        status="취약"
        reason="/etc/hosts.lpd 파일의 소유자가 root가 아닙니다. (현재: $owner)"
      fi

      if [ "$status" = "양호" ] && [ "$permit" -gt 600 ]; then
        status="취약"
        reason="/etc/hosts.lpd 파일 권한이 600보다 큽니다. (현재: $permit)"
      fi
    fi
  else
    status="양호"
    reason="/etc/hosts.lpd 파일이 존재하지 않습니다."
  fi

  _json_escape_u29() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u29 "$code")" \
    "$(_json_escape_u29 "$item")" \
    "$(_json_escape_u29 "$severity")" \
    "$(_json_escape_u29 "$status")" \
    "$(_json_escape_u29 "$reason")"
}

U_30() {
  local code="U-30"
  local item="UMASK 설정 관리"
  local severity="중"
  local status="양호"
  local reason="시스템/서비스/사용자 환경 전반에 UMASK 022 이상이 적용되어 있습니다."

  local vuln=0
  local reasons=""

  check_umask_value() {
    local value="$1"
    [ -z "$value" ] && return 0
    if [[ "$value" =~ ^[0-7]{3,4}$ ]]; then
      if [ $((8#$value)) -lt 18 ]; then
        return 1
      fi
    fi
    return 0
  }

  local cur_umask login_umask umask_val
  cur_umask="$(umask 2>/dev/null)"

  if ! check_umask_value "$cur_umask"; then
    vuln=1
    reasons="$reasons [현재세션:$cur_umask]"
  fi

  login_umask="$(grep -E "^[[:space:]]*UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}' | tail -n1)"
  if [ -n "$login_umask" ]; then
    if ! check_umask_value "$login_umask"; then
      vuln=1
      reasons="$reasons [/etc/login.defs:$login_umask]"
    fi
  fi

  local file
  for file in /etc/profile /etc/bash.bashrc; do
    [ -f "$file" ] || continue
    umask_val="$(grep -E "^[[:space:]]*umask" "$file" 2>/dev/null | awk '{print $2}' | tail -n1)"
    if [ -n "$umask_val" ]; then
      if ! check_umask_value "$umask_val"; then
        vuln=1
        reasons="$reasons [$file:$umask_val]"
      fi
    fi
  done

  for file in /etc/profile.d/*.sh; do
    [ -f "$file" ] || continue
    umask_val="$(grep -E "^[[:space:]]*umask" "$file" 2>/dev/null | awk '{print $2}' | tail -n1)"
    if [ -n "$umask_val" ]; then
      if ! check_umask_value "$umask_val"; then
        vuln=1
        reasons="$reasons [$file:$umask_val]"
      fi
    fi
  done

  local user uid home shell
  while IFS=: read -r user _ uid _ _ home shell; do
    [[ "$uid" -ge 1000 ]] || continue
    [[ "$shell" =~ nologin|false ]] && continue
    for file in .bashrc .profile .bash_profile; do
      local target="$home/$file"
      [ -f "$target" ] || continue
      umask_val="$(grep -E "^[[:space:]]*umask" "$target" 2>/dev/null | awk '{print $2}' | tail -n1)"
      if [ -n "$umask_val" ]; then
        if ! check_umask_value "$umask_val"; then
          vuln=1
          reasons="$reasons [$user:$target:$umask_val]"
        fi
      fi
    done
  done < /etc/passwd

  if grep -q "pam_umask.so" /etc/pam.d/common-session 2>/dev/null; then
    :
  else
    vuln=1
    reasons="$reasons [PAM:pam_umask 미적용]"
  fi

  local svc
  for svc in $(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}'); do
    umask_val="$(systemctl show "$svc" -p UMask 2>/dev/null | awk -F= '{print $2}')"
    if [ -n "$umask_val" ]; then
      if ! check_umask_value "$umask_val"; then
        vuln=1
        reasons="$reasons [systemd:$svc:$umask_val]"
        break
      fi
    fi
  done

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reasons="$(echo "$reasons" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if [ -n "$reasons" ]; then
      reason="UMASK 기준(022 이상) 미충족 또는 미적용 항목이 있습니다: $reasons"
    else
      reason="UMASK 기준(022 이상) 미충족 또는 미적용 항목이 있습니다."
    fi
  else
    status="양호"
    reason="UMASK 기준(022 이상)이 적용되어 있습니다. (현재세션: ${cur_umask:-N/A})"
  fi

  _json_escape_u30() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u30 "$code")" \
    "$(_json_escape_u30 "$item")" \
    "$(_json_escape_u30 "$severity")" \
    "$(_json_escape_u30 "$status")" \
    "$(_json_escape_u30 "$reason")"
}

U_31() {
  local code="U-31"
  local item="홈 디렉토리 소유자 및 권한 설정"
  local severity="중"
  local status="양호"
  local reason="홈 디렉토리 소유자가 해당 계정이며, 타 사용자 쓰기 권한이 제거되어 있습니다."

  local vuln=0
  local reasons=""

  local user_list
  user_list="$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /nologin|false/ { print $1 ":" $6 }' /etc/passwd 2>/dev/null)"

  local user username homedir owner permit others_permit
  for user in $user_list; do
    username="$(echo "$user" | cut -d: -f1)"
    homedir="$(echo "$user" | cut -d: -f2)"

    if [ -d "$homedir" ]; then
      owner="$(stat -c '%U' "$homedir" 2>/dev/null)"
      permit="$(stat -c '%a' "$homedir" 2>/dev/null)"
      others_permit="$(echo "$permit" | sed 's/.*\(.\)$/\1/')"

      if [ "$owner" != "$username" ]; then
        vuln=1
        reasons="$reasons 소유자 불일치: $username 홈($homedir) owner=$owner |"
      fi

      if [[ "$others_permit" =~ [2367] ]]; then
        vuln=1
        reasons="$reasons 타 사용자 쓰기 권한 존재: $username 홈($homedir) perm=$permit |"
      fi
    else
      vuln=1
      reasons="$reasons 홈 디렉토리 미존재: $username home=$homedir |"
    fi
  done

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reasons="$(echo "$reasons" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if [ -n "$reasons" ]; then
      if [ ${#reasons} -gt 250 ]; then reasons="${reasons:0:250}..."; fi
      reason="$reasons"
    else
      reason="홈 디렉토리 소유자/권한 기준을 충족하지 못했습니다."
    fi
  else
    status="양호"
    reason="홈 디렉토리 소유자가 해당 계정이며, 타 사용자 쓰기 권한이 제거되어 있습니다."
  fi

  _json_escape_u31() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u31 "$code")" \
    "$(_json_escape_u31 "$item")" \
    "$(_json_escape_u31 "$severity")" \
    "$(_json_escape_u31 "$status")" \
    "$(_json_escape_u31 "$reason")"
}

U_32() {
  local code="U-32"
  local item="홈 디렉토리로 지정한 디렉토리의 존재 관리"
  local severity="중"
  local status="양호"
  local reason="홈 디렉토리가 존재하지 않는 계정이 발견되지 않았습니다."

  local UID_MIN=1000
  if [ -r /etc/login.defs ]; then
    local v
    v="$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/ {print $2}' /etc/login.defs 2>/dev/null | tail -n1)"
    [[ "$v" =~ ^[0-9]+$ ]] && UID_MIN="$v"
  fi

  local -a bad_users=()
  local -a bad_reasons=()

  u32_is_login_shell() {
    local sh="${1:-}"
    [[ -n "$sh" ]] || return 1
    case "$sh" in
      */nologin|*/false) return 1 ;;
      *) return 0 ;;
    esac
  }

  while IFS=: read -r user _ uid _ _ home shell; do
    [[ -n "$user" && "$uid" =~ ^[0-9]+$ ]] || continue

    if [ "$uid" -ne 0 ] && [ "$uid" -lt "$UID_MIN" ]; then
      continue
    fi
    [[ "$user" == "nobody" ]] && continue
    u32_is_login_shell "$shell" || continue

    if [[ -z "$home" || "$home" == "/" ]]; then
      bad_users+=("$user")
      bad_reasons+=("HOME 경로 이상(home=$home)")
      continue
    fi

    if [ ! -d "$home" ]; then
      if [ -e "$home" ]; then
        bad_users+=("$user")
        bad_reasons+=("홈 경로가 디렉토리가 아님(home=$home)")
      else
        bad_users+=("$user")
        bad_reasons+=("홈디렉토리 미존재(home=$home)")
      fi
    fi
  done < /etc/passwd

  if [ "${#bad_users[@]}" -eq 0 ]; then
    status="양호"
    reason="홈 디렉토리가 존재하지 않는 계정이 발견되지 않았습니다."
  else
    status="취약"
    local reasons=""
    local i limit=30
    for i in "${!bad_users[@]}"; do
      if [ "$i" -ge "$limit" ]; then
        reasons="$reasons ... (생략) |"
        break
      fi
      reasons="$reasons ${bad_users[$i]}: ${bad_reasons[$i]} |"
    done
    reasons="$(echo "$reasons" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if [ ${#reasons} -gt 250 ]; then reasons="${reasons:0:250}..."; fi
    reason="$reasons"
  fi

  _json_escape_u32() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u32 "$code")" \
    "$(_json_escape_u32 "$item")" \
    "$(_json_escape_u32 "$severity")" \
    "$(_json_escape_u32 "$status")" \
    "$(_json_escape_u32 "$reason")"
}

U_33() {
  local code="U-33"
  local item="숨겨진 파일 및 디렉토리 검색 및 제거"
  local severity="하"
  local status="취약"
  local reason="불필요/의심 숨김 파일 및 디렉터리 여부는 환경/정책에 따라 달라 자동으로 양호 확정 불가 (확인 필요)"

  local targets=(/etc /root /home /tmp /var/tmp /dev/shm /opt /usr/local)

  local d
  for d in "${targets[@]}"; do
    [[ -d "$d" ]] || continue
    find "$d" -xdev \
      \( -path "$d/proc" -o -path "$d/sys" -o -path "$d/run" -o -path "$d/dev" \) -prune -o \
      -mindepth 1 -name ".*" \( -type f -o -type d \) -print 2>/dev/null >/dev/null
  done

  _json_escape_u33() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u33 "$code")" \
    "$(_json_escape_u33 "$item")" \
    "$(_json_escape_u33 "$severity")" \
    "$(_json_escape_u33 "$status")" \
    "$(_json_escape_u33 "$reason")"
}

U_34() {
  local code="U-34"
  local item="Finger 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="Finger 서비스가 비활성화되어 있습니다."

  local VULN=0
  local REASON=""

  local SERVICES=("finger" "fingerd" "in.fingerd" "finger.socket")
  local SVC
  for SVC in "${SERVICES[@]}"; do
    if systemctl is-active "$SVC" >/dev/null 2>&1; then
      VULN=1
      REASON="$REASON Finger 서비스가 활성화되어 있습니다. |"
    fi
  done

  if ps -ef | grep -v grep | grep -Ei "fingerd|in\.fingerd" >/dev/null 2>&1; then
    VULN=1
    REASON="$REASON Finger 프로세스가 실행 중입니다. |"
  fi

  local PORT_CHECK=""
  if command -v ss >/dev/null 2>&1; then
    PORT_CHECK="$(ss -nlp 2>/dev/null | grep -w ":79" || true)"
  else
    PORT_CHECK="$(netstat -natp 2>/dev/null | grep -w ":79" || true)"
  fi

  if [ -n "$PORT_CHECK" ]; then
    VULN=1
    REASON="$REASON Finger 포트가 리스닝 중입니다. |"
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$(echo "$REASON" | sed -e 's/[[:space:]]*$//' -e 's/[[:space:]]*|[[:space:]]*$//' )"
    [ -z "$reason" ] && reason="Finger 서비스가 활성화 상태로 판단되었습니다."
  else
    status="양호"
    reason="Finger 서비스가 비활성화되어 있습니다."
  fi

  _json_escape_u34() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u34 "$code")" \
    "$(_json_escape_u34 "$item")" \
    "$(_json_escape_u34 "$severity")" \
    "$(_json_escape_u34 "$status")" \
    "$(_json_escape_u34 "$reason")"
}

U_35() {
  local code="U-35"
  local item="공유 서비스에 대한 익명 접근 제한 설정"
  local severity="상"
  local status="양호"
  local reason="공유 서비스(FTP/NFS/Samba)에서 익명 접근을 유발하는 설정이 확인되지 않습니다."

  local vuln_flag=0

  local reasons=()
  _add_reason() {
    local s="$1"
    [ -n "$s" ] && reasons+=("$s")
  }

  is_listening_port() {
    ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1$"
  }

  is_active_service() {
    systemctl is-active "$1" >/dev/null 2>&1
  }

  local ftp_checked=0 ftp_running=0 ftp_pkg=0 ftp_conf_found=0

  if command -v rpm >/dev/null 2>&1; then
    rpm -q vsftpd >/dev/null 2>&1 && ftp_pkg=1
    rpm -q proftpd >/dev/null 2>&1 && ftp_pkg=1
    rpm -q proftpd-core >/dev/null 2>&1 && ftp_pkg=1
  fi

  if is_active_service vsftpd || is_active_service proftpd; then
    ftp_running=1
  fi
  if command -v ss >/dev/null 2>&1; then
    is_listening_port 21 && ftp_running=1
  fi

  local VSFTPD_FILES=()
  local PROFTPD_FILES=()

  local f conf
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

  dedup() { printf "%s\n" "$@" | awk 'NF && !seen[$0]++'; }
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
      block_hit=$(
        awk '
          BEGIN{inblk=0;hit=0}
          /^[[:space:]]*#/ {next}
          /<Anonymous[[:space:]>]/ {inblk=1}
          inblk && /<\/Anonymous>/ {inblk=0}
          inblk && ($1 ~ /^User$/ || $1 ~ /^UserAlias$/) {hit=1}
          END{print hit}
        ' "$conf" 2>/dev/null
      )
      if [ "$block_hit" = "1" ]; then
        vuln_flag=1
        _add_reason="$(_add_reason "proftpd 익명(Anonymous) FTP 설정 블록 존재: $conf")"
      fi
    done

    for conf in "${VSFTPD_FILES[@]}"; do
      [ -f "$conf" ] || continue
      last_val=$(
        grep -i '^[[:space:]]*anonymous_enable[[:space:]]*=' "$conf" 2>/dev/null \
          | grep -v '^[[:space:]]*#' \
          | tail -n 1 \
          | awk -F= '{gsub(/[[:space:]]/,"",$2); print tolower($2)}'
      )
      if [ -n "$last_val" ] && [ "$last_val" = "yes" ]; then
        vuln_flag=1
        _add_reason "vsftpd 익명 FTP 허용(anonymous_enable=YES): $conf"
      fi
    done

    if [ "$ftp_conf_found" -eq 0 ] && [ "$ftp_running" -eq 1 ]; then
      vuln_flag=1
      _add_reason "FTP 서비스 동작(21/tcp 리슨 또는 vsftpd/proftpd active) 중이나 설정 파일을 확인할 수 없음"
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
      cnt_no_root=$(
        grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null \
          | grep -E '(^|[[:space:]\(,])no_root_squash([[:space:]\),]|$)' \
          | wc -l
      )
      if [ "$cnt_no_root" -gt 0 ]; then
        vuln_flag=1
        _add_reason "NFS /etc/exports 에 no_root_squash 설정 존재"
      fi

      cnt_star=$(
        grep -v '^[[:space:]]*#' /etc/exports 2>/dev/null \
          | grep -E '(^|[[:space:]])\*([[:space:]\(]|$)' \
          | wc -l
      )
      if [ "$cnt_star" -gt 0 ]; then
        vuln_flag=1
        _add_reason "NFS /etc/exports 에 전체 호스트(*) 공유 설정 존재"
      fi
    else
      if [ "$nfs_running" -eq 1 ]; then
        vuln_flag=1
        _add_reason "NFS 서비스 active 이나 /etc/exports 파일이 없음"
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
      smb_hits=$(
        grep -v '^[[:space:]]*#' /etc/samba/smb.conf 2>/dev/null \
          | grep -Ei '^[[:space:]]*(guest[[:space:]]+ok|public|map[[:space:]]+to[[:space:]]+guest|security)[[:space:]]*='
      )
      if [ -n "$smb_hits" ]; then
        cnt_guest=$(echo "$smb_hits" | grep -Ei '^[[:space:]]*guest[[:space:]]+ok[[:space:]]*=[[:space:]]*yes' | wc -l)
        cnt_public=$(echo "$smb_hits" | grep -Ei '^[[:space:]]*public[[:space:]]*=[[:space:]]*yes' | wc -l)
        cnt_share=$(echo "$smb_hits" | grep -Ei '^[[:space:]]*security[[:space:]]*=[[:space:]]*share' | wc -l)
        cnt_map=$(echo "$smb_hits" | grep -Ei '^[[:space:]]*map[[:space:]]+to[[:space:]]+guest[[:space:]]*=' | wc -l)

        if [ "$cnt_guest" -gt 0 ] || [ "$cnt_public" -gt 0 ] || [ "$cnt_share" -gt 0 ] || [ "$cnt_map" -gt 0 ]; then
          vuln_flag=1
          local hit_one
          hit_one="$(echo "$smb_hits" | head -n 1 | tr '\r' ' ')"
          _add_reason "Samba 익명/게스트 접근 유발 가능 설정 존재(예: ${hit_one})"
        fi
      fi
    else
      if [ "$smb_running" -eq 1 ]; then
        vuln_flag=1
        _add_reason "Samba 서비스 active 이나 /etc/samba/smb.conf 파일이 없음"
      fi
    fi
  fi

  if [ "$vuln_flag" -eq 1 ]; then
    status="취약"
    if [ "${#reasons[@]}" -gt 0 ]; then
      reason="$(printf "%s; " "${reasons[@]}")"
      reason="${reason%; }"
    else
      reason="공유 서비스에서 익명 접근을 유발할 가능성이 있는 상태로 판단되었습니다."
    fi
  else
    status="양호"
    reason="공유 서비스(FTP/NFS/Samba)에서 익명 접근을 유발하는 설정이 확인되지 않습니다."
  fi

  _json_escape_u35() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u35 "$code")" \
    "$(_json_escape_u35 "$item")" \
    "$(_json_escape_u35 "$severity")" \
    "$(_json_escape_u35 "$status")" \
    "$(_json_escape_u35 "$reason")"
}

U_36() {
  local code="U-36"
  local item="r 계열 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="r 계열 서비스(rlogin/rsh/rexec 등)가 비활성화되어 있습니다."

  local VULN=0
  local REASON=""

  local CHECK_PORT=""
  if command -v ss >/dev/null 2>&1; then
    CHECK_PORT="$(ss -antl 2>/dev/null | grep -E ':512|:513|:514' || true)"
  else
    CHECK_PORT="$(netstat -antl 2>/dev/null | grep -E ':512|:513|:514' || true)"
  fi

  if [ -n "$CHECK_PORT" ]; then
    VULN=1
    REASON="${REASON}r-command 관련 포트(512,513,514)가 리스닝 중입니다. "
  fi

  local SERVICES=("rlogin" "rsh" "rexec" "shell" "login" "exec")
  local SVC
  for SVC in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
      VULN=1
      REASON="${REASON}활성화된 r 계열 서비스 발견: ${SVC}(active). "
    fi
  done

  if [ -d "/etc/xinetd.d" ]; then
    local XINETD_VUL=""
    XINETD_VUL="$(grep -lE "disable\s*=\s*no" \
      /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec \
      /etc/xinetd.d/shell /etc/xinetd.d/login /etc/xinetd.d/exec \
      2>/dev/null || true)"

    if [ -n "$XINETD_VUL" ]; then
      VULN=1
      REASON="${REASON}xinetd 설정에서 disable=no(서비스 활성) 항목이 발견되었습니다: $(echo "$XINETD_VUL" | tr '\n' ' '). "
    fi
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="${REASON:-r 계열 서비스가 활성화된 정황이 확인되었습니다.}"
  else
    status="양호"
    reason="r 계열 서비스(rlogin/rsh/rexec 등)가 비활성화되어 있습니다."
  fi

  _json_escape_u36() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u36 "$code")" \
    "$(_json_escape_u36 "$item")" \
    "$(_json_escape_u36 "$severity")" \
    "$(_json_escape_u36 "$status")" \
    "$(_json_escape_u36 "$reason")"
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
  local reason="DoS 취약 서비스가 비활성화되어 있습니다."

  local in_scope_active=0
  local vulnerable=0
  local evidences=()

  local inetd_services=("echo" "discard" "daytime" "chargen")
  local systemd_sockets=("echo.socket" "discard.socket" "daytime.socket" "chargen.socket")
  local snmp_units=("snmpd.service")
  local dns_units=("named.service" "bind9.service")
  local CHECK_NTP=0
  local ntp_units=("chronyd.service" "ntpd.service" "systemd-timesyncd.service")

  if [ -d /etc/xinetd.d ]; then
    local svc
    for svc in "${inetd_services[@]}"; do
      if [ -f "/etc/xinetd.d/${svc}" ]; then
        local disable_yes_count
        disable_yes_count=$(grep -vE '^\s*#' "/etc/xinetd.d/${svc}" 2>/dev/null \
          | grep -iE '^\s*disable\s*=\s*yes\s*$' | wc -l)

        if [ "$disable_yes_count" -eq 0 ]; then
          in_scope_active=1
          vulnerable=1
          evidences+=("xinetd:${svc} disable=yes 아님(/etc/xinetd.d/${svc})")
        else
          evidences+=("xinetd:${svc} disable=yes")
        fi
      fi
    done
  fi

  if [ -f /etc/inetd.conf ]; then
    local svc
    for svc in "${inetd_services[@]}"; do
      local enable_count
      enable_count=$(grep -vE '^\s*#' /etc/inetd.conf 2>/dev/null | grep -w "$svc" | wc -l)
      if [ "$enable_count" -gt 0 ]; then
        in_scope_active=1
        vulnerable=1
        evidences+=("inetd:${svc} enabled(/etc/inetd.conf)")
      fi
    done
  fi

  if command -v systemctl >/dev/null 2>&1; then
    local sock
    for sock in "${systemd_sockets[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$sock"; then
        if systemctl is-enabled --quiet "$sock" 2>/dev/null || systemctl is-active --quiet "$sock" 2>/dev/null; then
          in_scope_active=1
          vulnerable=1
          evidences+=("systemd:${sock} enabled/active")
        else
          evidences+=("systemd:${sock} disabled/inactive")
        fi
      fi
    done

    local unit
    for unit in "${snmp_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl is-active --quiet "$unit" 2>/dev/null; then
          in_scope_active=1
          vulnerable=1
          evidences+=("SNMP:${unit} enabled/active")
        else
          evidences+=("SNMP:${unit} disabled/inactive")
        fi
      fi
    done

    for unit in "${dns_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl is-active --quiet "$unit" 2>/dev/null; then
          in_scope_active=1
          vulnerable=1
          evidences+=("DNS:${unit} enabled/active")
        else
          evidences+=("DNS:${unit} disabled/inactive")
        fi
      fi
    done

    for unit in "${ntp_units[@]}"; do
      if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
        if systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl is-active --quiet "$unit" 2>/dev/null; then
          if [ "$CHECK_NTP" -eq 1 ]; then
            in_scope_active=1
            vulnerable=1
            evidences+=("NTP:${unit} enabled/active(정책상 포함)")
          else
            evidences+=("info:NTP ${unit} enabled/active(일반적으로 필요)")
          fi
        fi
      fi
    done
  fi

  if [ "$in_scope_active" -eq 0 ]; then
    status="N/A"
    reason="대상 서비스가 사용되지 않아 점검 대상이 아닙니다."
  else
    if [ "$vulnerable" -eq 1 ]; then
      status="취약"
      if [ "${#evidences[@]}" -gt 0 ]; then
        reason="DoS 취약 서비스 활성화 감지: ${evidences[0]}"
      else
        reason="DoS 취약 서비스가 활성화되어 있습니다."
      fi
    else
      status="양호"
      reason="대상 서비스가 존재하나 모두 비활성화 상태입니다."
    fi
  fi

  _json_escape_u38() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/}"
    printf '%s' "$s"
  }

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$(_json_escape_u38 "$code")" \
    "$(_json_escape_u38 "$item")" \
    "$(_json_escape_u38 "$severity")" \
    "$(_json_escape_u38 "$status")" \
    "$(_json_escape_u38 "$reason")"
}

U_39() {
  local code="U-39"
  local item="불필요한 NFS 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="NFS 관련 데몬이 실행 중이지 않습니다."

  local found=0
  local detail=""

  if command -v systemctl >/dev/null 2>&1; then
    local nfs_units=(
      "nfs-server"
      "nfs"
      "nfs-mountd"
      "rpcbind"
      "rpc-statd"
      "rpc-statd-notify"
      "rpc-gssd"
      "rpc-svcgssd"
      "rpc-idmapd"
      "nfs-idmapd"
    )

    local unitfiles
    unitfiles="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')"

    local u
    for u in "${nfs_units[@]}"; do
      if printf '%s\n' "$unitfiles" | grep -qx "${u}.service"; then
        if systemctl is-active --quiet "${u}.service" 2>/dev/null; then
          found=1
          detail+="${u}.service active; "
        fi
      fi
    done

    if systemctl list-units --type=service 2>/dev/null | grep -Eiq 'nfs|rpcbind|statd|mountd|idmapd|gssd'; then
      if [ -z "$detail" ]; then
        found=1
        detail="systemctl 목록에서 nfs/rpc 관련 서비스가 동작 중으로 보입니다."
      fi
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE 'nfs|rpc\.statd|statd|rpc\.lockd|lockd|rpcbind|mountd|idmapd|gssd' \
    | grep -ivE 'grep|kblockd|rstatd' >/dev/null 2>&1; then
    found=1
    if [ -z "$detail" ]; then
      detail="NFS 관련 데몬 프로세스가 실행 중입니다. (ps -ef 기준)"
    fi
  fi

  if [ "$found" -eq 1 ]; then
    status="취약"
    reason="불필요한 NFS 서비스 관련 데몬이 실행 중입니다. (${detail})"
  fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_40() {
  local code="U-40"
  local item="NFS 접근 통제"
  local severity="상"
  local status="양호"
  local reason="불필요한 NFS 서비스를 사용하지 않거나, everyone 공유가 제한되어 있습니다."

  local nfs_running=0
  local detail=""

  if ps -ef 2>/dev/null | grep -iE 'nfs|rpc\.statd|statd|rpc\.lockd|lockd' \
    | grep -ivE 'grep|kblockd|rstatd|' >/dev/null 2>&1; then
    nfs_running=1
  fi

  if [ "$nfs_running" -eq 0 ]; then
    :
  else
    if [ -f /etc/exports ]; then
      local etc_exports_all_count
      local etc_exports_insecure_count
      local etc_exports_directory_count
      local etc_exports_squash_count

      etc_exports_all_count="$(grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | grep '\*' | wc -l)"
      etc_exports_insecure_count="$(grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | grep -i 'insecure' | wc -l)"
      etc_exports_directory_count="$(grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | wc -l)"
      etc_exports_squash_count="$(grep -vE '^#|^\s#' /etc/exports 2>/dev/null | grep '/' | grep -iE 'root_squash|all_squash' | wc -l)"

      if [ "$etc_exports_all_count" -gt 0 ]; then
        status="취약"
        reason="/etc/exports 파일에 '*' 설정이 있습니다. ('*' 설정은 모든 클라이언트에 대해 전체 네트워크 공유를 허용)"
      elif [ "$etc_exports_insecure_count" -gt 0 ]; then
        status="취약"
        reason="/etc/exports 파일에 'insecure' 옵션이 설정되어 있습니다."
      else
        if [ "$etc_exports_directory_count" -ne "$etc_exports_squash_count" ]; then
          status="취약"
          reason="/etc/exports 파일에 'root_squash' 또는 'all_squash' 옵션이 설정되어 있지 않습니다."
        else
          status="양호"
          reason="NFS 사용 중이나 /etc/exports에 everyone 공유('*')가 없고, insecure 옵션이 없으며, root_squash/all_squash가 설정되어 있습니다."
        fi
      fi
    else
      status="취약"
      reason="NFS 관련 데몬이 실행 중이나 /etc/exports 파일이 존재하지 않아 접근 통제 설정을 확인할 수 없습니다."
    fi
  fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_41() {
  local code="U-41"
  local item="불필요한 automountd 제거"
  local severity="상"
  local status="양호"
  local reason="automountd(autofs) 서비스가 비활성화되어 있습니다."

  local vuln=0
  local details=()

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet autofs 2>/dev/null; then
      vuln=1
      details+=("autofs 서비스가 활성화(active) 상태입니다.")
    fi
  fi

  if ps -ef 2>/dev/null | grep -v grep | grep -Ei "automount|autofs" >/dev/null 2>&1; then
    vuln=1
    details+=("automount/autofs 관련 프로세스가 실행 중입니다. (ps -ef 기준)")
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="$(IFS=' '; echo "${details[*]}")"
    else
      reason="automountd(autofs) 관련 서비스/프로세스가 활성화되어 있습니다."
    fi
  fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_42() {
  local code="U-42"
  local item="불필요한 RPC 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="rpcbind 서비스가 비활성화되어 있습니다."

  local vuln=0

  if ! systemctl is-active rpcbind.service &>/dev/null; then
    status="양호"
    reason="rpcbind 서비스가 비활성화되어 있습니다."
  else
    if systemctl is-active nfs-server.service &>/dev/null; then
      status="양호"
      reason="rpcbind가 실행 중이며 nfs-server 서비스가 활성화되어 있어 정상 의존 관계로 판단됩니다."
    else
      vuln=1
      status="취약"
      reason="rpcbind가 실행 중이나 nfs-server 등 대표 의존 서비스가 비활성입니다."
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_43() {
  local code="U-43"
  local item="NIS, NIS+ 점검"
  local severity="상"
  local status="양호"
  local reason="NIS 사용 흔적은 있으나 활성화(실행/enable) 상태는 확인되지 않았습니다."

  local nis_in_use=0
  local vulnerable=0
  local evidences=()

  local nis_procs_regex='ypserv|ypbind|ypxfrd|rpc\.yppasswdd|rpc\.ypupdated|yppasswdd|ypupdated'
  local nisplus_procs_regex='nisplus|rpc\.nisd|nisd'

  if command -v systemctl >/dev/null 2>&1; then
    local nis_units=("ypserv.service" "ypbind.service" "ypxfrd.service")
    local unitfiles
    unitfiles="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')"

    local unit
    for unit in "${nis_units[@]}"; do
      if printf '%s\n' "$unitfiles" | grep -qx "$unit"; then
        if systemctl is-active --quiet "$unit" 2>/dev/null || systemctl is-enabled --quiet "$unit" 2>/dev/null; then
          nis_in_use=1
          vulnerable=1
          evidences+=("systemd: ${unit} 가 active/enabled 상태입니다.")
        fi
      fi
    done

    if printf '%s\n' "$unitfiles" | grep -qx "rpcbind.service"; then
      if systemctl is-active --quiet "rpcbind.service" 2>/dev/null || systemctl is-enabled --quiet "rpcbind.service" 2>/dev/null; then
        evidences+=("info: rpcbind.service 가 active/enabled 입니다. (NIS/RPC 계열 사용 가능성, 단 NIS 단독 증거는 아님)")
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
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(ss). (RPC 사용 흔적)")
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lntup 2>/dev/null | grep -E ':(111)\b' >/dev/null 2>&1; then
      evidences+=("info: TCP/UDP 111(rpcbind) 리스닝 감지(netstat). (RPC 사용 흔적)")
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE "$nisplus_procs_regex" | grep -v grep >/dev/null 2>&1; then
    evidences+=("info: NIS+ 관련 프로세스 흔적이 감지되었습니다. (환경에 따라 양호 조건 충족 가능)")
  fi

  if [ "$nis_in_use" -eq 0 ]; then
    status="N/A"
    reason="NIS 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다. (yp* 서비스/프로세스 미검출)"
    if [ "${#evidences[@]}" -gt 0 ]; then
      reason="${reason} Evidence: $(IFS=' '; echo "${evidences[*]}")"
    fi
  else
    if [ "$vulnerable" -eq 1 ]; then
      status="취약"
      reason="NIS 서비스가 활성화(실행/enable)된 흔적이 확인되었습니다."
      if [ "${#evidences[@]}" -gt 0 ]; then
        reason="${reason} Evidence: $(IFS=' '; echo "${evidences[*]}")"
      fi
    else
      status="양호"
      reason="NIS 사용 흔적은 있으나 활성화(실행/enable) 상태는 확인되지 않았습니다."
      if [ "${#evidences[@]}" -gt 0 ]; then
        reason="${reason} Evidence: $(IFS=' '; echo "${evidences[*]}")"
      fi
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_44() {
  local code="U-44"
  local item="tftp, talk 서비스 비활성화"
  local severity="상"
  local status="양호"
  local reason="tftp/talk/ntalk 서비스가 systemd/xinetd/inetd 설정에서 모두 비활성 상태입니다."

  local services=("tftp" "talk" "ntalk")

  local vuln=0
  local details=()

  if command -v systemctl >/dev/null 2>&1; then
    local unitfiles
    unitfiles="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')"

    local s u
    for s in "${services[@]}"; do
      local units=(
        "$s" "$s.service" "${s}d" "${s}d.service" "${s}-server" "${s}-server.service"
        "tftp-server.service" "tftpd.service" "talkd.service"
      )

      for u in "${units[@]}"; do
        if printf '%s\n' "$unitfiles" | grep -qx "$u"; then
          if systemctl is-active --quiet "$u" 2>/dev/null; then
            vuln=1
            details+=("${s} 서비스가 systemd에서 활성 상태입니다. (unit=${u})")
            break
          fi
        fi
      done

      [ "$vuln" -eq 1 ] && break
    done
  fi

  if [ "$vuln" -eq 0 ] && [ -d /etc/xinetd.d ]; then
    local s disable_line
    for s in "${services[@]}"; do
      if [ -f "/etc/xinetd.d/$s" ]; then
        disable_line="$(grep -vE '^[[:space:]]*#|^[[:space:]]*$' "/etc/xinetd.d/$s" 2>/dev/null \
          | grep -Ei '^[[:space:]]*disable[[:space:]]*=' | tail -n 1)"
        if ! echo "$disable_line" | grep -Eiq 'disable[[:space:]]*=[[:space:]]*yes'; then
          vuln=1
          details+=("${s} 서비스가 /etc/xinetd.d/${s} 에서 비활성화(disable=yes)되어 있지 않습니다.")
          break
        fi
      fi
    done
  fi

  if [ "$vuln" -eq 0 ] && [ -f /etc/inetd.conf ]; then
    local s
    for s in "${services[@]}"; do
      if grep -vE '^[[:space:]]*#|^[[:space:]]*$' /etc/inetd.conf 2>/dev/null \
        | grep -Eiq "(^|[[:space:]])${s}([[:space:]]|$)"; then
        vuln=1
        details+=("${s} 서비스가 /etc/inetd.conf 파일에서 활성 상태(주석 아님)로 존재합니다.")
        break
      fi
    done
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="$(IFS=' '; echo "${details[*]}")"
    else
      reason="tftp/talk/ntalk 관련 설정이 활성화되어 있습니다."
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_45() {
  local code="U-45"
  local item="메일 서비스 버전 점검"
  local severity="상"
  local status="양호"
  local reason="SMTP/Sendmail 실행 흔적이 없거나, 메일 서비스 버전이 기준 버전(8.18.2)입니다."

  local latest_ver="8.18.2"
  local service_detected=0
  local details=()

  if [ -f /etc/services ]; then
    local smtp_ports=()
    mapfile -t smtp_ports < <(
      grep -vE '^#|^\s#' /etc/services 2>/dev/null \
        | awk 'tolower($1)=="smtp" {print $2}' \
        | awk -F/ 'tolower($2)=="tcp" {print $1}' \
        | sort -u
    )

    if [ "${#smtp_ports[@]}" -gt 0 ] && command -v netstat >/dev/null 2>&1; then
      local p
      for p in "${smtp_ports[@]}"; do
        if netstat -nat 2>/dev/null \
          | grep -w 'tcp' \
          | grep -Ei 'listen|established|syn_sent|syn_received' \
          | grep -q ":${p} " ; then
          service_detected=1
          details+=("netstat에서 SMTP 포트(${p}) 사용 흔적이 감지되었습니다.")
          break
        fi
      done
    fi
  fi

  if ps -ef 2>/dev/null | grep -iE 'smtp|sendmail' | grep -v 'grep' >/dev/null 2>&1; then
    service_detected=1
    details+=("프로세스에서 smtp/sendmail 실행 흔적이 감지되었습니다.")
  fi

  if [ "$service_detected" -eq 1 ]; then
    local rpm_smtp_version=""
    local dnf_smtp_version=""

    if command -v rpm >/dev/null 2>&1; then
      rpm_smtp_version="$(rpm -qa 2>/dev/null | grep 'sendmail' | awk -F 'sendmail-' '{print $2}' | head -n 1)"
    fi
    if command -v dnf >/dev/null 2>&1; then
      dnf_smtp_version="$(dnf list installed sendmail 2>/dev/null | grep -v 'Installed Packages' | awk '{print $2}' | head -n 1)"
    fi

    if [[ "$rpm_smtp_version" != ${latest_ver}* ]] && [[ "$dnf_smtp_version" != ${latest_ver}* ]]; then
      status="취약"
      reason="메일 서비스 버전이 최신 버전(${latest_ver})이 아닙니다. (rpm=${rpm_smtp_version:-N/A}, dnf=${dnf_smtp_version:-N/A})"
      if [ "${#details[@]}" -gt 0 ]; then
        reason="${reason} Evidence: $(IFS=' '; echo "${details[*]}")"
      fi
    else
      status="양호"
      reason="메일 서비스가 감지되었으며 sendmail 버전이 기준 버전(${latest_ver})입니다. (rpm=${rpm_smtp_version:-N/A}, dnf=${dnf_smtp_version:-N/A})"
      if [ "${#details[@]}" -gt 0 ]; then
        reason="${reason} Evidence: $(IFS=' '; echo "${details[*]}")"
      fi
    fi
  else
    status="양호"
    reason="SMTP/Sendmail 실행 흔적이 없습니다."
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_46() {
  local code="U-46"
  local item="일반 사용자의 메일 서비스 실행 방지"
  local severity="상"
  local status="양호"
  local reason="Sendmail이 실행 중이지 않거나, 일반 사용자의 메일 서비스 실행 방지(restrictqrun)가 설정되어 있습니다."

  local vuln=0
  local details=()

  if ps -ef 2>/dev/null | grep -v grep | grep -q "sendmail"; then
    if [ -f "/etc/mail/sendmail.cf" ]; then
      local check=""
      check="$(grep -i "PrivacyOptions" /etc/mail/sendmail.cf 2>/dev/null | grep -i "restrictqrun" || true)"
      if [ -z "$check" ]; then
        vuln=1
        details+=("Sendmail 서비스가 실행 중이며, PrivacyOptions에 restrictqrun이 설정되어 있지 않습니다.")
      fi
    else
      vuln=1
      details+=("Sendmail 서비스가 실행 중이나 /etc/mail/sendmail.cf 설정파일이 존재하지 않습니다.")
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="$(IFS=' '; echo "${details[*]}")"
    else
      reason="Sendmail 관련 설정이 미흡합니다."
    fi
  else
    if ps -ef 2>/dev/null | grep -v grep | grep -q "sendmail"; then
      reason="Sendmail 서비스가 실행 중이며, PrivacyOptions에 restrictqrun 설정이 확인됩니다."
    else
      reason="Sendmail 서비스가 실행 중이지 않습니다."
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_47() {
  local code="U-47"
  local item="스팸 메일 릴레이 제한"
  local severity="상"
  local status="양호"
  local reason="메일 서버가 오픈 릴레이(open relay)로 동작하지 않도록 릴레이 제한 설정이 적용된 것으로 판단됩니다."

  local vuln=0

  if systemctl is-active postfix.service &>/dev/null || command -v postconf &>/dev/null; then
    if command -v postconf &>/dev/null; then
      local relay_restr recip_restr mynet
      relay_restr="$(postconf -h smtpd_relay_restrictions 2>/dev/null)"
      recip_restr="$(postconf -h smtpd_recipient_restrictions 2>/dev/null)"
      mynet="$(postconf -h mynetworks 2>/dev/null)"

      local has_reject=0
      echo "$relay_restr $recip_restr" | grep -q "reject_unauth_destination" && has_reject=1

      local net_ok=1
      echo "$mynet" | grep -Eq '0\.0\.0\.0/0|::/0' && net_ok=0

      if (( has_reject == 1 && net_ok == 1 )); then
        status="양호"
        reason="Postfix 설정에서 reject_unauth_destination이 확인되며, mynetworks가 0.0.0.0/0 또는 ::/0로 과다 설정되지 않았습니다."
      else
        vuln=1
        status="취약"
        reason="Postfix 설정에서 reject_unauth_destination 누락 또는 mynetworks 과다 설정 가능성이 있습니다."
      fi
    else
      vuln=1
      status="취약"
      reason="Postfix가 동작 중으로 보이나 postconf 명령이 없어 설정을 확인할 수 없습니다."
    fi
  fi

  if (( vuln == 0 )); then
    if systemctl is-active sendmail.service &>/dev/null || command -v sendmail &>/dev/null; then
      vuln=1
      status="취약"
      reason="Sendmail 사용 중: 오픈 릴레이 제한 설정을 수동 확인해야 합니다."
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_48() {
  local code="U-48"
  local item="expn, vrfy 명령어 제한"
  local severity="중"
  local status="양호"
  local reason="메일(SMTP) 서비스 사용 시 expn/vrfy 제한 설정이 확인되었습니다."

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
    local unitfiles
    unitfiles="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')"

    local unit
    for unit in sendmail.service postfix.service exim4.service; do
      if printf '%s\n' "$unitfiles" | grep -qx "$unit"; then
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
    reason="메일(SMTP) 서비스를 사용하지 않는 것으로 확인되어 점검 대상이 아닙니다. (25/tcp LISTEN 및 MTA 미검출)"
  else
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

          local goaway_count
          local noexpn_novrfy_count

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
        evidences+=("sendmail: 실행 흔적은 있으나 sendmail.cf 파일을 찾지 못했습니다. (설정 점검 불가)")
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
          | grep -iE '^\s*disable_vrfy_command\s*=\s*yes\s*$' | wc -l)"

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
        evidences+=("postfix: postfix 사용 흔적은 있으나 /etc/postfix/main.cf 파일이 없습니다. (설정 점검 불가)")
      fi
    fi

    if [ "$has_exim" -eq 1 ]; then
      evidences+=("exim: exim 사용 흔적 감지(구성 파일 기반 vrfy/expn 제한 수동 확인 필요)")
    fi

    if [ "$vulnerable" -eq 1 ]; then
      status="취약"
      reason="메일(SMTP) 서비스 사용 중이며 expn/vrfy 제한 설정이 미흡합니다. (미설정/점검불가=${bad_cnt}, 설정확인=${ok_cnt})"
      if [ "${#evidences[@]}" -gt 0 ]; then
        reason="${reason} Evidence: $(IFS=' '; echo "${evidences[*]}")"
      fi
    else
      status="양호"
      reason="메일(SMTP) 서비스 사용 중이며 expn/vrfy 제한 설정이 확인되었습니다. (설정확인=${ok_cnt})"
      if [ "${#evidences[@]}" -gt 0 ]; then
        reason="${reason} Evidence: $(IFS=' '; echo "${evidences[*]}")"
      fi
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_49() {
  local code="U-49"
  local item="DNS 보안 버전 패치"
  local severity="상"
  local status="양호"
  local reason="DNS 서비스를 사용하지 않거나, BIND 버전이 기준 이상으로 관리되고 있습니다."

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
  else
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
      reason="named는 동작 중이나 BIND 버전을 확인하지 못했습니다. (named -v / rpm -q bind 실패)"
    else
      major="$(echo "$bind_ver" | awk -F. '{print $1}')"
      minor="$(echo "$bind_ver" | awk -F. '{print $2}')"
      patch="$(echo "$bind_ver" | awk -F. '{print $3}')"

      if [ "$major" -ne 9 ]; then
        status="취약"
        reason="BIND 메이저 버전이 9가 아닙니다. (현재: ${bind_ver})"
      elif [ "$minor" -ge 19 ]; then
        status="취약"
        reason="BIND ${bind_ver} 는 9.19+ (개발/테스트 버전으로 간주) 입니다. 운영 권고 버전(9.18.7 이상)으로 관리 필요."
      elif [ "$minor" -lt 18 ]; then
        status="취약"
        reason="BIND 버전이 9.18 미만입니다. (현재: ${bind_ver}, 기준: 9.18.7 이상)"
      else
        if [ "$patch" -lt 7 ]; then
          status="취약"
          reason="BIND 버전이 최신 버전(9.18.7 이상)이 아닙니다. (현재: ${bind_ver})"
        else
          status="양호"
          reason="DNS 서비스 사용 중이며 BIND 버전이 기준 이상입니다. (현재: ${bind_ver})"
        fi
      fi
    fi
  fi
  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_50() {
  local code="U-50"
  local item="DNS Zone Transfer 설정"
  local severity="상"
  local status="양호"
  local reason="DNS(named) 서비스 미사용 또는 allow-transfer가 전체(any)로 허용되어 있지 않습니다."

  local ps_dns_count=0
  local allow_any_count=0

  ps_dns_count=$(ps -ef 2>/dev/null | grep -i 'named' | grep -v 'grep' | wc -l)

  if [ "$ps_dns_count" -gt 0 ]; then
    if [ -f /etc/named.conf ]; then
      allow_any_count=$(grep -vE '^#|^\s#' /etc/named.conf 2>/dev/null \
        | grep -i 'allow-transfer' | grep -i 'any' | wc -l)

      if [ "$allow_any_count" -gt 0 ]; then
        status="취약"
        reason="/etc/named.conf 파일에 allow-transfer { any; } 설정이 있습니다."
      fi
    else
      status="취약"
      reason="named 프로세스는 실행 중이나 /etc/named.conf 파일이 존재하지 않아 Zone Transfer 설정을 점검할 수 없습니다."
    fi
  else
    status="양호"
    reason="DNS(named) 서비스가 실행 중이지 않습니다."
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_51() {
  local code="U-51"
  local item="DNS 서비스의 취약한 동적 업데이트 설정 금지"
  local severity="중"
  local status="양호"
  local reason="DNS(named) 서비스가 실행 중이지 않거나, allow-update 전체 허용(any) 설정이 확인되지 않았습니다."

  local vuln=0
  local details=()

  if ps -ef 2>/dev/null | grep -v grep | grep -q "named"; then
    local CONF="/etc/named.conf"
    local CONF_FILES=("$CONF")

    if [ -f "$CONF" ]; then
      local extracted_paths
      extracted_paths="$(grep -E '^\s*(include|file)' "$CONF" 2>/dev/null | awk -F'"' '{print $2}')"

      local in_file
      for in_file in $extracted_paths; do
        if [ -f "$in_file" ]; then
          CONF_FILES+=("$in_file")
        elif [ -f "/etc/$in_file" ]; then
          CONF_FILES+=("/etc/$in_file")
        elif [ -f "/var/named/$in_file" ]; then
          CONF_FILES+=("/var/named/$in_file")
        fi
      done
    fi

    local file check
    for file in "${CONF_FILES[@]}"; do
      if [ -f "$file" ]; then
        check="$(grep -vE '^\s*//|^\s*#|^\s*/\*' "$file" 2>/dev/null \
          | grep -i "allow-update" \
          | grep -Ei 'any|\{\s*any\s*;\s*\}')"
        if [ -n "$check" ]; then
          vuln=1
          details+=("${file} 파일에서 동적 업데이트가 전체(any)로 허용되어 있습니다.")
        fi
      fi
    done
  else
    status="양호"
    reason="DNS(named) 서비스가 실행 중이지 않습니다."
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    reason="$(IFS=' '; echo "${details[*]}")"
  else
    if ps -ef 2>/dev/null | grep -v grep | grep -q "named"; then
      status="양호"
      reason="DNS(named) 서비스 사용 중이나 allow-update 전체 허용(any) 설정이 확인되지 않았습니다."
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_52() {
  local code="U-52"
  local item="Telnet 서비스 비활성화"
  local severity="중"
  local status="양호"
  local reason="Telnet(23/tcp) 활성화 징후가 확인되지 않았습니다."

  local vuln=0
  local details=()

  add_detail() { details+=("$1"); }

  local listen23=""
  listen23="$(ss -lntp 2>/dev/null | awk '$4 ~ /:23$/ {print}' | head -n 1)"
  if [ -n "$listen23" ]; then
    vuln=1
    add_detail "23/tcp LISTEN 감지"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    local units=("telnet.socket" "telnet.service" "telnet@.service" "telnetd.service")
    local unitfiles
    unitfiles="$(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}')"

    local u
    for u in "${units[@]}"; do
      if printf '%s\n' "$unitfiles" | grep -qx "$u"; then
        local is_act="inactive" is_en="disabled"
        systemctl is-active "$u" &>/dev/null && is_act="active"
        systemctl is-enabled "$u" &>/dev/null && is_en="enabled"
        if [ "$is_act" = "active" ] || [ "$is_en" = "enabled" ]; then
          vuln=1
          add_detail "${u} 상태: ${is_act}/${is_en}"
        fi
      fi
    done
  fi

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
    if [ "${#details[@]}" -gt 0 ]; then
      reason="Telnet 활성화 징후: ${details[0]}"
    else
      reason="Telnet 활성화 징후가 확인되었습니다."
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_53() {
  local code="U-53"
  local item="FTP 서비스 정보 노출 제한"
  local severity="하"
  local status="양호"
  local reason="FTP 접속 배너에 서비스명/버전 등 불필요한 정보 노출 징후가 확인되지 않았습니다."

  local listen_info=""
  if command -v ss >/dev/null 2>&1; then
    listen_info="$(ss -ltnp 2>/dev/null | awk '$4 ~ /:21$/ {print}' | head -n 1)"
  else
    listen_info="$(netstat -ltnp 2>/dev/null | awk '$4 ~ /:21$/ {print}' | head -n 1)"
  fi

  if [ -z "$listen_info" ]; then
    status="N/A"
    reason="FTP 서비스(21/tcp)가 리스닝 상태가 아니므로 점검 대상이 아닙니다."
  else
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
      reason="FTP 접속 배너에 서비스명/버전 등 불필요한 정보 노출 가능성이 있습니다."
      if [ -n "$daemon" ]; then
        reason="${reason} (daemon=${daemon})"
      fi
      if [ -n "$banner" ]; then
        reason="${reason} (banner=${banner})"
      fi
    else
      status="양호"
      reason="FTP 접속 배너에 노출되는 정보가 없거나 서비스명/버전 노출 패턴이 확인되지 않았습니다."
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_54() {
  local code="U-54"
  local item="암호화되지 않는 FTP 서비스 비활성화"
  local severity="중"
  local status="양호"
  local reason="암호화되지 않은 FTP 서비스(vsftpd/proftpd 등) 활성 징후가 확인되지 않았습니다."

  local ftp_active=0
  local details=()

  add_detail() { details+=("$1"); }

  if command -v systemctl >/dev/null 2>&1; then
    local svc
    for svc in vsftpd proftpd; do
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ftp_active=1
        add_detail "${svc} 활성"
      fi
    done
  fi

  if [ -d /etc/xinetd.d ]; then
    if grep -rEi "disable[[:space:]]*=[[:space:]]*no" /etc/xinetd.d/ 2>/dev/null | grep -qi "ftp"; then
      ftp_active=1
      add_detail "xinetd 내 ftp 활성 설정(disable=no) 발견"
    fi
  fi

  if [ "$ftp_active" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="$(IFS='; '; echo "${details[*]}")"
    else
      reason="FTP 서비스 활성 징후가 확인되었습니다."
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_55() {
  local code="U-55"
  local item="FTP 계정 Shell 제한"
  local severity="중"
  local status="양호"
  local reason="FTP 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되어 있습니다."

  if command -v rpm >/dev/null 2>&1; then
    if ! rpm -qa 2>/dev/null | egrep -qi 'vsftpd|proftpd'; then
      status="양호"
      reason="FTP 서비스가 미설치되어 있습니다."
      reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
      local reason_json="$reason"
      reason_json="${reason_json//\\/\\\\}"
      reason_json="${reason_json//\"/\\\"}"
      printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
        "$code" "$item" "$severity" "$status" "$reason_json"
      return 0
    fi
  fi

  local ftp_users=("ftp" "vsftpd" "proftpd")
  local ftp_exist=0
  local ftp_vuln=0
  local bad_users=()

  local user shell
  for user in "${ftp_users[@]}"; do
    if id "$user" >/dev/null 2>&1; then
      ftp_exist=1
      shell="$(grep "^${user}:" /etc/passwd 2>/dev/null | awk -F: '{print $7}' | head -n 1)"
      if [ "$shell" != "/bin/false" ] && [ "$shell" != "/sbin/nologin" ]; then
        ftp_vuln=1
        bad_users+=("${user}(shell=${shell:-미확인})")
      fi
    fi
  done

  if [ "$ftp_exist" -eq 0 ]; then
    status="양호"
    reason="FTP 계정이 존재하지 않습니다."
  elif [ "$ftp_vuln" -eq 1 ]; then
    status="취약"
    if [ "${#bad_users[@]}" -gt 0 ]; then
      reason="FTP 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되어 있지 않습니다. (대상: $(IFS=,; echo "${bad_users[*]}"))"
    else
      reason="FTP 계정에 /bin/false 쉘이 부여되어 있지 않습니다."
    fi
  else
    status="양호"
    reason="FTP 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여되어 있습니다."
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_56() {
  local code="U-56"
  local item="FTP 서비스 접근 제어 설정"
  local severity="하"
  local status="양호"
  local reason="FTP 서비스가 실행 중이지 않거나, FTP 접근 제어 설정(관련 파일/설정)이 확인됩니다."

  local vuln=0
  local details=()

  add_detail() { details+=("$1"); }

  if ps -ef 2>/dev/null | grep -v grep | grep -q "vsftpd"; then
    local CONF="/etc/vsftpd/vsftpd.conf"
    [ -f "$CONF" ] || CONF="/etc/vsftpd.conf"

    if [ -f "$CONF" ]; then
      local userlist_enable=""
      userlist_enable="$(grep -vE "^\s*#" "$CONF" 2>/dev/null | grep -i "userlist_enable" | awk -F= '{print $2}' | tr -d ' ' | tr '[:lower:]' '[:upper:]' | tail -n 1)"

      if [ "$userlist_enable" = "YES" ]; then
        if [ ! -f "/etc/vsftpd/user_list" ] && [ ! -f "/etc/vsftpd.user_list" ]; then
          vuln=1
          add_detail "vsftpd(userlist_enable=YES) 사용 중이나 접근 제어 파일(user_list)이 없습니다."
        fi
      else
        if [ ! -f "/etc/vsftpd/ftpusers" ] && [ ! -f "/etc/vsftpd.ftpusers" ]; then
          vuln=1
          add_detail "vsftpd(userlist_enable=NO/미설정) 사용 중이나 접근 제어 파일(ftpusers)이 없습니다."
        fi
      fi
    else
      vuln=1
      add_detail "vsftpd 서비스가 실행 중이나 설정파일을 찾을 수 없습니다."
    fi

  elif ps -ef 2>/dev/null | grep -v grep | grep -q "proftpd"; then
    local CONF="/etc/proftpd.conf"
    [ -f "$CONF" ] || CONF="/etc/proftpd/proftpd.conf"

    if [ -f "$CONF" ]; then
      local u_f_u=""
      u_f_u="$(grep -vE "^\s*#" "$CONF" 2>/dev/null | grep -i "UseFtpUsers" | awk '{print $2}' | tr '[:upper:]' '[:lower:]' | tail -n 1)"

      if [ -z "$u_f_u" ] || [ "$u_f_u" = "on" ]; then
        if [ ! -f "/etc/ftpusers" ] && [ ! -f "/etc/ftpd/ftpusers" ]; then
          vuln=1
          add_detail "proftpd(UseFtpUsers=on/기본) 사용 중이나 접근 제어 파일(ftpusers)이 없습니다."
        fi
      else
        local limit=""
        limit="$(grep -i "<Limit LOGIN>" "$CONF" 2>/dev/null | head -n 1)"
        if [ -z "$limit" ]; then
          vuln=1
          add_detail "proftpd(UseFtpUsers=off) 사용 중이나 설정 파일 내 <Limit LOGIN> 접근 제어 설정이 없습니다."
        fi
      fi
    else
      vuln=1
      add_detail "proftpd 서비스가 실행 중이나 설정파일을 찾을 수 없습니다."
    fi
  fi

  if [ "$vuln" -eq 1 ]; then
    status="취약"
    if [ "${#details[@]}" -gt 0 ]; then
      reason="$(IFS=' '; echo "${details[*]}")"
    else
      reason="FTP 접근 제어 설정이 미흡합니다."
    fi
  else
    if ps -ef 2>/dev/null | grep -v grep | grep -Eq "vsftpd|proftpd"; then
      reason="FTP 서비스 사용 중이며 접근 제어 관련 파일/설정이 확인됩니다."
    else
      reason="FTP 서비스가 실행 중이지 않습니다."
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_57() {
  local code="U-57"
  local item="Ftpusers 파일 설정"
  local severity="중"
  local status="양호"
  local reason="FTP 사용 시 접속 금지 사용자(root 등) 차단이 적절히 설정되어 있습니다."

  local vuln=0

  local ftp_running=0
  if command -v systemctl >/dev/null 2>&1; then
    local svc
    for svc in vsftpd.service proftpd.service pure-ftpd.service; do
      if systemctl is-active "$svc" &>/dev/null; then
        ftp_running=1
        break
      fi
    done
  fi

  if [ "$ftp_running" -eq 0 ]; then
    status="양호"
    reason="FTP 서비스가 동작 중이지 않아 점검 대상 위험이 없습니다."
  else
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
      status="취약"
      reason="Ftpusers/user_list 후보 파일을 찾지 못했습니다."
    else
      local has_root=0
      grep -Eq '^[[:space:]]*root([[:space:]]|$)' "$file_found" 2>/dev/null && has_root=1

      local owner perm
      owner="$(stat -Lc '%U' "$file_found" 2>/dev/null)"
      perm="$(stat -Lc '%a' "$file_found" 2>/dev/null)"

      if [ "$owner" != "root" ]; then
        vuln=1
        status="취약"
        reason="${file_found} 소유자가 root가 아닙니다. (owner=${owner:-확인불가})"
      fi

      if [ "$vuln" -eq 0 ]; then
        local oct="0$perm"
        if [ -n "$perm" ] && (( (oct & 18) != 0 )); then
          vuln=1
          status="취약"
          reason="${file_found} 그룹/기타 쓰기 권한이 존재합니다. (perm=${perm:-확인불가})"
        fi
      fi

      if [ "$vuln" -eq 0 ] && [ "$has_root" -eq 0 ]; then
        vuln=1
        status="취약"
        reason="${file_found} 차단 목록에 root가 포함되어 있지 않습니다."
      fi

      if [ "$vuln" -eq 0 ]; then
        status="양호"
        reason="FTP 서비스 사용 중이며 차단 목록 파일(${file_found})에 root 포함 및 권한/소유자가 적절합니다. (owner=${owner:-확인불가}, perm=${perm:-확인불가})"
      fi
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_58() {
  local code="U-58"
  local item="불필요한 SNMP 서비스 구동 점검"
  local severity="중"
  local status="양호"
  local reason="SNMP 서비스(snmpd/snmptrapd) 사용 징후가 확인되지 않았습니다."

  local found=0
  local found_reason=""

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet snmpd 2>/dev/null; then
      found=1
      found_reason="snmpd 서비스가 활성(Active) 상태입니다."
    elif systemctl is-active --quiet snmptrapd 2>/dev/null; then
      found=1
      found_reason="snmptrapd 서비스가 활성(Active) 상태입니다."
    fi
  fi

  if [ "$found" -eq 0 ] && command -v pgrep >/dev/null 2>&1; then
    if pgrep -x snmpd >/dev/null 2>&1; then
      found=1
      found_reason="snmpd 프로세스가 실행 중입니다."
    elif pgrep -x snmptrapd >/dev/null 2>&1; then
      found=1
      found_reason="snmptrapd 프로세스가 실행 중입니다."
    fi
  fi

  if [ "$found" -eq 0 ]; then
    if command -v ss >/dev/null 2>&1; then
      if ss -lunp 2>/dev/null | awk '$5 ~ /:(161|162)$/ {print}' | head -n 1 | grep -q .; then
        found=1
        found_reason="SNMP 포트(161/162 UDP)가 리스닝 상태입니다."
      fi
    elif command -v netstat >/dev/null 2>&1; then
      if netstat -lunp 2>/dev/null | awk '$4 ~ /:(161|162)$/ {print}' | head -n 1 | grep -q .; then
        found=1
        found_reason="SNMP 포트(161/162 UDP)가 리스닝 상태입니다."
      fi
    fi
  fi

  if [ "$found" -eq 1 ]; then
    status="취약"
    reason="SNMP 서비스를 사용하고 있습니다. ${found_reason}"
  else
    status="양호"
    reason="SNMP 서비스를 사용하지 않는 것으로 확인됩니다."
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_59() {
  local code="U-59"
  local item="안전한 SNMP 버전 사용"
  local severity="상"
  local status="양호"
  local reason="SNMP 서비스를 v3 이상으로 사용하는 것으로 확인됩니다."

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
    status="N/A"
    reason="SNMP 서비스(snmpd)가 비활성/미사용 상태입니다."
  else
    if [ -f "$snmpd_conf" ]; then
      cfg_files+=("$snmpd_conf")
      cfg_exists_count=$((cfg_exists_count+1))
    fi
    if [ -f "$snmpd_persist" ]; then
      cfg_files+=("$snmpd_persist")
      cfg_exists_count=$((cfg_exists_count+1))
    fi

    if [ "$cfg_exists_count" -eq 0 ]; then
      status="취약"
      reason="snmpd는 활성 상태이나 설정 파일이 없습니다. (${snmpd_conf} / ${snmpd_persist} 미존재)"
    else
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
        reason="SNMPv3 설정(createUser(SHA+AES) 및 rouser/rwuser)이 확인되었습니다."
      else
        status="취약"
        reason="snmpd는 활성 상태이나 SNMPv3 필수 설정이 미흡합니다. (createUser(SHA+AES) 또는 rouser/rwuser 미확인)"
      fi
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_60() {
  local code="U-60"
  local item="SNMP Community String 복잡성 설정"
  local severity="중"
  local status="양호"
  local reason="SNMP Community String 복잡성 기준을 만족합니다."

  local vuln_flag=0
  local community_found=0

  local ps_snmp_count
  ps_snmp_count="$(ps -ef 2>/dev/null | grep -iE 'snmpd|snmptrapd' | grep -v 'grep' | wc -l)"
  if [ "${ps_snmp_count:-0}" -eq 0 ]; then
    status="양호"
    reason="SNMP 서비스가 미설치/미사용 상태입니다."
  else
    local snmpdconf_files=()
    [ -f /etc/snmp/snmpd.conf ] && snmpdconf_files+=("/etc/snmp/snmpd.conf")
    [ -f /usr/local/etc/snmp/snmpd.conf ] && snmpdconf_files+=("/usr/local/etc/snmp/snmpd.conf")
    while IFS= read -r f; do
      snmpdconf_files+=("$f")
    done < <(find /etc -maxdepth 4 -type f -name 'snmpd.conf' 2>/dev/null | sort -u)

    if [ ${#snmpdconf_files[@]} -gt 0 ]; then
      mapfile -t snmpdconf_files < <(printf "%s\n" "${snmpdconf_files[@]}" | awk '!seen[$0]++')
    fi

    if [ ${#snmpdconf_files[@]} -eq 0 ]; then
      status="취약"
      reason="SNMP 서비스를 사용하고 있으나 Community String을 설정하는 파일(snmpd.conf)이 없습니다."
    else
      is_strong_community() {
        local s="$1"
        s="${s%\"}"; s="${s#\"}"
        s="${s%\'}"; s="${s#\'}"

        echo "$s" | grep -qiE '^(public|private)$' && return 1

        local len=${#s}
        local has_alpha=0
        local has_digit=0
        local has_special=0

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

      local i
      for ((i=0; i<${#snmpdconf_files[@]}; i++)); do
        local file="${snmpdconf_files[$i]}"

        while IFS= read -r comm; do
          community_found=1
          if ! is_strong_community "$comm"; then
            vuln_flag=1
          fi
        done < <(grep -vE '^\s*#|^\s*$' "$file" 2>/dev/null \
          | awk 'tolower($1) ~ /^(rocommunity6?|rwcommunity6?)$/ {print $2}')

        while IFS= read -r comm; do
          community_found=1
          if ! is_strong_community "$comm"; then
            vuln_flag=1
          fi
        done < <(grep -vE '^\s*#|^\s*$' "$file" 2>/dev/null \
          | awk 'tolower($1)=="com2sec" {print $4}')
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
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_61() {
  local code="U-61"
  local item="SNMP Access Control 설정"
  local severity="상"
  local status="양호"
  local reason="SNMP 서비스에 대한 접근 제어 설정이 적절한 것으로 확인됩니다."

  local VULN=0
  local REASON=""

  if ps -ef 2>/dev/null | grep -v grep | grep -q "snmpd" ; then
    local CONF="/etc/snmp/snmpd.conf"

    if [ -f "$CONF" ]; then
      local CHECK_COM2SEC CHECK_COMM
      CHECK_COM2SEC="$(grep -vE "^\s*#" "$CONF" 2>/dev/null | grep -E "^\s*com2sec" | awk '$3=="default" {print $0}')"
      CHECK_COMM="$(grep -vE "^\s*#" "$CONF" 2>/dev/null | grep -Ei "^\s*(ro|rw)community6?|^\s*(ro|rw)user")"

      local IS_COMM_VULN=0
      if [ -n "$CHECK_COMM" ]; then
        while read -r line; do
          local COMM_STR SOURCE_IP
          COMM_STR="$(echo "$line" | awk '{print $2}')"
          SOURCE_IP="$(echo "$line" | awk '{print $3}')"

          if [ "$SOURCE_IP" = "default" ] || echo "$COMM_STR" | grep -Eqi 'public|private'; then
            IS_COMM_VULN=1
            break
          fi
        done <<< "$CHECK_COMM"
      fi

      if [ -n "$CHECK_COM2SEC" ] || [ "$IS_COMM_VULN" -eq 1 ]; then
        VULN=1
        REASON="${REASON}SNMP 설정 파일(${CONF})에 모든 호스트 접근을 허용하는 설정이 존재합니다. |"
      fi
    else
      VULN=1
      REASON="${REASON}SNMP 서비스가 실행 중이고, 설정 파일을 찾을 수 없습니다. |"
    fi
  else
    :
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  else
    status="양호"
    reason="SNMP 서비스가 실행 중이 아니거나, 모든 호스트 접근 허용(default/public/private) 설정이 확인되지 않습니다."
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[|]/ /g; s/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_62() {
  local code="U-62"
  local item="로그인 시 경고 메시지 설정"
  local severity="하"
  local status="양호"
  local reason="로그인 경고 메시지(비인가 접근 금지) 문구가 설정되어 있습니다."

  local -a warn_files=("/etc/issue" "/etc/issue.net" "/etc/motd")
  local -a candidates=()
  local f

  for f in "${warn_files[@]}"; do
    [ -r "$f" ] && candidates+=("$f")
  done

  if command -v sshd >/dev/null 2>&1; then
    local banner
    banner="$(sshd -T 2>/dev/null | awk '/^banner /{print $2}' | tail -n1)"
    if [ -n "$banner" ] && [ "$banner" != "none" ] && [ -r "$banner" ]; then
      candidates+=("$banner")
    fi
  fi

  if [ "${#candidates[@]}" -eq 0 ]; then
    status="취약"
    reason="경고 메시지 파일(/etc/issue, /etc/issue.net, /etc/motd, sshd Banner)을 확인할 수 없습니다."
  else
    local found=0
    local best_file=""
    local kw
    local -a keywords=("unauthorized" "authorized" "warning" "prohibited" "무단" "불법" "경고" "허가" "접근 금지" "접속 금지")

    for f in "${candidates[@]}"; do
      local content
      content="$(tr -d '\000' < "$f" 2>/dev/null | head -n 50 | tr '[:upper:]' '[:lower:]')"
      [ -n "$content" ] || continue

      for kw in "${keywords[@]}"; do
        if echo "$content" | grep -q "$(echo "$kw" | tr '[:upper:]' '[:lower:]')"; then
          found=1
          best_file="$f"
          break 2
        fi
      done
    done

    if [ "$found" -eq 1 ]; then
      status="양호"
      reason="경고 메시지 문구가 확인되었습니다. (파일: ${best_file})"
    else
      status="취약"
      reason="관련 파일은 존재하나 '비인가 접근 금지' 성격의 경고 문구를 찾지 못했습니다. (대상: ${candidates[*]})"
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}
U_63() {
  local code="U-63"
  local item="sudo 명령어 접근 관리"
  local severity="중"
  local status="양호"
  local reason="/etc/sudoers 소유자/권한이 기준에 부합합니다. (owner=root, perm=640)"

  if [ ! -e /etc/sudoers ]; then
    status="N/A"
    reason="/etc/sudoers 파일이 존재하지 않아 점검 대상이 아닙니다."
  else
    local owner perm
    owner="$(stat -c %U /etc/sudoers 2>/dev/null)"
    perm="$(stat -c %a /etc/sudoers 2>/dev/null)"

    if [ -z "$owner" ] || [ -z "$perm" ]; then
      status="점검불가"
      reason="/etc/sudoers 권한 정보를 숫자(예: 640)로 확인할 수 없습니다."
    else
      if [ "$owner" = "root" ] && [ "$perm" = "640" ]; then
        status="양호"
        reason="/etc/sudoers 소유자: ${owner}, 권한: ${perm}"
      else
        status="취약"
        reason="/etc/sudoers 소유자 또는 권한 설정이 기준에 부합하지 않습니다. (현재 owner=${owner}, perm=${perm})"
      fi
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}


U_64() {
  local code="U-64"
  local item="주기적 보안 패치 및 벤더 권고사항 적용"
  local severity="상"
  local status="양호"
  local reason="보안 업데이트 미적용 항목이 없고, 최신 커널로 부팅된 것으로 확인됩니다."

  local running_kernel latest_kernel pending_updates
  running_kernel="$(uname -r 2>/dev/null)"
  latest_kernel=""
  pending_updates=""

  if command -v dnf >/dev/null 2>&1; then
    pending_updates="$(dnf updateinfo list --updates security -q 2>/dev/null | grep -i "security" || true)"
  fi

  if command -v rpm >/dev/null 2>&1; then
    latest_kernel="$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -n 1)"
  fi

  if [ -n "$pending_updates" ]; then
    status="취약"
    reason="미적용된 보안 업데이트가 존재합니다."
  elif [ -n "$latest_kernel" ] && [[ "$running_kernel" != *"$latest_kernel"* ]]; then
    status="취약"
    reason="최신 커널 설치 후 재부팅이 되지 않았습니다. (Running: ${running_kernel:-확인불가} / Latest: ${latest_kernel})"
  else
    status="양호"
    reason="보안 업데이트 미적용 항목이 없고, 커널 상태가 기준에 부합합니다."
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_65() {
  local code="U-65"
  local item="NTP 및 시각 동기화 설정"
  local severity="중"
  local status="양호"
  local reason="NTP 및 시각 동기화 설정이 기준에 따라 적용된 것으로 확인됩니다."

  local timedatectl_ntp time_sync_state
  timedatectl_ntp="$(timedatectl show -p NTP --value 2>/dev/null | tr -d '\r')"
  time_sync_state="$(timedatectl show -p NTPSynchronized --value 2>/dev/null | tr -d '\r')"

  if [ "$time_sync_state" = "yes" ] && [ "$timedatectl_ntp" = "yes" ]; then
    status="양호"
    reason="timedatectl 기준으로 NTP 활성화 및 동기화 상태가 정상입니다. (NTP=yes, NTPSynchronized=yes)"
  else
    is_active_service() { systemctl is-active --quiet "$1" 2>/dev/null; }

    local timesyncd_active=0 chronyd_active=0 ntpd_active=0
    is_active_service systemd-timesyncd && timesyncd_active=1
    is_active_service chrony && chronyd_active=1
    is_active_service ntp && ntpd_active=1

    if [ "$timesyncd_active" -eq 0 ] && [ "$chronyd_active" -eq 0 ] && [ "$ntpd_active" -eq 0 ]; then
      status="취약"
      reason="NTP/시각동기화 서비스(systemd-timesyncd/chrony/ntp)가 활성화되어 있지 않습니다."
    else
      local server_found=0 sync_ok=0

      if [ "$chronyd_active" -eq 1 ]; then
        local f
        for f in /etc/chrony/chrony.conf /etc/chrony.conf /etc/chrony/*.conf; do
          [ -f "$f" ] || continue
          grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | grep -qiE '^\s*(server|pool)\s+' && server_found=1 && break
        done
        command -v chronyc >/dev/null 2>&1 && chronyc -n sources 2>/dev/null | grep -qE '^\^\*|^\^\+' && sync_ok=1
      fi

      if [ "$server_found" -eq 0 ] && [ "$ntpd_active" -eq 1 ]; then
        local f
        for f in /etc/ntp.conf /etc/ntp/*.conf; do
          [ -f "$f" ] || continue
          grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | grep -qiE '^\s*server\s+' && server_found=1 && break
        done
        command -v ntpq >/dev/null 2>&1 && ntpq -pn 2>/dev/null | awk 'NR>2{print $1}' | grep -q '^\*' && sync_ok=1
      fi

      if [ "$server_found" -eq 0 ] && [ "$timesyncd_active" -eq 1 ]; then
        if grep -R -vE '^\s*#|^\s*$' /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d 2>/dev/null \
          | grep -qiE '^\s*NTP\s*='; then
          server_found=1
        fi
        [ "$time_sync_state" = "yes" ] && sync_ok=1
      fi

      if [ "$sync_ok" -eq 1 ]; then
        status="양호"
        reason="NTP 서비스가 활성화되어 있고, 동기화 상태가 정상으로 확인됩니다."
      else
        status="취약"
        reason="NTP 서비스는 활성화되어 있으나, 서버 설정 또는 동기화 상태를 정상으로 확인하지 못했습니다."
      fi
    fi
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_66() {
  local code="U-66"
  local item="정책에 따른 시스템 로깅 설정"
  local severity="중"
  local status="양호"
  local reason="로그 기록 정책이 적용되어 있고, 로그를 남기고 있는 것으로 확인됩니다."

  local VULN=0
  local REASON=""

  local CONF="/etc/rsyslog.conf"
  local -a CONF_FILES=()

  [ -f "$CONF" ] && CONF_FILES+=("$CONF")
  if [ -d "/etc/rsyslog.d" ]; then
    while IFS= read -r f; do
      [ -f "$f" ] && CONF_FILES+=("$f")
    done < <(find /etc/rsyslog.d -maxdepth 1 -type f -name "*.conf" 2>/dev/null | sort)
  fi

  local RSYSLOG_RUNNING=0
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active rsyslog >/dev/null 2>&1 && RSYSLOG_RUNNING=1
  else
    pgrep -x rsyslogd >/dev/null 2>&1 && RSYSLOG_RUNNING=1
  fi

  if [ "$RSYSLOG_RUNNING" -ne 1 ]; then
    VULN=1
    REASON="시스템 로그 데몬(rsyslog)이 실행 중이지 않습니다."
  else
    if [ "${#CONF_FILES[@]}" -eq 0 ]; then
      VULN=1
      REASON="rsyslog 설정 파일(/etc/rsyslog.conf 또는 /etc/rsyslog.d/*.conf)을 찾을 수 없습니다."
    else
      local ALL_CONF_CONTENT
      ALL_CONF_CONTENT="$(cat "${CONF_FILES[@]}" 2>/dev/null | grep -vE '^[[:space:]]*#' | sed '/^[[:space:]]*$/d')"

      local CHECK_MSG CHECK_SECURE CHECK_MAIL CHECK_CRON CHECK_ALERT CHECK_EMERG
      CHECK_MSG="$(echo "$ALL_CONF_CONTENT" | grep -E '^\s*\*\.info;mail\.none;authpriv\.none;cron\.none[[:space:]]+-?(/var/log/(messages|syslog))(\s|$)')"

      CHECK_SECURE="$(echo "$ALL_CONF_CONTENT" | grep -E '^\s*auth,authpriv\.\*[[:space:]]+-?(/var/log/(secure|auth\.log))(\s|$)')"

      CHECK_MAIL="$(echo "$ALL_CONF_CONTENT" | grep -E '^\s*mail\.\*[[:space:]]+-?(/var/log/(maillog|mail\.log))(\s|$)')"

      CHECK_CRON="$(echo "$ALL_CONF_CONTENT" | grep -E '^\s*cron\.\*[[:space:]]+-?(/var/log/(cron|cron\.log))(\s|$)')"

      CHECK_ALERT="$(echo "$ALL_CONF_CONTENT" | grep -E '^\s*\*\.alert[[:space:]]+((/dev/console)|(/dev/tty[0-9]+)|(:omusrmsg:\*)|(root))(\s|$)')"

      CHECK_EMERG="$(echo "$ALL_CONF_CONTENT" | grep -E '^\s*\*\.emerg[[:space:]]+(\*|:omusrmsg:\*)(\s|$)')"

      local MISSING_LOGS=""
      [ -z "$CHECK_MSG" ]    && MISSING_LOGS="$MISSING_LOGS [messages/syslog]"
      [ -z "$CHECK_SECURE" ] && MISSING_LOGS="$MISSING_LOGS [secure/auth.log]"
      [ -z "$CHECK_MAIL" ]   && MISSING_LOGS="$MISSING_LOGS [maillog/mail.log]"
      [ -z "$CHECK_CRON" ]   && MISSING_LOGS="$MISSING_LOGS [cron/cron.log]"
      [ -z "$CHECK_ALERT" ]  && MISSING_LOGS="$MISSING_LOGS [alert]"
      [ -z "$CHECK_EMERG" ]  && MISSING_LOGS="$MISSING_LOGS [emerg]"

      if [ -n "$MISSING_LOGS" ]; then
        VULN=1
        REASON="rsyslog 설정에 다음 주요 로그 항목이 누락되었습니다:$MISSING_LOGS"
      else
        local LOG_EXIST=0
        local f
        for f in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure /var/log/mail.log /var/log/maillog /var/log/cron.log /var/log/cron; do
          [ -e "$f" ] && { LOG_EXIST=1; break; }
        done

        if [ "$LOG_EXIST" -ne 1 ]; then
          VULN=1
          REASON="rsyslog 설정은 존재하나 /var/log 하위에 주요 로그 파일이 존재하지 않습니다."
        fi
      fi
    fi
  fi

  if [ "$VULN" -eq 1 ]; then
    status="취약"
    reason="$REASON"
  else
    status="양호"
    reason="rsyslog 동작 및 주요 로그 정책 설정/파일 존재가 확인됩니다."
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
}

U_67() {
  local code="U-67"
  local item="로그 디렉터리 소유자 및 권한 설정"
  local severity="중"
  local status="양호"
  local reason="/var/log 및 관련 로그 파일 소유자/권한이 기준에 부합합니다."

  local LOG_DIR="/var/log"
  local MAX_MODE="644"

  local vuln=0
  local r=""

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    status="N/A"
    reason="root 권한 필요(sudo로 실행)"
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  if [[ ! -d "$LOG_DIR" ]]; then
    status="N/A"
    reason="$LOG_DIR 디렉터리가 존재하지 않습니다."
    printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
      "$code" "$item" "$severity" "$status" "$reason"
    return 0
  fi

  local f owner mode
  while IFS= read -r -d '' f; do
    owner="$(stat -c '%U' "$f" 2>/dev/null)"
    mode="$(stat -c '%a' "$f" 2>/dev/null)"

    if [[ -z "$owner" || -z "$mode" ]]; then
      vuln=1
      r="stat 조회 실패: $f"
      break
    fi

    if [[ "$owner" != "root" ]]; then
      vuln=1
      r="소유자가 root가 아님: $f (owner=$owner)"
      break
    fi

    if [[ "$mode" =~ ^[0-7]+$ ]]; then
      if (( 8#$mode > 8#$MAX_MODE )); then
        vuln=1
        r="권한이 644 초과: $f (perm=$mode)"
        break
      fi
    else
      vuln=1
      r="권한 파싱 실패: $f (perm=$mode)"
      break
    fi
  done < <(find "$LOG_DIR" -xdev -type f -print0 2>/dev/null)

  if (( vuln == 1 )); then
    status="취약"
    reason="$r"
  else
    status="양호"
    reason="/var/log 하위 파일 소유자가 root이며 권한이 644 이하입니다."
  fi

  reason="$(echo "$reason" | tr '\r' ' ' | tr '\n' ' ' | sed -e 's/[[:space:]]\+/ /g; s/^[[:space:]]*//; s/[[:space:]]*$//')"
  if (( ${#reason} > 250 )); then reason="${reason:0:250}..."; fi

  local reason_json="$reason"
  reason_json="${reason_json//\\/\\\\}"
  reason_json="${reason_json//\"/\\\"}"
  reason_json="${reason_json//$'\n'/ }"
  reason_json="${reason_json//$'\r'/ }"

  printf '{"code":"%s","item":"%s","severity":"%s","status":"%s","reason":"%s"}\n' \
    "$code" "$item" "$severity" "$status" "$reason_json"
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
