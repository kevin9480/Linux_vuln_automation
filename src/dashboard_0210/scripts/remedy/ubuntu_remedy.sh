#!/bin/bash

TARGET_CODE="$1"

U_01() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        exit 1
    fi

    APPLIED=""

    if systemctl list-unit-files | grep -q "sshd.service" || [ -f /etc/ssh/sshd_config ]; then
        if [ -f /etc/ssh/sshd_config ]; then
            sed -i 's/^[#]*PermitRootLogin.*/#&/' /etc/ssh/sshd_config
     
            sed -i '0,/^#.*PermitRootLogin.*/{s/^#.*PermitRootLogin.*/PermitRootLogin no/}' /etc/ssh/sshd_config
    
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
            
            APPLIED="SSH"
        fi
    fi

    TELNET_ACTIVE=0

    if systemctl list-unit-files 2>/dev/null | grep -q "telnet"; then
        TELNET_ACTIVE=1
    fi

    if [ -f /etc/xinetd.d/telnet ]; then
        if grep -q "disable.*=.*no" /etc/xinetd.d/telnet 2>/dev/null; then
            TELNET_ACTIVE=1
        fi
    fi

    if [ "$TELNET_ACTIVE" -eq 1 ]; then
        if [ -f /etc/pam.d/login ]; then
            if ! grep -q "auth.*required.*pam_securetty.so" /etc/pam.d/login; then
                sed -i '1i auth required /lib/security/pam_securetty.so' /etc/pam.d/login
            fi
        fi
        
        if [ -f /etc/securetty ]; then
            sed -i 's/^pts\//#&/' /etc/securetty
        fi
        
        [ -n "$APPLIED" ] && APPLIED="$APPLIED, Telnet" || APPLIED="Telnet"
    fi

    if [ -n "$APPLIED" ]; then
        echo "✓ U-01 조치 완료 ($APPLIED root 원격 접속 차단)"
    else
        echo "! SSH 또는 Telnet 서비스를 찾을 수 없습니다."
    fi
}

U_03() {
    if [ "$EUID" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        return 1
    fi

    local CODE="U-03"

    local DENY="${U03_DENY:-10}"
    local UNLOCK_TIME="${U03_UNLOCK_TIME:-120}"

    local COMMON_AUTH="/etc/pam.d/common-auth"
    local COMMON_ACCOUNT="/etc/pam.d/common-account"

    local OS_ID=""
    local OS_LIKE=""
    if [ -f /etc/os-release ]; then
        OS_ID="$(grep -E '^ID=' /etc/os-release 2>/dev/null | head -n1 | cut -d= -f2 | tr -d '"')"
        OS_LIKE="$(grep -E '^ID_LIKE=' /etc/os-release 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '"')"
    fi

    local is_debian_family=0
    case " ${OS_ID} ${OS_LIKE} " in
        *" debian "*|*" ubuntu "*)
            is_debian_family=1
            ;;
    esac

    if [ "$is_debian_family" -ne 1 ]; then
        echo "[N/A] $CODE: Debian(Ubuntu) 계열이 아님. (현재 ID=${OS_ID}, ID_LIKE=${OS_LIKE})"
        echo "[N/A] $CODE: 이 스크립트는 Ubuntu 24.04 가이드(pam_faillock, common-auth/common-account) 경로만 자동 조치"
        return 0
    fi

    if [ ! -f "$COMMON_AUTH" ]; then
        echo "[ERROR] $COMMON_AUTH 파일 없음"
        return 1
    fi

    if [ ! -f "$COMMON_ACCOUNT" ]; then
        echo "[ERROR] $COMMON_ACCOUNT 파일 없음"
        return 1
    fi

    local PAM_FAILLOCK_SO=""
    local p=""
    for p in \
        "/lib/security/pam_faillock.so" \
        "/lib/x86_64-linux-gnu/security/pam_faillock.so" \
        "/usr/lib/security/pam_faillock.so" \
        "/usr/lib/x86_64-linux-gnu/security/pam_faillock.so"
    do
        if [ -f "$p" ]; then
            PAM_FAILLOCK_SO="$p"
            break
        fi
    done

    if [ -z "$PAM_FAILLOCK_SO" ]; then
        echo "[ERROR] pam_faillock.so 모듈을 찾지 못함"
        echo "[HINT] libpam-modules 패키지/구성 확인 필요"
        return 1
    fi

    local ts=""
    ts="$(date +%F_%H%M%S)"
    cp -a "$COMMON_AUTH" "${COMMON_AUTH}.bak.${ts}" 2>/dev/null || { echo "[ERROR] common-auth 백업 실패"; return 1; }
    cp -a "$COMMON_ACCOUNT" "${COMMON_ACCOUNT}.bak.${ts}" 2>/dev/null || { echo "[ERROR] common-account 백업 실패"; return 1; }

    local PREAUTH_LINE="auth required pam_faillock.so preauth audit deny=${DENY} unlock_time=${UNLOCK_TIME}"
    local AUTHFAIL_LINE="auth [default=die] pam_faillock.so authfail audit deny=${DENY} unlock_time=${UNLOCK_TIME}"
    local AUTHSUCC_LINE="auth sufficient pam_faillock.so authsucc audit deny=${DENY} unlock_time=${UNLOCK_TIME}"
    local ACCOUNT_LINE="account required pam_faillock.so"

    local tmp1=""
    local tmp2=""
    tmp1="$(mktemp)" || { echo "[ERROR] 임시파일 생성 실패"; return 1; }
    tmp2="$(mktemp)" || { rm -f "$tmp1"; echo "[ERROR] 임시파일 생성 실패"; return 1; }
    trap 'rm -f "$tmp1" "$tmp2"' RETURN

    local found_pam_unix=0
    awk -v pre="$PREAUTH_LINE" -v af="$AUTHFAIL_LINE" -v as="$AUTHSUCC_LINE" '
        $0 ~ /^[[:space:]]*auth[[:space:]]+/ && $0 ~ /pam_faillock\.so/ { next }

        {
            if (found_unix == 0 && $0 ~ /^[[:space:]]*auth[[:space:]]+/ && $0 ~ /pam_unix\.so/) {
                print pre
                print $0
                print af
                print as
                found_unix = 1
                next
            }
            print $0
        }

        END {
            if (found_unix == 0) {
                print ""
                print pre
                print af
                print as
            }
        }
    ' found_unix=0 "$COMMON_AUTH" > "$tmp1" || { echo "[ERROR] Step1(common-auth) 처리 실패"; return 1; }

    if ! cmp -s "$COMMON_AUTH" "$tmp1"; then
        cp "$tmp1" "$COMMON_AUTH" 2>/dev/null || { echo "[ERROR] Step1(common-auth) 반영 실패"; return 1; }
    fi


    awk -v acc="$ACCOUNT_LINE" '
        $0 ~ /^[[:space:]]*account[[:space:]]+/ && $0 ~ /pam_faillock\.so/ { next }

        {
            if ($0 ~ /end of pam-auth-update config/ && inserted == 0) {
                print acc
                inserted = 1
            }
            print $0
        }

        END {
            if (inserted == 0) {
                print ""
                print acc
            }
        }
    ' inserted=0 "$COMMON_ACCOUNT" > "$tmp2" || { echo "[ERROR] Step2(common-account) 처리 실패"; return 1; }

    if ! cmp -s "$COMMON_ACCOUNT" "$tmp2"; then
        cp "$tmp2" "$COMMON_ACCOUNT" 2>/dev/null || { echo "[ERROR] Step2(common-account) 반영 실패"; return 1; }
    fi

    local ok1=0
    local ok2=0

    grep -Eq "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+preauth.*deny=${DENY}.*unlock_time=${UNLOCK_TIME}" "$COMMON_AUTH" && ok1=$((ok1+1))
    grep -Eq "^[[:space:]]*auth[[:space:]]+\\[default=die\\][[:space:]]+pam_faillock\.so[[:space:]]+authfail.*deny=${DENY}.*unlock_time=${UNLOCK_TIME}" "$COMMON_AUTH" && ok1=$((ok1+1))
    grep -Eq "^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_faillock\.so[[:space:]]+authsucc.*deny=${DENY}.*unlock_time=${UNLOCK_TIME}" "$COMMON_AUTH" && ok1=$((ok1+1))

    grep -Eq "^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_faillock\.so" "$COMMON_ACCOUNT" && ok2=1

    if [ "$ok1" -ge 2 ] && [ "$ok2" -eq 1 ]; then
        echo "[완료] $CODE 조치 완료 (Debian/Ubuntu: pam_faillock 적용, deny=${DENY}, unlock_time=${UNLOCK_TIME})"
        return 0
    else
        echo "[주의] $CODE 조치 반영 확인 필요"
        echo "[HINT] 아래 파일에서 pam_faillock 설정 확인"
        echo "       - $COMMON_AUTH"
        echo "       - $COMMON_ACCOUNT"
        return 1
    fi
}

U_04() {
    if [ "$EUID" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        return 1
    fi

    local FIX_COUNT=0

    local ROOT_PASSWD_FIELD
    ROOT_PASSWD_FIELD=$(grep "^root:" /etc/passwd | cut -d: -f2)

    local NON_SHADOW_USERS
    NON_SHADOW_USERS=$(awk -F: '$2 != "x" && $2 != "*" && $2 != "!" && $2 != "" {print $1}' /etc/passwd)

    if [ "$ROOT_PASSWD_FIELD" = "x" ] && [ -z "$NON_SHADOW_USERS" ]; then
        echo "[양호] 조치 불필요 (쉐도우 비밀번호 이미 적용됨)"
        return 0
    fi

    if ! command -v pwconv &>/dev/null; then
        echo "[ERROR] pwconv 명령어를 찾을 수 없습니다"
        return 1
    fi

    pwconv &>/dev/null

    if [ $? -eq 0 ]; then
        FIX_COUNT=$((FIX_COUNT + 1))

        local ROOT_PASSWD_FIELD_AFTER
        ROOT_PASSWD_FIELD_AFTER=$(grep "^root:" /etc/passwd | cut -d: -f2)

        if [ "$ROOT_PASSWD_FIELD_AFTER" = "x" ]; then
            echo "[완료] U-04 조치 완료 (쉐도우 비밀번호 적용: ${FIX_COUNT}개)"
            return 0
        else
            echo "[경고] pwconv 실행했으나 적용 확인 필요"
            return 1
        fi
    else
        echo "[ERROR] pwconv 실행 실패"
        return 1
    fi
}

U_05() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        exit 1
    fi

    ZERO_UID_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

    if [ -z "$ZERO_UID_ACCOUNTS" ]; then
        echo "✓ U-05 이미 양호 (root 외 UID 0 계정 없음)"
        exit 0
    fi

    get_available_uid() {
        local uid=1000
        while getent passwd "$uid" >/dev/null 2>&1; do
            uid=$((uid + 1))
        done
        echo "$uid"
    }

    CHANGED_COUNT=0

    for account in $ZERO_UID_ACCOUNTS; do
        NEW_UID=$(get_available_uid)
    
        if usermod -u "$NEW_UID" "$account" 2>/dev/null; then
            CHANGED_COUNT=$((CHANGED_COUNT + 1))
        else
            sed -i "s/^\($account:[^:]*:\)0:/\1$NEW_UID:/" /etc/passwd
            
            if [ $? -eq 0 ]; then
                CHANGED_COUNT=$((CHANGED_COUNT + 1))
            fi
        fi
    done

    if [ "$CHANGED_COUNT" -gt 0 ]; then
        echo "✓ U-05 조치 완료 (root 외 UID 0 계정 ${CHANGED_COUNT}개 변경)"
    else
        echo "✗ U-05 조치 실패"
    fi
}

U_06() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local FIX_COUNT=0
    local PAM_SU="/etc/pam.d/su"
    local SU_BIN="/usr/bin/su"
    local PAM_USED=0

    if [ -f "$PAM_SU" ]; then
        PAM_USED=1
    fi

    if ! grep -q "^wheel:" /etc/group; then
        groupadd wheel &>/dev/null
        ((FIX_COUNT++))
    fi

    if [ $PAM_USED -eq 0 ]; then
      
        local SU_GROUP=$(stat -c "%G" "$SU_BIN" 2>/dev/null)
        local SU_PERM=$(stat -c "%a" "$SU_BIN" 2>/dev/null)

        if [ "$SU_GROUP" != "wheel" ]; then
            chgrp wheel "$SU_BIN" &>/dev/null
            ((FIX_COUNT++))
        fi

        if [ "$SU_PERM" != "4750" ]; then
            chmod 4750 "$SU_BIN" &>/dev/null
            ((FIX_COUNT++))
        fi

    else
        
        local SU_GROUP=$(stat -c "%G" "$SU_BIN" 2>/dev/null)
        local SU_PERM=$(stat -c "%a" "$SU_BIN" 2>/dev/null)

        if [ "$SU_GROUP" != "wheel" ]; then
            chgrp wheel "$SU_BIN" &>/dev/null
            ((FIX_COUNT++))
        fi
        if [ "$SU_PERM" != "4750" ]; then
            chmod 4750 "$SU_BIN" &>/dev/null
            ((FIX_COUNT++))
        fi

        if grep -q "^#.*pam_wheel\.so" "$PAM_SU"; then
            cp "$PAM_SU" "${PAM_SU}.bak.$(date +%Y%m%d%H%M%S)"
            sed -i 's/^#\(.*\)pam_wheel\.so.*/auth\t\trequired\tpam_wheel.so use_uid/' "$PAM_SU"
            ((FIX_COUNT++))
        elif ! grep -q "^auth.*pam_wheel\.so.*use_uid" "$PAM_SU"; then
           
            cp "$PAM_SU" "${PAM_SU}.bak.$(date +%Y%m%d%H%M%S)"
            if grep -q "^auth.*pam_wheel\.so" "$PAM_SU"; then
                sed -i 's/^auth.*pam_wheel\.so.*/auth\t\trequired\tpam_wheel.so use_uid/' "$PAM_SU"
            else
                
                echo -e "auth\t\trequired\tpam_wheel.so use_uid" >> "$PAM_SU"
            fi
            ((FIX_COUNT++))
        fi
    fi

    local SUDO_USERS=$(getent group sudo 2>/dev/null | awk -F: '{print $4}' | tr ',' ' ')
    for USER in $SUDO_USERS; do
        if [ -n "$USER" ]; then
            if ! id -nG "$USER" 2>/dev/null | grep -qw "wheel"; then
                usermod -aG wheel "$USER" &>/dev/null
                ((FIX_COUNT++))
            fi
        fi
    done

    if [ $FIX_COUNT -eq 0 ]; then
        echo "✓ U-06 이미 양호 (su 명령어 접근 제한 설정됨)"
    else
        local MODE_STR="비PAM 방식"
        [ $PAM_USED -eq 1 ] && MODE_STR="PAM 모듈 방식"
        echo "✓ U-06 조치 완료 ($MODE_STR: ${FIX_COUNT}개 항목 수정)"
    fi
}

U_08() {
  echo "[시작] U-08 관리자 그룹(root) 계정 정비 조치를 시작합니다."

  local extra_users=$(grep "^root:" /etc/group | cut -d: -f4 | sed 's/,/ /g')

  if [ -z "$extra_users" ]; then
    echo "[양호] root 그룹에 추가된 일반 사용자가 없습니다."
    return 0
  fi

  for user in $extra_users; do
    if [ "$user" != "root" ]; then
      echo "[조치] root 그룹에서 불필요한 계정 발견 및 제거: $user"
      
      gpasswd -d "$user" root
      
      if [ $? -eq 0 ]; then
        echo "[완료] $user 계정이 root 그룹에서 제거되었습니다."
      else
        echo "[오류] $user 계정 제거 실패"
      fi
    fi
  done
}

U_10() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    PASSWD_FILE="/etc/passwd"
    FIX_COUNT=0

    if [ ! -f "$PASSWD_FILE" ]; then
        echo "[ERROR] $PASSWD_FILE 파일 없음"
        exit 1
    fi

    DUPLICATE_UIDS=$(awk -F: '$3 > 0 {print $3}' "$PASSWD_FILE" | sort | uniq -d)

    if [ -z "$DUPLICATE_UIDS" ]; then
        echo "[양호] 중복 UID 없음"
        exit 0
    fi

    find_available_uid() {
        local start_uid=$1
        local check_uid=$start_uid
        
        while true; do
            if ! grep -q "^[^:]*:[^:]*:$check_uid:" "$PASSWD_FILE"; then
                echo $check_uid
                return
            fi
            ((check_uid++))
        done
    }

    for dup_uid in $DUPLICATE_UIDS; do
     
        USERS=$(awk -F: -v uid="$dup_uid" '$3 == uid {print $1}' "$PASSWD_FILE")
        
        USER_ARRAY=($USERS)
       
        for ((i=1; i<${#USER_ARRAY[@]}; i++)); do
            username="${USER_ARRAY[$i]}"
            
            if [ "$dup_uid" -lt 1000 ]; then
             
                new_uid=$(find_available_uid 100)
            else
              
                new_uid=$(find_available_uid 1000)
            fi
        
            usermod -u "$new_uid" "$username" 2>/dev/null
            
            if [ $? -eq 0 ]; then
                ((FIX_COUNT++))
            fi
        done
    done

    if [ $FIX_COUNT -gt 0 ]; then
        echo "[완료] U-10 조치 완료 (수정: ${FIX_COUNT}개)"
    else
        echo "[양호] 조치 불필요"
    fi
}

U_11() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local TARGET_USERS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")
    local SAFE_SHELL="/usr/sbin/nologin"
    local ALT_SAFE_SHELL="/bin/false"
    
    local FIX_COUNT=0
    local FOUND_VULN=0

    for user in "${TARGET_USERS[@]}"; do
        if grep -q "^$user:" /etc/passwd; then
          
            local CURRENT_SHELL=$(grep "^$user:" /etc/passwd | awk -F: '{print $7}')
         
            if [[ "$CURRENT_SHELL" != "$SAFE_SHELL" && "$CURRENT_SHELL" != "$ALT_SAFE_SHELL" ]]; then
                FOUND_VULN=$((FOUND_VULN + 1))
                
                if usermod -s "$SAFE_SHELL" "$user" 2>/dev/null; then
                    FIX_COUNT=$((FIX_COUNT + 1))
                else
                
                    sed -i "s|^\($user:.*:\)[^:]*$|\1$SAFE_SHELL|" /etc/passwd
                    if [ $? -eq 0 ]; then
                        FIX_COUNT=$((FIX_COUNT + 1))
                    fi
                fi
            fi
        fi
    done

  
    if [ "$FOUND_VULN" -eq 0 ]; then
        echo "✓ U-11 이미 양호 (관리 계정들이 안전한 쉘을 사용 중)"
    else
        if [ "$FIX_COUNT" -eq "$FOUND_VULN" ]; then
            echo "✓ U-11 조치 완료 (총 ${FIX_COUNT}개 계정의 쉘을 $SAFE_SHELL 로 변경)"
        else
            echo "✗ U-11 조치 중 일부 실패 (대상: ${FOUND_VULN}, 완료: ${FIX_COUNT})"
        fi
    fi
}

U_12() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        exit 1
    fi

    SHELLS_IN_USE=$(awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $7}' /etc/passwd | sort -u)
    ROOT_SHELL=$(awk -F: '$1=="root" {print $7}' /etc/passwd)

    USE_BASH=0
    USE_CSH=0

    for shell in $SHELLS_IN_USE $ROOT_SHELL; do
        case "$shell" in
            */bash|*/sh|*/ksh) USE_BASH=1 ;;
            */csh|*/tcsh) USE_CSH=1 ;;
        esac
    done

    APPLIED=""

    if [ "$USE_BASH" -eq 1 ]; then
        sed -i '/^# Session Timeout Setting (U-12)/d' /etc/profile
        sed -i '/^TMOUT=/d' /etc/profile
        sed -i '/^export TMOUT$/d' /etc/profile
        echo "" >> /etc/profile
        echo "# Session Timeout Setting (U-12)" >> /etc/profile
        echo "TMOUT=600" >> /etc/profile
        echo "export TMOUT" >> /etc/profile
        APPLIED="bash/sh/ksh"
    fi

    if [ "$USE_CSH" -eq 1 ]; then
        if [ -f /etc/csh.cshrc ]; then
            sed -i '/^# Session Timeout Setting (U-12)/d' /etc/csh.cshrc
            sed -i '/^set autologout=/d' /etc/csh.cshrc
            echo "" >> /etc/csh.cshrc
            echo "# Session Timeout Setting (U-12)" >> /etc/csh.cshrc
            echo "set autologout=10" >> /etc/csh.cshrc
        fi
        if [ -f /etc/csh.login ]; then
            sed -i '/^# Session Timeout Setting (U-12)/d' /etc/csh.login
            sed -i '/^set autologout=/d' /etc/csh.login
            echo "" >> /etc/csh.login
            echo "# Session Timeout Setting (U-12)" >> /etc/csh.login
            echo "set autologout=10" >> /etc/csh.login
        fi
        [ -n "$APPLIED" ] && APPLIED="$APPLIED, csh/tcsh" || APPLIED="csh/tcsh"
    fi

    if [ -n "$APPLIED" ]; then
        echo "✓ U-12 조치 완료 ($APPLIED 설정 적용)"
    else
        echo "! 설정할 Shell이 없습니다."
    fi
}

U_13() {
  
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local LOGIN_METHOD="SHA512"   
    local PAM_OPT="sha512"        
    local SHADOW_PREFIX='$6$'
    local SHADOW="/etc/shadow"
    local LOGIN_DEFS="/etc/login.defs"
    local FAMILY="unknown"
    local PAM_FILE=""
    local FIX_COUNT=0
    local SKIPPED=0

    if [ -r /etc/os-release ]; then
        . /etc/os-release
        local LIKE_STR="${ID_LIKE:-} ${ID:-}"
        if echo "$LIKE_STR" | grep -qiE "(debian|ubuntu)"; then
            FAMILY="debian"
        elif echo "$LIKE_STR" | grep -qiE "(rhel|fedora|centos|rocky|almalinux)"; then
            FAMILY="redhat"
        fi
    fi
    
    if [ "$FAMILY" = "unknown" ]; then
        if [ -f /etc/pam.d/common-password ]; then
            FAMILY="debian"
        elif [ -f /etc/pam.d/system-auth ]; then
            FAMILY="redhat"
        else
            echo "✗ U-13 점검 실패 (배포판 계열 판별 불가)"
            return 1
        fi
    fi

    if [ ! -f "$SHADOW" ]; then
        echo "✗ U-13 점검 실패 ($SHADOW 파일 없음)"
        return 1
    fi

    local MD5_USERS
    MD5_USERS="$(awk -F: '$2 ~ /(^!|\*)?\$1\$/ { print $1 }' "$SHADOW" 2>/dev/null)"

    if [ -f "$LOGIN_DEFS" ]; then
        cp -a "$LOGIN_DEFS" "${LOGIN_DEFS}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null

        if grep -qE '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+' "$LOGIN_DEFS"; then
            sed -i -E "s|^[[:space:]]*ENCRYPT_METHOD[[:space:]]+.*$|ENCRYPT_METHOD ${LOGIN_METHOD}|g" "$LOGIN_DEFS"
        else
            printf "\nENCRYPT_METHOD %s\n" "$LOGIN_METHOD" >> "$LOGIN_DEFS"
        fi
    fi

   
    if [ "$FAMILY" = "debian" ]; then
        PAM_FILE="/etc/pam.d/common-password"
    else
        PAM_FILE="/etc/pam.d/system-auth"
    fi

    if [ -f "$PAM_FILE" ]; then
       
        cp -a "$PAM_FILE" "${PAM_FILE}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null

        perl -i -pe '
          if (/^\s*password\b/ && /\bpam_unix\.so\b/) {
            s/\b(yescrypt|md5|bigcrypt|descrypt|sha256|sha512)\b//g;
            s/[ \t]+/ /g;
            s/\s+$//;
            $_ .= " '"$PAM_OPT"'\n" unless /\b'"$PAM_OPT"'\b/;
          }
        ' "$PAM_FILE"
    fi

    if ! chpasswd --help 2>/dev/null | grep -q -- '--crypt-method'; then
        echo "✗ U-13 조치 실패 (chpasswd가 --crypt-method 옵션을 지원하지 않음)"
        return 1
    fi

    if [ -n "$MD5_USERS" ]; then
        while IFS= read -r u; do
            [ -z "$u" ] && continue

            local uid
            uid="$(id -u "$u" 2>/dev/null || echo "")"
            
            if [ -z "$uid" ] || [ "$uid" -lt 1000 ] || [ "$uid" -eq 65534 ]; then
                SKIPPED=$((SKIPPED+1))
                continue
            fi

            local TMPPW
            TMPPW="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20)"

            if printf '%s:%s\n' "$u" "$TMPPW" | chpasswd --crypt-method "$LOGIN_METHOD" >/dev/null 2>&1; then
                chage -d 0 "$u" >/dev/null 2>&1 || true
                FIX_COUNT=$((FIX_COUNT+1))
            fi
        done <<< "$MD5_USERS"
    fi

    local REMAIN_MD5
    REMAIN_MD5="$(awk -F: '$2 ~ /(^!|\*)?\$1\$/ { c++ } END { print (c+0) }' "$SHADOW" 2>/dev/null)"

    if [ "$REMAIN_MD5" -eq 0 ]; then
        if [ "$FIX_COUNT" -gt 0 ]; then
             echo "✓ U-13 조치 완료 (알고리즘: $LOGIN_METHOD, ${FIX_COUNT}개 계정 변환 완료)"
        else
             echo "✓ U-13 이미 양호 (알고리즘: $LOGIN_METHOD 설정됨, MD5 계정 없음)"
        fi
    else
        echo "✗ U-13 조치 미흡 (설정은 적용되었으나 MD5 해시 계정 ${REMAIN_MD5}개 잔존 - 시스템 계정 등)"
    fi
}

U_14() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    FIX_COUNT=0

    fix_path_in_file() {
        local file=$1
        
        if [ ! -f "$file" ]; then
            return
        fi
       
        if ! grep -q "^[^#]*PATH.*=" "$file" 2>/dev/null; then
            return
        fi
      
        if ! grep "^[^#]*PATH=.*\." "$file" | grep -q ":\.\|^\." > /dev/null 2>&1; then
            return
        fi
     
        cp "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null
        
        local tmpfile=$(mktemp)
        
        while IFS= read -r line; do
       
            if echo "$line" | grep -q "^[^#]*PATH.*=" ; then
              
                if echo "$line" | grep -q '\.:' || echo "$line" | grep -q ':\.' || echo "$line" | grep -q '^[^#]*PATH=[\"'\'']\?\.' ; then
                   
                    local path_value=$(echo "$line" | sed -n 's/.*PATH=\(.*\)/\1/p')
                  
                    local quote=""
                    if [[ "$path_value" == \"*\" ]]; then
                        quote="\""
                        path_value=${path_value#\"}
                        path_value=${path_value%\"}
                    elif [[ "$path_value" == \'*\' ]]; then
                        quote="'"
                        path_value=${path_value#\'}
                        path_value=${path_value%\'}
                    fi
                  
                    path_value=$(echo "$path_value" | sed 's/^\.:*//')
                    path_value=$(echo "$path_value" | sed 's/:\.$//')
                    path_value=$(echo "$path_value" | sed 's/:\.:/:/g')
                    path_value=$(echo "$path_value" | sed 's/::/:/g')
                
                    path_value=$(echo "$path_value" | sed 's/^://')
                  
                    path_value=$(echo "$path_value" | sed 's/:$//')

                    local prefix=$(echo "$line" | sed 's/PATH=.*/PATH=/')
                    if [ -n "$quote" ]; then
                        echo "${prefix}${quote}${path_value}${quote}"
                    else
                        echo "${prefix}${path_value}"
                    fi
                else
                    echo "$line"
                fi
            else
                echo "$line"
            fi
        done < "$file" > "$tmpfile"
       
        mv "$tmpfile" "$file"
        ((FIX_COUNT++))
    }

    process_shell_files() {
        local shell_type=$1
        local homedir=$2
        
        case "$shell_type" in
            *bash)
           
                if [ "$homedir" = "SYSTEM" ]; then
                    fix_path_in_file "/etc/profile"
                    fix_path_in_file "/etc/bash.bashrc"
                else
                    fix_path_in_file "$homedir/.profile"
                    fix_path_in_file "$homedir/.bash_profile"
                    fix_path_in_file "$homedir/.bashrc"
                fi
                ;;
            *sh)
            
                if [ "$homedir" = "SYSTEM" ]; then
                    fix_path_in_file "/etc/profile"
                else
                    fix_path_in_file "$homedir/.profile"
                fi
                ;;
            *csh)
          
                if [ "$homedir" = "SYSTEM" ]; then
                    fix_path_in_file "/etc/csh.cshrc"
                    fix_path_in_file "/etc/csh.login"
                else
                    fix_path_in_file "$homedir/.cshrc"
                    fix_path_in_file "$homedir/.login"
                fi
                ;;
            *ksh)
             
                if [ "$homedir" = "SYSTEM" ]; then
                    fix_path_in_file "/etc/profile"
                else
                    fix_path_in_file "$homedir/.profile"
                    fix_path_in_file "$homedir/.kshrc"
                fi
                ;;
        esac
    }

    SHELLS=$(awk -F: '$7 ~ /\/(bash|sh|csh|ksh)$/ {print $7}' /etc/passwd | sort -u)

    for shell in $SHELLS; do
        process_shell_files "$shell" "SYSTEM"
    done

    while IFS=: read -r username _ uid _ _ homedir shell; do
  
        if [ "$username" = "root" ] && [ -d "$homedir" ]; then
            process_shell_files "$shell" "$homedir"
        fi
        
        if [ "$uid" -ge 1000 ] && [ "$uid" -lt 60000 ] && [ -d "$homedir" ]; then
            if [[ "$shell" =~ (bash|sh|csh|ksh)$ ]]; then
                process_shell_files "$shell" "$homedir"
            fi
        fi
    done < /etc/passwd

    if [ $FIX_COUNT -eq 0 ]; then
        echo "[양호] 조치 불필요"
    else
        echo "[완료] U-14 조치 완료 (수정: ${FIX_COUNT}개 파일)"
    fi
}

U_15() {
    SEARCH_ROOT="/"
    TARGET_USER="root"
    TARGET_GROUP="root"

    LOG_DIR="/tmp"
    TS="$(date +%Y%m%d_%H%M%S)"
    LOG_FILE="${LOG_DIR}/u15_fix_${TS}.log"
    BEFORE_LIST="${LOG_DIR}/u15_before_${TS}.txt"
    AFTER_LIST="${LOG_DIR}/u15_after_${TS}.txt"

    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요 (sudo로 실행)"
        exit 1
    fi

    for cmd in find stat getent chown chgrp; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "[ERROR] 필수 명령 없음: $cmd"
            exit 1
        fi
    done

    find "$SEARCH_ROOT" -xdev \( -nouser -o -nogroup \) -print 2>/dev/null > "$BEFORE_LIST"
    BEFORE_COUNT=$(wc -l < "$BEFORE_LIST" 2>/dev/null || echo 0)

    if [ "$BEFORE_COUNT" -eq 0 ]; then
        echo "[양호] 조치 불필요 (nouser/nogroup 항목 없음)"
        exit 0
    fi

    {
    echo "U-15 Fix Log: $TS"
    echo "SEARCH_ROOT=$SEARCH_ROOT"
    echo "TARGET_OWNER=${TARGET_USER}:${TARGET_GROUP}"
    echo "BEFORE_COUNT=$BEFORE_COUNT"
    echo "BEFORE_LIST=$BEFORE_LIST"
    } >> "$LOG_FILE"

    FIX_OK=0
    FIX_FAIL=0

    while IFS= read -r path; do
        [ -n "$path" ] || continue
        [ -e "$path" ] || continue

        uid="$(stat -c '%u' "$path" 2>/dev/null)"
        gid="$(stat -c '%g' "$path" 2>/dev/null)"

        missing_user=0
        missing_group=0

        if [ -n "$uid" ] && ! getent passwd "$uid" >/dev/null 2>&1; then
            missing_user=1
        fi
        if [ -n "$gid" ] && ! getent group "$gid" >/dev/null 2>&1; then
            missing_group=1
        fi

        if [ "$missing_user" -eq 1 ] && [ "$missing_group" -eq 1 ]; then
            if chown -h "${TARGET_USER}:${TARGET_GROUP}" "$path" 2>>"$LOG_FILE"; then
                FIX_OK=$((FIX_OK+1))
                echo "[FIX] chown ${TARGET_USER}:${TARGET_GROUP} $path" >> "$LOG_FILE"
            else
                FIX_FAIL=$((FIX_FAIL+1))
                echo "[FAIL] chown ${TARGET_USER}:${TARGET_GROUP} $path" >> "$LOG_FILE"
            fi
        elif [ "$missing_user" -eq 1 ]; then
            if chown -h "${TARGET_USER}" "$path" 2>>"$LOG_FILE"; then
                FIX_OK=$((FIX_OK+1))
                echo "[FIX] chown ${TARGET_USER} $path" >> "$LOG_FILE"
            else
                FIX_FAIL=$((FIX_FAIL+1))
                echo "[FAIL] chown ${TARGET_USER} $path" >> "$LOG_FILE"
            fi
        elif [ "$missing_group" -eq 1 ]; then
            if chgrp -h "${TARGET_GROUP}" "$path" 2>>"$LOG_FILE"; then
                FIX_OK=$((FIX_OK+1))
                echo "[FIX] chgrp ${TARGET_GROUP} $path" >> "$LOG_FILE"
            else
                FIX_FAIL=$((FIX_FAIL+1))
                echo "[FAIL] chgrp ${TARGET_GROUP} $path" >> "$LOG_FILE"
            fi
        fi
    done < "$BEFORE_LIST"

    find "$SEARCH_ROOT" -xdev \( -nouser -o -nogroup \) -print 2>/dev/null > "$AFTER_LIST"
    AFTER_COUNT=$(wc -l < "$AFTER_LIST" 2>/dev/null || echo 0)

    {
    echo "FIX_OK=$FIX_OK"
    echo "FIX_FAIL=$FIX_FAIL"
    echo "AFTER_COUNT=$AFTER_COUNT"
    echo "AFTER_LIST=$AFTER_LIST"
    } >> "$LOG_FILE"

    if [ "$AFTER_COUNT" -eq 0 ]; then
        echo "[완료] U-15 조치 완료 (잔여 0) | 수정:$FIX_OK 실패:$FIX_FAIL | 로그:$LOG_FILE"
        exit 0
    else
        echo "[실패] U-15 조치 후에도 잔여:$AFTER_COUNT | 수정:$FIX_OK 실패:$FIX_FAIL | 로그:$LOG_FILE"
        echo "남은 목록: $AFTER_LIST"
        exit 1
    fi
}

U_16() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    PASSWD_FILE="/etc/passwd"

    if [ ! -f "$PASSWD_FILE" ]; then
        echo "[ERROR] $PASSWD_FILE 파일 없음"
        exit 1
    fi

    CURRENT_OWNER=$(stat -c '%U' "$PASSWD_FILE" 2>/dev/null)
    CURRENT_PERM=$(stat -c '%a' "$PASSWD_FILE" 2>/dev/null)

    NEED_FIX=0

    if [ "$CURRENT_OWNER" != "root" ]; then
        NEED_FIX=1
    fi

    if [ "$CURRENT_PERM" != "644" ]; then
        NEED_FIX=1
    fi


    if [ $NEED_FIX -eq 1 ]; then
        chown root "$PASSWD_FILE" 2>/dev/null && chmod 644 "$PASSWD_FILE" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "[완료] U-16 조치 완료 (소유자: root, 권한: 644)"
        else
            echo "[실패] 조치 실패"
            exit 1
        fi
    else
        echo "[양호] 조치 불필요"
    fi
}

U_17() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    FIX_COUNT=0
    SKIP_MASKED=0
    FAIL_COUNT=0

    is_other_writable() {
    local perm="$1"
    local other=$(( perm % 10 ))
    [ $(( other & 2 )) -ne 0 ]
    }

    fix_target() {
    local target="$1"
    
    [ -f "$target" ] || return 0

    local owner perm
    owner="$(stat -c '%U' "$target" 2>/dev/null || true)"
    perm="$(stat -c '%a' "$target" 2>/dev/null || true)"

    [ -n "$owner" ] || return 0
    [ -n "$perm" ] || return 0

    local need=0
    [ "$owner" != "root" ] && need=1
    if is_other_writable "$perm"; then
        need=1
    fi

    if [ "$need" -eq 1 ]; then
        if chown root:root "$target" 2>/dev/null && chmod o-w "$target" 2>/dev/null; then
        FIX_COUNT=$((FIX_COUNT + 1))
        else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    fi
    }

    process_dir() {
    local dir="$1"
    [ -d "$dir" ] || return 0

    while IFS= read -r -d '' p; do
        if [ -L "$p" ]; then
   
        local t
        t="$(readlink -f "$p" 2>/dev/null || true)"
      
        if [ "$t" = "/dev/null" ]; then
            SKIP_MASKED=$((SKIP_MASKED + 1))
            continue
        fi

        [ -n "$t" ] || continue
        fix_target "$t"
        else

        fix_target "$p"
        fi
    done < <(find "$dir" \( -type f -o -type l \) -print0 2>/dev/null)
    }

    if [ -d /run/systemd/system ]; then
    process_dir "/etc/systemd/system"
    process_dir "/lib/systemd/system"
    process_dir "/usr/lib/systemd/system"
    else
  
    process_dir "/etc/rc.d"
    process_dir "/etc/init.d"
    fi

    if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "[완료] U-17 조치 완료 (수정: ${FIX_COUNT}개, 마스킹 제외: ${SKIP_MASKED}개, 실패: ${FAIL_COUNT}개)"
    else
    if [ "$FIX_COUNT" -eq 0 ]; then
        echo "[양호] 조치 불필요 (마스킹 제외: ${SKIP_MASKED}개)"
    else
        echo "[완료] U-17 조치 완료 (수정: ${FIX_COUNT}개, 마스킹 제외: ${SKIP_MASKED}개)"
    fi
  fi
}

U_18() {
    SHADOW_FILE="/etc/shadow"
    REQUIRED_OWNER="root"
    REQUIRED_PERM="400"

    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    if [ ! -f "$SHADOW_FILE" ]; then
        echo "[ERROR] $SHADOW_FILE 파일 없음"
        exit 1
    fi

    CURRENT_OWNER=$(stat -c '%U' "$SHADOW_FILE" 2>/dev/null)
    CURRENT_PERM=$(stat -c '%a' "$SHADOW_FILE" 2>/dev/null)

    NEED_FIX=0

    if [ "$CURRENT_OWNER" != "$REQUIRED_OWNER" ]; then
        NEED_FIX=1
    fi

    if [ "$CURRENT_PERM" -gt "$REQUIRED_PERM" ]; then
        NEED_FIX=1
    fi

    if [ $NEED_FIX -eq 1 ]; then
        chown root "$SHADOW_FILE" 2>/dev/null && chmod 400 "$SHADOW_FILE" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "[완료] U-18 조치 완료 (소유자: root, 권한: 400)"
        else
            echo "[실패] 조치 실패"
            exit 1
        fi
    else
        echo "[양호] 조치 불필요"
    fi
}

U_19() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    HOSTS_FILE="/etc/hosts"

    if [ ! -f "$HOSTS_FILE" ]; then
        echo "[ERROR] $HOSTS_FILE 파일 없음"
        exit 1
    fi

    CURRENT_OWNER=$(stat -c '%U' "$HOSTS_FILE" 2>/dev/null)
    CURRENT_PERM=$(stat -c '%a' "$HOSTS_FILE" 2>/dev/null)

    NEED_FIX=0

    if [ "$CURRENT_OWNER" != "root" ]; then
        NEED_FIX=1
    fi

    if [ "$CURRENT_PERM" != "644" ]; then
        NEED_FIX=1
    fi

    if [ $NEED_FIX -eq 1 ]; then
        chown root "$HOSTS_FILE" 2>/dev/null && chmod 644 "$HOSTS_FILE" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "[완료] U-19 조치 완료 (소유자: root, 권한: 644)"
        else
            echo "[실패] 조치 실패"
            exit 1
        fi
    else
        echo "[양호] 조치 불필요"
    fi
}

U_20() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    FIX_COUNT=0

    SYSTEM_CONF="/etc/systemd/system.conf"

    if [ -f "$SYSTEM_CONF" ]; then
        NEED_FIX=0
        
        OWNER=$(stat -c '%U' "$SYSTEM_CONF" 2>/dev/null)
        PERM=$(stat -c '%a' "$SYSTEM_CONF" 2>/dev/null)
        
        if [ "$OWNER" != "root" ]; then
            NEED_FIX=1
        fi
        
        if [ "$PERM" -gt 600 ]; then
            NEED_FIX=1
        fi
        
        if [ $NEED_FIX -eq 1 ]; then
            chown root "$SYSTEM_CONF" 2>/dev/null && chmod 600 "$SYSTEM_CONF" 2>/dev/null
            if [ $? -eq 0 ]; then
                ((FIX_COUNT++))
            fi
        fi
    fi

    SYSTEMD_DIR="/etc/systemd"

    if [ -d "$SYSTEMD_DIR" ]; then
        while IFS= read -r file; do
            if [ -f "$file" ]; then
                NEED_FIX=0
                
                OWNER=$(stat -c '%U' "$file" 2>/dev/null)
                PERM=$(stat -c '%a' "$file" 2>/dev/null)
                
                if [ "$OWNER" != "root" ]; then
                    NEED_FIX=1
                fi
                
                if [ "$PERM" -gt 600 ]; then
                    NEED_FIX=1
                fi
                
                if [ $NEED_FIX -eq 1 ]; then
                    chown root "$file" 2>/dev/null && chmod 600 "$file" 2>/dev/null
                    if [ $? -eq 0 ]; then
                        ((FIX_COUNT++))
                    fi
                fi
            fi
        done < <(find "$SYSTEMD_DIR" -type f 2>/dev/null)
     
        chown -R root "$SYSTEMD_DIR" 2>/dev/null
    fi

    if [ $FIX_COUNT -eq 0 ]; then
        echo "[양호] 조치 불필요"
    else
        echo "[완료] U-20 조치 완료 (수정: ${FIX_COUNT}개 파일)"
    fi
}

U_21() {
    SYSLOG_FILE="/etc/rsyslog.conf"
    REQUIRED_OWNER="root"
    REQUIRED_PERM="640"

    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    if [ ! -f "$SYSLOG_FILE" ]; then
        echo "[ERROR] $SYSLOG_FILE 파일 없음"
        exit 1
    fi

    CURRENT_OWNER=$(stat -c '%U' "$SYSLOG_FILE" 2>/dev/null)
    CURRENT_PERM=$(stat -c '%a' "$SYSLOG_FILE" 2>/dev/null)

    NEED_FIX=0

    if [ "$CURRENT_OWNER" != "$REQUIRED_OWNER" ]; then
        NEED_FIX=1
    fi

    if [ "$CURRENT_PERM" -gt "$REQUIRED_PERM" ]; then
        NEED_FIX=1
    fi

    if [ $NEED_FIX -eq 1 ]; then
        chown root "$SYSLOG_FILE" 2>/dev/null && chmod 640 "$SYSLOG_FILE" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "[완료] U-21 조치 완료 (소유자: root, 권한: 640)"
        else
            echo "[실패] 조치 실패"
            exit 1
        fi
    else
        echo "[양호] 조치 불필요"
    fi
}

U_22() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    SERVICES_FILE="/etc/services"

    if [ ! -f "$SERVICES_FILE" ]; then
        echo "[ERROR] $SERVICES_FILE 파일 없음"
        exit 1
    fi

    CURRENT_OWNER=$(stat -c '%U' "$SERVICES_FILE" 2>/dev/null)
    CURRENT_PERM=$(stat -c '%a' "$SERVICES_FILE" 2>/dev/null)

    NEED_FIX=0

    if [ "$CURRENT_OWNER" != "root" ] && [ "$CURRENT_OWNER" != "bin" ] && [ "$CURRENT_OWNER" != "sys" ]; then
        NEED_FIX=1
    fi

    if [ "$CURRENT_PERM" -gt 644 ]; then
        NEED_FIX=1
    fi

    if [ $NEED_FIX -eq 1 ]; then
        chown root "$SERVICES_FILE" 2>/dev/null && chmod 644 "$SERVICES_FILE" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "[완료] U-22 조치 완료 (소유자: root, 권한: 644)"
        else
            echo "[실패] 조치 실패"
            exit 1
        fi
    else
        echo "[양호] 조치 불필요"
    fi
}

U_24() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    ENV_FILES=(
    ".profile"
    ".kshrc"
    ".cshrc"
    ".bashrc"
    ".bash_profile"
    ".login"
    ".exrc"
    ".netrc"
    )

    TOTAL_FOUND=0
    TOTAL_FIXED=0
    TOTAL_ERRORS=0

    fix_one_file() {
        local user="$1"
        local home="$2"
        local fname="$3"
        local path="$home/$fname"

        if [ ! -f "$path" ]; then
            return 0
        fi

        TOTAL_FOUND=$((TOTAL_FOUND+1))

        local owner perm perm3 g o
        owner="$(stat -c '%U' "$path" 2>/dev/null)"
        perm="$(stat -c '%a' "$path" 2>/dev/null)"

        if [ -z "$owner" ] || [ -z "$perm" ]; then
            TOTAL_ERRORS=$((TOTAL_ERRORS+1))
            return 0
        fi

        perm3="${perm: -3}"
        g="${perm3:1:1}"
        o="${perm3:2:1}"

        case "$perm3" in
            *[!0-9]*)
                TOTAL_ERRORS=$((TOTAL_ERRORS+1))
                return 0
                ;;
        esac

        local need_fix=0

        if [ "$owner" != "root" ] && [ "$owner" != "$user" ]; then
            need_fix=1
            local target_group
            target_group="$(id -gn "$user" 2>/dev/null)"
            [ -z "$target_group" ] && target_group="$user"

            if ! chown "$user":"$target_group" "$path" 2>/dev/null; then
                TOTAL_ERRORS=$((TOTAL_ERRORS+1))
                return 0
            fi
        fi

        if (( (g & 2) != 0 )) || (( (o & 2) != 0 )); then
            need_fix=1
        fi

        if [ "$need_fix" -eq 1 ]; then
            if [ "$fname" = ".netrc" ]; then
        
                if ! chmod 600 "$path" 2>/dev/null; then
                    TOTAL_ERRORS=$((TOTAL_ERRORS+1))
                    return 0
                fi
            else
                if ! chmod go-w "$path" 2>/dev/null; then
                    TOTAL_ERRORS=$((TOTAL_ERRORS+1))
                    return 0
                fi
            fi

            TOTAL_FIXED=$((TOTAL_FIXED+1))
        fi
    }

    while IFS=: read -r user _ uid _ _ home shell; do
        [ -n "$home" ] || continue
        [ "$home" != "/" ] || continue
        [ -d "$home" ] || continue

        if [ "$uid" -ne 0 ] && [ "$uid" -lt 1000 ]; then
            continue
        fi

        case "$shell" in
            */nologin|*/false) continue ;;
        esac

        for f in "${ENV_FILES[@]}"; do
            fix_one_file "$user" "$home" "$f"
        done
    done < <(getent passwd)

    if [ "$TOTAL_ERRORS" -gt 0 ]; then
        echo "[실패] U-24 조치 실패 (오류: $TOTAL_ERRORS)"
        exit 1
    fi

    if [ "$TOTAL_FOUND" -eq 0 ]; then
        echo "[양호] 조치 불필요 (점검 대상 파일 없음)"
        exit 0
    fi

    if [ "$TOTAL_FIXED" -gt 0 ]; then
        echo "[완료] U-24 조치 완료 (점검: $TOTAL_FOUND, 조치: $TOTAL_FIXED)"
    else
        echo "[양호] 조치 불필요 (점검: $TOTAL_FOUND)"
    fi
}

U_25() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local SEARCH_ROOT="${U25_ROOT:-/}"
    local MAX_SHOW=5  
    local EXCLUDE_FIND_ARGS=(
        -not -path "/proc/*"
        -not -path "/sys/*"
        -not -path "/run/*"
        -not -path "/dev/*"
    )

    local FOUND_FILES=()
    local FIXED_LIST=()
    local FAILED_LIST=()

    while IFS= read -r -d '' f; do
        FOUND_FILES+=("$f")
    done < <(
        find "$SEARCH_ROOT" -xdev -type f -perm -0002 \
        "${EXCLUDE_FIND_ARGS[@]}" -print0 2>/dev/null
    )

    local TOTAL_FOUND=${#FOUND_FILES[@]}

    if [ "$TOTAL_FOUND" -eq 0 ]; then
        echo "✓ U-25 이미 양호 (world writable 파일 없음)"
        echo "   [!] Step3(불필요 파일 삭제)은 수동 확인이 필요합니다."
        return 0
    fi

    for f in "${FOUND_FILES[@]}"; do
        if [ ! -e "$f" ]; then
            FAILED_LIST+=("$f (사유: 파일이 사라짐)")
            continue
        fi

        local BEFORE_MODE=$(stat -c '%a' "$f" 2>/dev/null)
        local ERR_MSG
        ERR_MSG=$(chmod o-w "$f" 2>&1)

        if [ $? -eq 0 ]; then
            local AFTER_MODE=$(stat -c '%a' "$f" 2>/dev/null)
            FIXED_LIST+=("$f ($BEFORE_MODE -> $AFTER_MODE)")
        else
            FAILED_LIST+=("$f (chmod 실패: $ERR_MSG)")
        fi
    done

    local FIX_OK=${#FIXED_LIST[@]}
    local FIX_FAIL=${#FAILED_LIST[@]}

    if [ "$FIX_OK" -gt 0 ]; then
        echo "✓ U-25 조치 완료 (대상: ${TOTAL_FOUND}건 / 조치성공: ${FIX_OK}건)"
        local c=0
        for line in "${FIXED_LIST[@]}"; do
            echo "   - $line"
            ((c++))
            [ "$c" -ge "$MAX_SHOW" ] && { echo "   ... (이하 생략)"; break; }
        done
    fi

    if [ "$FIX_FAIL" -gt 0 ]; then
        echo "✗ U-25 조치 실패 (${FIX_FAIL}건)"
        local c=0
        for line in "${FAILED_LIST[@]}"; do
            echo "   - [실패] $line"
            ((c++))
            [ "$c" -ge "$MAX_SHOW" ] && break
        done
    fi

    echo "   [!] 수동 확인 필요: Step3(불필요 파일 삭제)은 운영 영향 검토 후 직접 수행하십시오."
}

U_26() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local FIX_COUNT=0
    local DEV_DIR="/dev"
    local UNWANTED_FILES=""
    local DELETED=0

    if [ ! -d "$DEV_DIR" ]; then
        echo "[ERROR] /dev 디렉터리가 존재하지 않습니다"
        return 1
    fi

    UNWANTED_FILES=$(find "$DEV_DIR" \
        \( -path "$DEV_DIR/mqueue" -o -path "$DEV_DIR/shm" \) -prune \
        -o -type f -print 2>/dev/null)

    if [ -z "$UNWANTED_FILES" ]; then
        echo "✓ U-26 이미 양호 (/dev 디렉터리 내 불필요한 일반 파일 없음)"
        return 0
    fi

    while IFS= read -r file; do
        if [ -n "$file" ]; then
            rm -f "$file" 2>/dev/null
            if [ $? -eq 0 ]; then
                ((DELETED++))
            fi
        fi
    done <<< "$UNWANTED_FILES"

    FIX_COUNT=$DELETED

    if [ "$FIX_COUNT" -gt 0 ]; then
        echo "✓ U-26 조치 완료 (불필요한 파일 제거: ${FIX_COUNT}개)"
    else
        echo "✗ U-26 조치 실패 (파일이 발견되었으나 삭제하지 못함)"
    fi
}

U_29() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    HOSTS_LPD="/etc/hosts.lpd"

    if [ ! -f "$HOSTS_LPD" ]; then
        echo "[양호] /etc/hosts.lpd 파일 없음"
        exit 0
    fi

    CURRENT_OWNER=$(stat -c '%U' "$HOSTS_LPD" 2>/dev/null)
    CURRENT_PERM=$(stat -c '%a' "$HOSTS_LPD" 2>/dev/null)

    NEED_FIX=0

    if [ "$CURRENT_OWNER" != "root" ]; then
        NEED_FIX=1
    fi

    if [ "$CURRENT_PERM" -gt 600 ]; then
        NEED_FIX=1
    fi

    if [ $NEED_FIX -eq 1 ]; then
        chown root "$HOSTS_LPD" 2>/dev/null && chmod 600 "$HOSTS_LPD" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "[완료] U-29 조치 완료 (소유자: root, 권한: 600)"
        else
            echo "[실패] 조치 실패"
            exit 1
        fi
    else
        echo "[양호] 조치 불필요"
    fi
}

U_31() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    PASSWD="/etc/passwd"

    if [ ! -f "$PASSWD" ]; then
        echo "[ERROR] $PASSWD 파일 없음"
        exit 1
    fi

    CHECKED=0
    FIXED=0
    CREATED=0
    ERRORS=0

    while IFS=: read -r user _ uid _ _ home shell; do
      
        case "$uid" in
            ''|*[!0-9]*) continue ;;
        esac

        if [ "$uid" -ne 0 ] && [ "$uid" -lt 1000 ]; then
            continue
        fi

        case "$shell" in
            */nologin|*/false) continue ;;
        esac

        if [ -z "$home" ] || [ "$home" = "/" ]; then
            continue
        fi


        if [ ! -d "$home" ]; then
            if [ "$home" = "/root" ] || [[ "$home" == /home/* ]]; then
                mkdir -p "$home" 2>/dev/null
                if [ $? -ne 0 ]; then
                    ERRORS=$((ERRORS+1))
                    continue
                fi
                CREATED=$((CREATED+1))
            else

                ERRORS=$((ERRORS+1))
                continue
            fi
        fi

        CHECKED=$((CHECKED+1))

        CUR_OWNER=$(stat -c '%U' "$home" 2>/dev/null)
        CUR_PERM=$(stat -c '%a' "$home" 2>/dev/null)

        if [ -z "$CUR_OWNER" ] || [ -z "$CUR_PERM" ]; then
            ERRORS=$((ERRORS+1))
            continue
        fi

        PERM3="${CUR_PERM: -3}"
        O_DIGIT="${PERM3:2:1}"

        NEED_FIX=0

        if [ "$CUR_OWNER" != "$user" ]; then
            NEED_FIX=1
        fi

        case "$O_DIGIT" in
            ''|*[!0-9]*) NEED_FIX=1 ;;
            *)
                if (( (O_DIGIT & 2) != 0 )); then
                    NEED_FIX=1
                fi
                ;;
        esac


        if [ $NEED_FIX -eq 1 ]; then
            chown "$user" "$home" 2>/dev/null
            if [ $? -ne 0 ]; then
                ERRORS=$((ERRORS+1))
                continue
            fi

            chmod o-w "$home" 2>/dev/null
            if [ $? -ne 0 ]; then
                ERRORS=$((ERRORS+1))
                continue
            fi

            FIXED=$((FIXED+1))
        fi

    done < "$PASSWD"

    if [ "$ERRORS" -gt 0 ]; then
        echo "[실패] U-31 조치 실패 (오류: $ERRORS)"
        exit 1
    fi

    if [ "$CHECKED" -eq 0 ]; then
        echo "[양호] 조치 불필요 (점검 대상 계정 없음)"
        exit 0
    fi

    if [ "$FIXED" -gt 0 ] || [ "$CREATED" -gt 0 ]; then
        echo "[완료] U-31 조치 완료 (점검: $CHECKED, 생성: $CREATED, 조치: $FIXED)"
    else
        echo "[양호] 조치 불필요 (점검: $CHECKED)"
    fi
}

U_32() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local FIX_COUNT=0
    local DELETED_USERS=""
    local USERS_TO_CHECK=$(awk -F: '
        $3 >= 1000 && 
        $7 !~ /nologin|false|sync/ && 
        $1 != "nobody" 
        {print $1":"$6}
    ' /etc/passwd)

    if [ -z "$USERS_TO_CHECK" ]; then
        echo "✓ U-32 이미 양호 (점검 대상 사용자 없음)"
        return 0
    fi

 
    while IFS=: read -r username homedir; do
        if [ -z "$username" ]; then continue; fi

        if [ ! -d "$homedir" ]; then
            
            userdel "$username" &>/dev/null
            if [ $? -eq 0 ]; then
                ((FIX_COUNT++))
                DELETED_USERS="$DELETED_USERS $username"
            fi
        fi
    done <<< "$USERS_TO_CHECK"

    if [ "$FIX_COUNT" -gt 0 ]; then
        echo "✓ U-32 조치 완료 (홈 디렉터리 없는 계정 ${FIX_COUNT}개 삭제)"
        echo "   - 삭제된 계정:$DELETED_USERS"
    else
        echo "✓ U-32 이미 양호 (홈 디렉터리가 없는 사용자 계정 없음)"
    fi
}

U_34() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    UNIT_SOCKET="finger.socket"
    UNIT_SERVICE_TMPL="finger@.service"

    UNIT_FILE_SOCKET="/etc/systemd/system/${UNIT_SOCKET}"
    UNIT_FILE_SERVICE="/etc/systemd/system/${UNIT_SERVICE_TMPL}"

    NEED_RELOAD=0
    FAILED=0

    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "${UNIT_SOCKET}"; then
        systemctl disable --now "${UNIT_SOCKET}" >/dev/null 2>&1
        systemctl reset-failed "${UNIT_SOCKET}" >/dev/null 2>&1
    fi

    if [ -f "${UNIT_FILE_SOCKET}" ]; then
        rm -f "${UNIT_FILE_SOCKET}" >/dev/null 2>&1 && NEED_RELOAD=1
    fi

    if [ -f "${UNIT_FILE_SERVICE}" ]; then
        rm -f "${UNIT_FILE_SERVICE}" >/dev/null 2>&1 && NEED_RELOAD=1
    fi

    if [ "${NEED_RELOAD}" -eq 1 ]; then
        systemctl daemon-reload >/dev/null 2>&1
    fi

    systemctl disable --now inetutils-inetd >/dev/null 2>&1 || true
    systemctl disable --now openbsd-inetd  >/dev/null 2>&1 || true
    systemctl disable --now xinetd         >/dev/null 2>&1 || true

    if [ -f /etc/inetd.conf ]; then
        if grep -qE '^[[:space:]]*finger[[:space:]]' /etc/inetd.conf; then
            
           sed -i 's/^[[:space:]]*\(finger[[:space:]].*\)$/#\1/' /etc/inetd.conf >/dev/null 2>&1 || true
        fi
    fi

    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE '(:79$|\]:79$)'; then
        echo "[실패] U-34 조치 실패 (79/tcp 여전히 LISTEN)"
        exit 1
    fi
    echo "[완료] U-34 조치 완료 (Finger 비활성화)"
}

U_36() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local FIX_COUNT=0
    local INETD_CONF="/etc/inetd.conf"
    local XINETD_DIR="/etc/xinetd.d"
    _u36_has_systemctl() {
        command -v systemctl >/dev/null 2>&1
    }

    _u36_unit_exists() {
        local unit="$1"
        local st
        st="$(systemctl show -p LoadState --value "$unit" 2>/dev/null)"
        [ "$st" = "loaded" ] || [ "$st" = "masked" ]
    }

    _u36_backup_file() {
        local f="$1"
        if [ -f "$f" ]; then
            local ts
            ts="$(date +%Y%m%d%H%M%S)"
            cp -a "$f" "${f}.bak.u36.${ts}" >/dev/null 2>&1
        fi
    }

    if _u36_has_systemctl; then
        local targets=(rlogin rsh rexec)
        local svc unit changed

        for svc in "${targets[@]}"; do
            for unit in "${svc}.service" "${svc}.socket"; do
                if _u36_unit_exists "$unit"; then
                    changed=0
        
                    if systemctl is-active --quiet "$unit" 2>/dev/null; then
                        systemctl stop "$unit" >/dev/null 2>&1 && changed=1
                    fi
                   
                    systemctl disable "$unit" >/dev/null 2>&1 && changed=1
                   
                    systemctl mask "$unit" >/dev/null 2>&1 && changed=1

                    if [ "$changed" -eq 1 ]; then
                        ((FIX_COUNT++))
                      
                    fi
                fi
            done
        done
    fi

 
    if [ -f "$INETD_CONF" ]; then
        if grep -qE '^[[:space:]]*(login|shell|exec)[[:space:]]' "$INETD_CONF"; then
            _u36_backup_file "$INETD_CONF"
        
            sed -i -E 's/^[[:space:]]*(login|shell|exec)[[:space:]]/# \1 /' "$INETD_CONF" >/dev/null 2>&1
            ((FIX_COUNT++))
            
            if _u36_has_systemctl; then
                for s in openbsd-inetd.service inetutils-inetd.service inetd.service; do
                    if _u36_unit_exists "$s"; then
                        systemctl restart "$s" >/dev/null 2>&1
                    fi
                done
            fi
        fi
    fi

    if [ -d "$XINETD_DIR" ]; then
        local f conf
        for f in rlogin rsh rexec; do
            conf="${XINETD_DIR}/${f}"
            if [ -f "$conf" ]; then
               
                if grep -qE '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no' "$conf"; then
                    _u36_backup_file "$conf"
                    sed -i -E 's/^[[:space:]]*disable[[:space:]]*=[[:space:]]*no[[:space:]]*$/\tdisable\t\t= yes/' "$conf" >/dev/null 2>&1
                    ((FIX_COUNT++))
                
                elif ! grep -qE '^[[:space:]]*disable[[:space:]]*=' "$conf"; then
                    _u36_backup_file "$conf"
                    awk '
                        BEGIN{added=0}
                        {print}
                        $0 ~ /^[[:space:]]*\{[[:space:]]*$/ && added==0 {
                            print "\tdisable\t\t= yes"
                            added=1
                        }
                    ' "$conf" > "${conf}.tmp.u36" && mv "${conf}.tmp.u36" "$conf"
                    ((FIX_COUNT++))
                fi
            fi
        done

        if [ "$FIX_COUNT" -gt 0 ] && _u36_has_systemctl; then
             if _u36_unit_exists "xinetd.service"; then
                systemctl restart xinetd.service >/dev/null 2>&1
             fi
        fi
    fi

    if [ "$FIX_COUNT" -gt 0 ]; then
        echo "✓ U-36 조치 완료 (r 계열 서비스 비활성화: ${FIX_COUNT}건)"
    else
        echo "✓ U-36 이미 양호 (r 계열 서비스가 비활성화되어 있음)"
    fi
}

U_37() {
  echo "[시작] U-37 cron 및 at 관련 파일 권한 조치를 시작합니다."
  local LOG_FILE="/root/u37_remediation_log.txt"
  echo "--- U-37 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local BIN_FILES=("/usr/bin/crontab" "/usr/bin/at" "/usr/bin/atq" "/usr/bin/atrm" "/bin/crontab" "/bin/at")
  
  for file in "${BIN_FILES[@]}"; do
    if [ -f "$file" ]; then
      local real_path=$(readlink -f "$file")
      
      chown root:root "$real_path" 2>/dev/null
      chmod 750 "$real_path" 2>/dev/null
      chmod -s "$real_path" 2>/dev/null  
      
      chown -h root "$file" 2>/dev/null
      echo "[완료] 명령어 $file 조치 완료" >> "$LOG_FILE"
    fi
  done

  local TARGET_PATHS=(
    "/etc/crontab" "/etc/anacrontab" "/etc/cron.allow" "/etc/cron.deny" 
    "/etc/at.allow" "/etc/at.deny" "/etc/cron.d" "/etc/cron.hourly" 
    "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" 
    "/var/spool/cron" "/var/spool/at"
  )

  for path in "${TARGET_PATHS[@]}"; do
    if [ -e "$path" ]; then
      local real_path=$(readlink -f "$path")

      if [ -d "$real_path" ]; then
        chown -R root:root "$real_path" 2>/dev/null
        chmod 750 "$real_path" 2>/dev/null
       
        find "$real_path" -maxdepth 1 -type f -exec chmod 640 {} + 2>/dev/null
        echo "[완료] 디렉터리 $path 및 내부 파일 조치 완료" >> "$LOG_FILE"
      else
      
        chown root:root "$real_path" 2>/dev/null
        chmod 640 "$real_path" 2>/dev/null
       
        chown -h root "$path" 2>/dev/null
        echo "[완료] 파일 $path 조치 완료" >> "$LOG_FILE"
      fi
    fi
  done

  echo "----------------------------------------------------------"
  echo "[완료] U-37 조치가 모두 마무리되었습니다. 상세 내역: $LOG_FILE"
}

U_38() {
   
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local FIX_COUNT=0
    local XINETD_DIR="/etc/xinetd.d"
    local INETD_CONF="/etc/inetd.conf"
    
   
    _u38_unit_exists() {
        local unit="$1"
        systemctl list-unit-files --no-legend "$unit" 2>/dev/null | awk '{print $1}' | grep -qx "$unit"
    }

    _u38_disable_unit() {
        local unit="$1"
        if _u38_unit_exists "$unit"; then
           
            if systemctl is-active --quiet "$unit" 2>/dev/null || \
               [ "$(systemctl is-enabled "$unit" 2>/dev/null)" = "enabled" ]; then
                
                systemctl stop "$unit" 2>/dev/null || true
                systemctl disable "$unit" 2>/dev/null || true
                systemctl mask "$unit" 2>/dev/null || true
                ((FIX_COUNT++))
            fi
        fi
    }

    _u38_disable_unit "chrony.service"
    _u38_disable_unit "systemd-timesyncd.service"
    _u38_disable_unit "ntp.service"
    _u38_disable_unit "ntpsec.service"
    _u38_disable_unit "openntpd.service"

    _u38_disable_unit "bind9.service"
    _u38_disable_unit "named.service"
    _u38_disable_unit "dnsmasq.service"

    _u38_disable_unit "snmpd.service"

   
    _u38_disable_unit "postfix.service"
    _u38_disable_unit "exim4.service"
    _u38_disable_unit "sendmail.service"

    local SOCKET_UNITS=(
        "echo.socket" "echo-dgram.socket"
        "discard.socket" "discard-dgram.socket"
        "daytime.socket" "daytime-dgram.socket"
        "chargen.socket" "chargen-dgram.socket"
    )

    for s in "${SOCKET_UNITS[@]}"; do
        _u38_disable_unit "$s"
    done

 
    if [ -d "$XINETD_DIR" ]; then
        for svc in echo discard daytime chargen; do
            local f="$XINETD_DIR/$svc"
            if [ -f "$f" ]; then
                
                if grep -Eq '^[[:space:]]*disable[[:space:]]*=[[:space:]]*no[[:space:]]*$' "$f"; then
                    cp -a "$f" "${f}.bak" 2>/dev/null || true
                    sed -i -E 's/^[[:space:]]*disable[[:space:]]*=[[:space:]]*no[[:space:]]*$/  disable = yes/' "$f"
                    ((FIX_COUNT++))
                else
                   
                    if ! grep -Eq '^[[:space:]]*disable[[:space:]]*=' "$f"; then
                        cp -a "$f" "${f}.bak" 2>/dev/null || true
                        sed -i -E '0,/^{/{s/^{/{\n  disable = yes/}' "$f"
                        ((FIX_COUNT++))
                    fi
                fi
            fi
        done

        if [ "$FIX_COUNT" -gt 0 ] && _u38_unit_exists "xinetd.service"; then
            systemctl restart xinetd.service 2>/dev/null || true
        fi
    fi

 
    if [ -f "$INETD_CONF" ]; then
        if grep -Eq '^[[:space:]]*(echo|discard|daytime|chargen)\b' "$INETD_CONF"; then
            cp -a "$INETD_CONF" "${INETD_CONF}.bak" 2>/dev/null || true
            sed -i -E '/^[[:space:]]*(echo|discard|daytime|chargen)\b/ s/^/# [U-38 disabled] /' "$INETD_CONF"
            ((FIX_COUNT++))

            if _u38_unit_exists "openbsd-inetd.service"; then
                systemctl restart openbsd-inetd.service 2>/dev/null || true
            elif _u38_unit_exists "inetd.service"; then
                systemctl restart inetd.service 2>/dev/null || true
            fi
        fi
    fi

    local PORT_PATTERN=':(7|9|13|19|25|53|123|161|162)\b'
    local LISTEN_LEFT
    LISTEN_LEFT="$(ss -lntup 2>/dev/null | grep -E "$PORT_PATTERN" || true)"

    if [ "$FIX_COUNT" -gt 0 ]; then
        echo "✓ U-38 조치 완료 (DoS 취약 서비스 ${FIX_COUNT}건 비활성화/설정변경)"
    else
        echo "✓ U-38 이미 양호 (대상 서비스가 없거나 이미 비활성화됨)"
    fi

    if [ -n "$LISTEN_LEFT" ]; then
        echo "   [!] 경고: 조치 후에도 일부 포트가 리슨 중입니다 (수동 확인 권장):"
        echo "$LISTEN_LEFT" | sed 's/^/      /'
    fi
}

U_39() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local FIX_COUNT=0
    local CHANGED=0
    local CUSTOM_UNIT_PATH="/etc/systemd/system/nfs-server.service"
    local REMAIN=0

    _u39_unit_load_state() {
        systemctl show -p LoadState --value "$1" 2>/dev/null
    }

    _u39_unit_exists() {
        local st
        st="$(_u39_unit_load_state "$1")"
        [ -n "$st" ] && [ "$st" != "not-found" ]
    }

    _u39_unit_is_active() {
        systemctl is-active --quiet "$1" 2>/dev/null
    }

    _u39_unit_is_enabled() {
        systemctl is-enabled --quiet "$1" 2>/dev/null
    }

    _u39_stop_disable_mask() {
        local unit="$1"
        local did=0

        if _u39_unit_is_active "$unit"; then
            systemctl stop "$unit" >/dev/null 2>&1 && did=1
        fi

        systemctl disable "$unit" >/dev/null 2>&1 && did=1

        systemctl mask "$unit" >/dev/null 2>&1 && did=1

        if [ "$did" -eq 1 ]; then
            ((FIX_COUNT++))
            CHANGED=1
        fi
    }

    local NFS_UNITS=(
        "nfs-server.service" "nfs-kernel-server.service"
        "nfs-server" "nfs-kernel-server"
        "rpcbind.service" "rpcbind.socket"
        "rpc-statd.service" "rpc-statd"
        "nfs-idmapd.service" "nfs-idmapd"
        "nfs-mountd.service" "nfs-mountd"
        "nfsdcld.service" "nfsdcld"
    )

    local FOUND_IN_SCOPE=0
    local FOUND_ACTIVE_OR_ENABLED=0

    for u in "${NFS_UNITS[@]}"; do
        if _u39_unit_exists "$u"; then
            FOUND_IN_SCOPE=1
            if _u39_unit_is_active "$u" || _u39_unit_is_enabled "$u"; then
                FOUND_ACTIVE_OR_ENABLED=1
            fi
        fi
    done

    if systemctl list-units --type=service --all 2>/dev/null | grep -qi nfs; then
        FOUND_IN_SCOPE=1
    fi

    if [ "$FOUND_IN_SCOPE" -eq 0 ] || [ "$FOUND_ACTIVE_OR_ENABLED" -eq 0 ]; then
        echo "✓ U-39 이미 양호 (NFS 관련 서비스가 비활성화 상태)"
        return 0
    fi

    for u in "${NFS_UNITS[@]}"; do
        if _u39_unit_exists "$u"; then
            
            if _u39_unit_is_active "$u" || _u39_unit_is_enabled "$u"; then
                _u39_stop_disable_mask "$u"
            fi
        fi
    done

  
    if [ -f "$CUSTOM_UNIT_PATH" ]; then
        rm -f "$CUSTOM_UNIT_PATH" >/dev/null 2>&1 && {
            ((FIX_COUNT++))
            CHANGED=1
        }
    fi

    if [ "$CHANGED" -eq 1 ]; then
        systemctl daemon-reload >/dev/null 2>&1
    fi

    for u in "${NFS_UNITS[@]}"; do
        if _u39_unit_exists "$u"; then
            if _u39_unit_is_active "$u" || _u39_unit_is_enabled "$u"; then
                REMAIN=1
            fi
        fi
    done

    if [ "$REMAIN" -eq 0 ]; then
        if [ "$CHANGED" -eq 1 ]; then
             echo "✓ U-39 조치 완료 (NFS 서비스 비활성화: ${FIX_COUNT}건 조치)"
        else
             echo "✓ U-39 이미 양호"
        fi
    else
        echo "✗ U-39 조치 실패 (일부 NFS 서비스가 여전히 활성 상태임)"
    fi
}

U_41() {
   
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local SERVICE_NAME="autofs"
    local UNIT_CHECK
    local CURRENT_ACTIVE
    local CURRENT_ENABLED
    local NEED_FIX=0
    local RESULT_ACTIVE
    local RESULT_ENABLED

   
    UNIT_CHECK=$(systemctl list-unit-files | grep -E "^${SERVICE_NAME}" | wc -l)

    if [ "$UNIT_CHECK" -eq 0 ]; then
        echo "✓ U-41 이미 양호 ($SERVICE_NAME 서비스가 설치되어 있지 않습니다)"
        return 0
    fi

    CURRENT_ACTIVE=$(systemctl is-active "$SERVICE_NAME")
    CURRENT_ENABLED=$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null)

   
    if [ "$CURRENT_ACTIVE" == "active" ] || [ "$CURRENT_ENABLED" == "enabled" ]; then
        NEED_FIX=1
    fi


    if [ $NEED_FIX -eq 1 ]; then
    
        systemctl stop "$SERVICE_NAME" 2>/dev/null
        
       
        systemctl disable "$SERVICE_NAME" 2>/dev/null
    
        RESULT_ACTIVE=$(systemctl is-active "$SERVICE_NAME")
        RESULT_ENABLED=$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null)

        if [ "$RESULT_ACTIVE" != "active" ] && [ "$RESULT_ENABLED" != "enabled" ]; then
            echo "✓ U-41 조치 완료 ($SERVICE_NAME 비활성화)"
        else
            echo "✗ U-41 조치 실패 ($SERVICE_NAME 상태 확인 필요)"
        fi
    else
        echo "✓ U-41 이미 양호 ($SERVICE_NAME 이미 비활성화됨)"
    fi
}

U_42() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    if [ ! -d /run/systemd/system ]; then
        echo "[N/A] systemd 환경이 아님"
        exit 0
    fi

    FIX_COUNT=0
    CHANGED=()

    ts() { date +%Y%m%d%H%M%S; }

    unit_exists() {
        local u="$1"
        systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "$u"
    }

    stop_disable_mask() {
        local u="$1"

        if ! unit_exists "$u"; then
            return 1
        fi

        local changed=0

        if systemctl is-active --quiet "$u" 2>/dev/null; then
            systemctl stop "$u" >/dev/null 2>&1 || true
            changed=1
        fi

        if systemctl is-enabled --quiet "$u" 2>/dev/null; then
            systemctl disable "$u" >/dev/null 2>&1 || true
            changed=1
        fi

        if systemctl is-active --quiet "$u" 2>/dev/null; then
            systemctl mask --now "$u" >/dev/null 2>&1 || true
            changed=1
        fi

        if [ $changed -eq 1 ]; then
            ((FIX_COUNT++))
            CHANGED+=("$u")
            return 0
        fi

        return 1
    }

    candidates_for_name() {
        local name="$1"               
        local base="${name#rpc.}"      
        local dash="${name//./-}"     

        echo "${name}.service"
        echo "${dash}.service"
        echo "${base}.service"

        echo "${name}.socket"
        echo "${dash}.socket"
        echo "${base}.socket"
    }

    RPC_LIST=(
    "rpc.cmsd"
    "rpc.ttdbserverd"
    "sadmind"
    "rusersd"
    "walld"
    "sprayd"
    "rstatd"
    "rpc.nisd"
    "rexd"
    "rpc.pcnfsd"
    "rpc.ypupdated"
    "rpc.rquotad"
    "kcms_server"
    "cachefsd"
    )

    for n in "${RPC_LIST[@]}"; do
        while IFS= read -r u; do
            stop_disable_mask "$u" || true
        done < <(candidates_for_name "$n")
    done

    EXTRA_UNITS=(
    "rpcbind.socket"
    "rpcbind.service"

    "nfs-client.target"
    "nfs-server.service"
    "nfs-kernel-server.service"

    "rpc-statd.service"
    "rpc-statd-notify.service"
    "rpc-mountd.service"
    "rpc-idmapd.service"
    "nfs-idmapd.service"
    )

    for u in "${EXTRA_UNITS[@]}"; do
        stop_disable_mask "$u" || true
    done

    TEST_UNITS=(
    "/etc/systemd/system/u42-test-rquotad.service"
    "/etc/systemd/system/u42-test-rusersd.service"
    )
    removed_test=0
    for f in "${TEST_UNITS[@]}"; do
        if [ -f "$f" ]; then
          
            b="$(basename "$f")"
            stop_disable_mask "$b" || true
            cp "$f" "${f}.bak.$(ts)" 2>/dev/null || true
            rm -f "$f"
            removed_test=1
            ((FIX_COUNT++))
            CHANGED+=("removed:$b")
        fi
    done
    if [ $removed_test -eq 1 ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    XINETD_DIR="/etc/xinetd.d"
    if [ -d "$XINETD_DIR" ]; then
        for f in "$XINETD_DIR"/*; do
            [ -f "$f" ] || continue

            hit=0
            for n in "${RPC_LIST[@]}"; do
                base="${n#rpc.}"
                if grep -qiE "^[[:space:]]*service[[:space:]]+(${n}|${base})\\b" "$f" 2>/dev/null; then
                    hit=1
                    break
                fi
            done
            [ $hit -eq 1 ] || continue

            if grep -qiE "^[[:space:]]*disable[[:space:]]*=[[:space:]]*no\\b" "$f" 2>/dev/null; then
                cp "$f" "${f}.bak.$(ts)" 2>/dev/null || true
                sed -i -E "s/^([[:space:]]*disable[[:space:]]*=[[:space:]]*)no\\b/\\1yes/I" "$f" 2>/dev/null || true
                ((FIX_COUNT++))
                CHANGED+=("xinetd:$(basename "$f")")
            fi
        done

        if unit_exists "xinetd.service" && systemctl is-active --quiet xinetd.service 2>/dev/null; then
            systemctl restart xinetd.service >/dev/null 2>&1 || true
        fi
    fi

    INETD_CONF="/etc/inetd.conf"
    if [ -f "$INETD_CONF" ]; then
        need=0
        for n in "${RPC_LIST[@]}"; do
            base="${n#rpc.}"
            if grep -nE "^[[:space:]]*[^#].*\\b(${n}|${base})\\b" "$INETD_CONF" >/dev/null 2>&1; then
                need=1
                break
            fi
        done

        if [ $need -eq 1 ]; then
            cp "$INETD_CONF" "${INETD_CONF}.bak.$(ts)" 2>/dev/null || true
            for n in "${RPC_LIST[@]}"; do
                base="${n#rpc.}"
                sed -i -E "/^[[:space:]]*[^#].*\\b(${n}|${base})\\b/ s/^[[:space:]]*/# /" "$INETD_CONF" 2>/dev/null || true
            done
            ((FIX_COUNT++))
            CHANGED+=("inetd.conf")

            if unit_exists "openbsd-inetd.service" && systemctl is-active --quiet openbsd-inetd.service 2>/dev/null; then
                systemctl restart openbsd-inetd.service >/dev/null 2>&1 || true
            fi
        fi
    fi

    still_bad=0

    if systemctl is-active --quiet rpcbind.service 2>/dev/null || systemctl is-active --quiet rpcbind.socket 2>/dev/null; then
        still_bad=1
    fi

    for u in nfs-kernel-server.service nfs-server.service rpc-statd.service; do
        if unit_exists "$u" && systemctl is-active --quiet "$u" 2>/dev/null; then
            still_bad=1
        fi
    done

    if [ $still_bad -eq 1 ]; then
        echo "[취약] 조치 후에도 rpcbind/NFS/RPC 관련 서비스가 active 상태입니다."
        echo " 확인: systemctl --no-pager --type=service --state=active | egrep 'rpcbind|nfs|rpc-'"
        exit 1
    fi

    if [ $FIX_COUNT -eq 0 ]; then
        echo "[양호] 조치 불필요"
    else
        echo "[완료] U-42 조치 완료 (수정: ${FIX_COUNT}개)"
    fi
}

U_43() {
   
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local FIX_COUNT=0
    local CHANGED=0
    local REMAIN=0

    _u43_unit_exists() {
        local st
        st="$(systemctl show -p LoadState --value "$1" 2>/dev/null)"
        [ -n "$st" ] && [ "$st" != "not-found" ]
    }

    _u43_unit_is_active() {
        systemctl is-active --quiet "$1" 2>/dev/null
    }

    _u43_unit_is_enabled() {
        systemctl is-enabled --quiet "$1" 2>/dev/null
    }

    _u43_stop_disable_mask() {
        local unit="$1"
        local did=0

        if _u43_unit_is_active "$unit"; then
            systemctl stop "$unit" >/dev/null 2>&1 && did=1
        fi

        systemctl disable "$unit" >/dev/null 2>&1 && did=1
        
        systemctl mask "$unit" >/dev/null 2>&1 && did=1

        if [ "$did" -eq 1 ]; then
            ((FIX_COUNT++))
            CHANGED=1
        fi
    }

    local NIS_UNITS=(
        "ypserv.service" "ypbind.service" "ypxfrd.service"
        "rpc.yppasswdd.service" "rpc.ypupdated.service"
        "nis.service" "nis-client.service" "nis-domainname.service"
    )

    local FOUND=0
    local NEED_FIX=0

    for u in "${NIS_UNITS[@]}"; do
        if _u43_unit_exists "$u"; then
            FOUND=1
            if _u43_unit_is_active "$u" || _u43_unit_is_enabled "$u"; then
                NEED_FIX=1
            fi
        fi
    done

    if [ "$FOUND" -eq 0 ] || [ "$NEED_FIX" -eq 0 ]; then
        echo "✓ U-43 이미 양호 (NIS 관련 서비스 미사용 또는 비활성화)"
        return 0
    fi

    for u in "${NIS_UNITS[@]}"; do
        if _u43_unit_exists "$u"; then
            if _u43_unit_is_active "$u" || _u43_unit_is_enabled "$u"; then
                _u43_stop_disable_mask "$u"
            fi
        fi
    done

    local CUSTOM_UNITS=(
        "/etc/systemd/system/ypserv.service"
        "/etc/systemd/system/ypbind.service"
        "/etc/systemd/system/ypxfrd.service"
        "/etc/systemd/system/rpc.yppasswdd.service"
        "/etc/systemd/system/rpc.ypupdated.service"
    )

    for f in "${CUSTOM_UNITS[@]}"; do
        if [ -f "$f" ]; then
            rm -f "$f" >/dev/null 2>&1 && {
                ((FIX_COUNT++))
                CHANGED=1
            }
        fi
    done

    if [ "$CHANGED" -eq 1 ]; then
        systemctl daemon-reload >/dev/null 2>&1
    fi

    for u in "${NIS_UNITS[@]}"; do
        if _u43_unit_exists "$u"; then
            if _u43_unit_is_active "$u" || _u43_unit_is_enabled "$u"; then
                REMAIN=1
            fi
        fi
    done

    if [ "$REMAIN" -eq 0 ]; then
        echo "✓ U-43 조치 완료 (NIS 서비스 비활성화: ${FIX_COUNT}건 조치)"
    else
        echo "✗ U-43 조치 실패 (일부 NIS 서비스가 여전히 활성 상태임)"
    fi
}

U_44() {
  
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local TARGET_SERVICES="tftp tftpd tftpd-hpa talk talkd ntalk ntalkd"
    local INETD_CONF="/etc/inetd.conf"
    local XINETD_DIR="/etc/xinetd.d"
    local NEED_FIX=0
    local CHECK_AGAIN=0
    local service

    for service in $TARGET_SERVICES; do
        if systemctl is-active --quiet "$service"; then
            NEED_FIX=1
        fi
    done

    if [ -f "$INETD_CONF" ]; then
     
        if grep -E "^tftp|^talk|^ntalk" "$INETD_CONF" >/dev/null; then
            NEED_FIX=1
        fi
    fi

    if [ -d "$XINETD_DIR" ]; then

        if grep -r "disable.*=.*no" "$XINETD_DIR" 2>/dev/null | grep -E "tftp|talk|ntalk" >/dev/null; then
            NEED_FIX=1
        fi
    fi

    if [ $NEED_FIX -eq 1 ]; then
       
        for service in $TARGET_SERVICES; do
            if systemctl is-active --quiet "$service"; then
                systemctl stop "$service" 2>/dev/null
                systemctl disable "$service" 2>/dev/null
            fi
        done

       
        if [ -f "$INETD_CONF" ]; then
            sed -i 's/^tftp/#tftp/g' "$INETD_CONF"
            sed -i 's/^talk/#talk/g' "$INETD_CONF"
            sed -i 's/^ntalk/#ntalk/g' "$INETD_CONF"
          
            systemctl restart openbsd-inetd 2>/dev/null || systemctl restart inetd 2>/dev/null
        fi

        if [ -d "$XINETD_DIR" ]; then
          
            if grep -r "disable.*=.*no" "$XINETD_DIR" 2>/dev/null | grep -qE "tftp|talk|ntalk"; then
                grep -lE "service.*(tftp|talk|ntalk)" "$XINETD_DIR"/* 2>/dev/null | xargs sed -i 's/disable.*=.*/disable = yes/g' 2>/dev/null
                systemctl restart xinetd 2>/dev/null
            fi
        fi

        CHECK_AGAIN=0
        
        for service in $TARGET_SERVICES; do
            systemctl is-active --quiet "$service" && CHECK_AGAIN=1
        done
  
        if [ -f "$INETD_CONF" ]; then
            grep -E "^tftp|^talk|^ntalk" "$INETD_CONF" >/dev/null && CHECK_AGAIN=1
        fi
       
        if [ -d "$XINETD_DIR" ]; then
             if grep -r "disable.*=.*no" "$XINETD_DIR" 2>/dev/null | grep -E "tftp|talk|ntalk" >/dev/null; then
                CHECK_AGAIN=1
             fi
        fi

        if [ $CHECK_AGAIN -eq 0 ]; then
            echo "✓ U-44 조치 완료 (tftp, talk, ntalk 서비스 비활성화)"
        else
            echo "✗ U-44 조치 실패 (일부 서비스가 여전히 활성화 상태임)"
        fi

    else
        echo "✓ U-44 이미 양호 (tftp, talk, ntalk 서비스 비활성화됨)"
    fi
}

U_45() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    FIX_COUNT=0


    if systemctl list-units --type=service 2>/dev/null | grep -q sendmail; then
        if systemctl is-active --quiet sendmail 2>/dev/null; then
           
            echo "[확인] Sendmail 사용 중 - 버전 점검 필요"
            sendmail -d0 -bt < /dev/null 2>&1 | head -1
            echo "※ 최신 버전으로 업데이트 권장: sudo apt update && sudo apt upgrade sendmail"
        else
          
            systemctl stop sendmail 2>/dev/null
            systemctl disable sendmail 2>/dev/null
            ((FIX_COUNT++))
        fi
    fi

    

    if systemctl list-units --type=service 2>/dev/null | grep -q postfix || \
    ps -ef 2>/dev/null | grep -v grep | grep -q postfix; then
        
        if systemctl is-active --quiet postfix 2>/dev/null; then
            
            echo "[확인] Postfix 사용 중 - 버전 점검 필요"
            postconf mail_version 2>/dev/null || echo "버전 확인 실패"
            echo "※ 최신 버전으로 업데이트 권장: sudo apt update && sudo apt upgrade postfix"
        else
          
            POSTFIX_PIDS=$(ps -ef | grep postfix | grep -v grep | awk '{print $2}')
            if [ -n "$POSTFIX_PIDS" ]; then
                for pid in $POSTFIX_PIDS; do
                    kill -9 "$pid" 2>/dev/null
                done
                ((FIX_COUNT++))
            fi
            systemctl disable postfix 2>/dev/null
        fi
    fi


    EXIM_SERVICE=""
    if systemctl list-units --type=service 2>/dev/null | grep -q "exim4"; then
        EXIM_SERVICE="exim4"
    elif systemctl list-units --type=service 2>/dev/null | grep -q "exim"; then
        EXIM_SERVICE="exim"
    fi

    if [ -n "$EXIM_SERVICE" ] || ps -ef 2>/dev/null | grep -v grep | grep -q exim; then
        
        if systemctl is-active --quiet exim4 2>/dev/null || \
        systemctl is-active --quiet exim 2>/dev/null; then
            
            echo "[확인] Exim 사용 중 - 버전 점검 필요"
            exim -bV 2>/dev/null | head -1 || exim4 -bV 2>/dev/null | head -1 || echo "버전 확인 실패"
            echo "※ 최신 버전으로 업데이트 권장: sudo apt update && sudo apt upgrade exim4"
        else
            
            EXIM_PIDS=$(ps -ef | grep exim | grep -v grep | awk '{print $2}')
            if [ -n "$EXIM_PIDS" ]; then
                for pid in $EXIM_PIDS; do
                    kill -9 "$pid" 2>/dev/null
                done
                ((FIX_COUNT++))
            fi
            systemctl disable exim 2>/dev/null
            systemctl disable exim4 2>/dev/null
        fi
    fi


    if [ $FIX_COUNT -eq 0 ]; then
        
        if ! systemctl is-active --quiet sendmail 2>/dev/null && \
        ! systemctl is-active --quiet postfix 2>/dev/null && \
        ! systemctl is-active --quiet exim 2>/dev/null && \
        ! systemctl is-active --quiet exim4 2>/dev/null; then
            echo "[양호] 메일 서비스 미사용"
        fi
    else
        echo "[완료] U-45 조치 완료 (중지: ${FIX_COUNT}개 서비스)"
    fi
}

U_46() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    FIX_COUNT=0
    MAIL_SERVER=""

    if systemctl is-active --quiet sendmail 2>/dev/null; then
        MAIL_SERVER="sendmail"
    elif systemctl is-active --quiet postfix 2>/dev/null; then
        MAIL_SERVER="postfix"
    elif systemctl is-active --quiet exim4 2>/dev/null; then
        MAIL_SERVER="exim4"
    elif systemctl is-active --quiet exim 2>/dev/null; then
        MAIL_SERVER="exim"
    fi

    if [ -z "$MAIL_SERVER" ]; then
        echo "[양호] 메일 서비스 사용 안 함"
        exit 0
    fi

    if [ "$MAIL_SERVER" = "sendmail" ]; then
        SENDMAIL_CF="/etc/mail/sendmail.cf"
        
        if [ -f "$SENDMAIL_CF" ]; then
            
            NEED_FIX=0
           
            if ! grep -q "^O PrivacyOptions=.*restrictqrun" "$SENDMAIL_CF"; then
                NEED_FIX=1
            fi
            
            if [ $NEED_FIX -eq 1 ]; then
             
                cp "$SENDMAIL_CF" "${SENDMAIL_CF}.bak.$(date +%Y%m%d%H%M%S)"
                
              
                if grep -q "^O PrivacyOptions=" "$SENDMAIL_CF"; then
                  
                    sed -i '/^O PrivacyOptions=/ { /restrictqrun/!s/$/, restrictqrun/ }' "$SENDMAIL_CF"
                else
                    echo "O PrivacyOptions=authwarnings, novrfy, noexpn, restrictqrun" >> "$SENDMAIL_CF"
                fi
                
                ((FIX_COUNT++))
                
                systemctl restart sendmail 2>/dev/null
            fi
        fi
    fi


    if [ "$MAIL_SERVER" = "postfix" ]; then
        POSTSUPER="/usr/sbin/postsuper"
        
        if [ -f "$POSTSUPER" ]; then
         
            PERM=$(stat -c '%a' "$POSTSUPER" 2>/dev/null)
            OTHER_PERM=$((PERM % 10))
           
            if [ $((OTHER_PERM & 1)) -ne 0 ]; then
               
                chmod o-x "$POSTSUPER" 2>/dev/null
                ((FIX_COUNT++))
            fi
        fi
    fi



    if [ "$MAIL_SERVER" = "exim" ] || [ "$MAIL_SERVER" = "exim4" ]; then
        EXIQGREP="/usr/sbin/exiqgrep"
        
        if [ -f "$EXIQGREP" ]; then
            
            PERM=$(stat -c '%a' "$EXIQGREP" 2>/dev/null)
            OTHER_PERM=$((PERM % 10))
           
            if [ $((OTHER_PERM & 1)) -ne 0 ]; then
                
                chmod o-x "$EXIQGREP" 2>/dev/null
                ((FIX_COUNT++))
            fi
        fi
    fi

    if [ $FIX_COUNT -eq 0 ]; then
        echo "[양호] 조치 불필요"
    else
        echo "[완료] U-46 조치 완료 ($MAIL_SERVER 수정: ${FIX_COUNT}개)"
    fi
}

U_48() {
   
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    FIX_COUNT=0
    MAIL_SERVER=""

    if systemctl is-active --quiet sendmail 2>/dev/null; then
        MAIL_SERVER="sendmail"
    elif systemctl is-active --quiet postfix 2>/dev/null; then
        MAIL_SERVER="postfix"
    elif systemctl is-active --quiet exim4 2>/dev/null; then
        MAIL_SERVER="exim4"
    elif systemctl is-active --quiet exim 2>/dev/null; then
        MAIL_SERVER="exim"
    fi

    if [ -z "$MAIL_SERVER" ]; then
        echo "[양호] SMTP 서비스 사용 안 함"
        exit 0
    fi


    if [ "$MAIL_SERVER" = "sendmail" ]; then
        SENDMAIL_CF="/etc/mail/sendmail.cf"
        
        if [ -f "$SENDMAIL_CF" ]; then
          
            
            NEED_FIX=0
            
            if ! grep -q "^O PrivacyOptions=.*noexpn" "$SENDMAIL_CF" || \
            ! grep -q "^O PrivacyOptions=.*novrfy" "$SENDMAIL_CF"; then
                NEED_FIX=1
            fi
            
            if [ $NEED_FIX -eq 1 ]; then
            
                cp "$SENDMAIL_CF" "${SENDMAIL_CF}.bak.$(date +%Y%m%d%H%M%S)"
               
                if grep -q "^O PrivacyOptions=" "$SENDMAIL_CF"; then
                    sed -i 's/^O PrivacyOptions=.*/O PrivacyOptions=authwarnings, novrfy, noexpn, restrictqrun/' "$SENDMAIL_CF"
                else
                    echo "O PrivacyOptions=authwarnings, novrfy, noexpn, restrictqrun" >> "$SENDMAIL_CF"
                fi
                
                ((FIX_COUNT++))
             
                systemctl restart sendmail 2>/dev/null
            fi
        fi
    fi

 
    if [ "$MAIL_SERVER" = "postfix" ]; then
        POSTFIX_MAIN="/etc/postfix/main.cf"
        
        if [ -f "$POSTFIX_MAIN" ]; then
            
            NEED_FIX=0
           
            if ! grep -q "^disable_vrfy_command *= *yes" "$POSTFIX_MAIN"; then
                NEED_FIX=1
            fi
            
            if [ $NEED_FIX -eq 1 ]; then
                
                cp "$POSTFIX_MAIN" "${POSTFIX_MAIN}.bak.$(date +%Y%m%d%H%M%S)"
                
                if grep -q "^disable_vrfy_command" "$POSTFIX_MAIN"; then
                    sed -i 's/^disable_vrfy_command.*/disable_vrfy_command = yes/' "$POSTFIX_MAIN"
                else
                    echo "disable_vrfy_command = yes" >> "$POSTFIX_MAIN"
                fi
                
                ((FIX_COUNT++))
                
                postfix reload 2>/dev/null || systemctl restart postfix 2>/dev/null
            fi
        fi
    fi


    if [ "$MAIL_SERVER" = "exim" ] || [ "$MAIL_SERVER" = "exim4" ]; then
        EXIM_CONF=""
        
        if [ -f "/etc/exim4/exim4.conf.template" ]; then
            EXIM_CONF="/etc/exim4/exim4.conf.template"
        elif [ -f "/etc/exim4/exim4.conf" ]; then
            EXIM_CONF="/etc/exim4/exim4.conf"
        elif [ -f "/etc/exim/exim.conf" ]; then
            EXIM_CONF="/etc/exim/exim.conf"
        fi
        
        if [ -n "$EXIM_CONF" ]; then
       
            NEED_FIX=0
         
            if grep -q "^acl_smtp_vrfy.*accept" "$EXIM_CONF" || \
            grep -q "^acl_smtp_expn.*accept" "$EXIM_CONF"; then
                NEED_FIX=1
            fi
            
            if [ $NEED_FIX -eq 1 ]; then
             
                cp "$EXIM_CONF" "${EXIM_CONF}.bak.$(date +%Y%m%d%H%M%S)"
               
                sed -i 's/^acl_smtp_vrfy.*accept/#&/' "$EXIM_CONF"
                sed -i 's/^acl_smtp_expn.*accept/#&/' "$EXIM_CONF"
                
                ((FIX_COUNT++))
                
                if [ "$MAIL_SERVER" = "exim4" ]; then
                    update-exim4.conf 2>/dev/null
                    systemctl restart exim4 2>/dev/null
                else
                    systemctl restart exim 2>/dev/null
                fi
            fi
        fi
    fi

    if [ $FIX_COUNT -eq 0 ]; then
        echo "[양호] 조치 불필요"
    else
        echo "[완료] U-48 조치 완료 ($MAIL_SERVER 수정: ${FIX_COUNT}개)"
    fi
}

U_49() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        return 1
    fi

    local FIX_COUNT=0
    local DNS_STATUS
    local INSTALLED_VERSION=""
    local LATEST_VERSION=""
    local VERSION_STATUS="알 수 없음"

  
    DNS_STATUS=$(systemctl list-units --type=service 2>/dev/null | grep named)

    if [ -z "$DNS_STATUS" ] && ! systemctl is-active --quiet bind9 2>/dev/null; then
        echo "✓ U-49 이미 양호 (DNS 서비스 사용 안 함)"
        return 0
    fi

    systemctl stop named >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        ((FIX_COUNT++))
    fi
    systemctl disable named >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        ((FIX_COUNT++))
    fi

 
    if systemctl is-active --quiet bind9 2>/dev/null; then
        systemctl stop bind9 >/dev/null 2>&1
        systemctl disable bind9 >/dev/null 2>&1
        ((FIX_COUNT++))
    fi

    if command -v dpkg >/dev/null 2>&1; then
        INSTALLED_VERSION=$(dpkg -l | grep "^ii.*bind9" | awk '{print $3}' | head -n 1)
    fi

    if command -v apt-cache >/dev/null 2>&1; then
   
        if apt-cache policy bind9 >/dev/null 2>&1; then
            LATEST_VERSION=$(apt-cache policy bind9 2>/dev/null | grep "Candidate:" | awk '{print $2}')
        fi
    fi

    if [ -n "$INSTALLED_VERSION" ] && [ -n "$LATEST_VERSION" ]; then
        if [ "$INSTALLED_VERSION" = "$LATEST_VERSION" ]; then
            VERSION_STATUS="최신 버전"
        else
            VERSION_STATUS="업데이트 필요"
        fi
    fi

   
    if [ $FIX_COUNT -gt 0 ]; then
        echo "✓ U-49 조치 완료 (DNS 서비스 비활성화: ${FIX_COUNT}건)"
    else
       
        echo "✓ U-49 점검 완료 (DNS 서비스 관련)"
    fi

    if [ -n "$INSTALLED_VERSION" ]; then
        echo "   [INFO] BIND 버전 비교"
        echo "     - 현재 버전: ${INSTALLED_VERSION:-미설치}"
        echo "     - 최신 버전: ${LATEST_VERSION:-확인 불가}"
        echo "     - 상태: $VERSION_STATUS"

        if [ "$VERSION_STATUS" = "업데이트 필요" ]; then
            echo "     - [권장] 최신 버전 업데이트: sudo apt update && sudo apt upgrade bind9"
        fi
    fi
}

U_52() {
   
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    TELNET_PORT=23

    UNIT_SOCKET="telnet.socket"
    UNIT_SERVICE_TMPL="telnet@.service"
    UNIT_FILE_SOCKET="/etc/systemd/system/${UNIT_SOCKET}"
    UNIT_FILE_SERVICE="/etc/systemd/system/${UNIT_SERVICE_TMPL}"

    NEED_RELOAD=0

    if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx "${UNIT_SOCKET}"; then
        systemctl disable --now "${UNIT_SOCKET}" >/dev/null 2>&1 || true
        systemctl reset-failed "${UNIT_SOCKET}" >/dev/null 2>&1 || true
    fi

    if [ -f "${UNIT_FILE_SOCKET}" ]; then
        rm -f "${UNIT_FILE_SOCKET}" >/dev/null 2>&1 && NEED_RELOAD=1
    fi

    if [ -f "${UNIT_FILE_SERVICE}" ]; then
        rm -f "${UNIT_FILE_SERVICE}" >/dev/null 2>&1 && NEED_RELOAD=1
    fi

    if [ "${NEED_RELOAD}" -eq 1 ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

   
    systemctl disable --now inetutils-inetd >/dev/null 2>&1 || true
    systemctl disable --now openbsd-inetd  >/dev/null 2>&1 || true
    systemctl disable --now xinetd         >/dev/null 2>&1 || true

    if [ -f /etc/inetd.conf ]; then
        if grep -qE '^[[:space:]]*telnet[[:space:]]' /etc/inetd.conf; then
            sed -i 's/^[[:space:]]*\(telnet[[:space:]].*\)$/#\1/' /etc/inetd.conf >/dev/null 2>&1 || true
        fi
    fi

    if [ -f /etc/xinetd.d/telnet ]; then
   
        sed -i 's/^[[:space:]]*disable[[:space:]]*=[[:space:]]*no[[:space:]]*$/\tdisable\t\t= yes/' /etc/xinetd.d/telnet >/dev/null 2>&1 || true
    fi

    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(:${TELNET_PORT}$|\]:${TELNET_PORT}$)"; then
        echo "[실패] U-52 조치 실패 (23/tcp 여전히 LISTEN)"
        exit 1
    fi

    echo "[완료] U-52 조치 완료 (Telnet 비활성화)"
}

U_58() {
    
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    FIX_COUNT=0


    SNMP_STATUS=$(systemctl list-units --type=service 2>/dev/null | grep snmpd)

    if [ -z "$SNMP_STATUS" ]; then
        echo "[양호] SNMP 서비스 사용 안 함"
        exit 0
    fi

    systemctl stop snmpd &>/dev/null
    if [ $? -eq 0 ]; then
        ((FIX_COUNT++))
    fi

    systemctl disable snmpd &>/dev/null
    if [ $? -eq 0 ]; then
        ((FIX_COUNT++))
    fi

    if [ $FIX_COUNT -eq 0 ]; then
        echo "[양호] 조치 불필요"
    else
        echo "[완료] U-58 조치 완료 (SNMP 비활성화: ${FIX_COUNT}개)"
    fi
}

U_59() {
if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] root 권한 필요"
  exit 1
fi

exec >/dev/null 2>&1

FIX_COUNT=0

DIST="unknown"
if [ -f /etc/os-release ]; then
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) DIST="debian" ;;
    rhel|centos|rocky|almalinux|fedora) DIST="redhat" ;;
    *)
      if echo "${ID_LIKE:-}" | grep -qiE 'rhel|fedora|centos'; then
        DIST="redhat"
      elif echo "${ID_LIKE:-}" | grep -qiE 'debian|ubuntu'; then
        DIST="debian"
      fi
      ;;
  esac
fi

if ! command -v snmpd >/dev/null 2>&1; then

  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y snmpd snmp >/dev/null 2>&1 || true
  fi
fi

if ! command -v snmpd >/dev/null 2>&1; then
  echo "[양호] SNMP 서비스 미설치"
 
  exec >/dev/tty 2>/dev/tty || true
  echo "U-59 조치완료"
  exit 0
fi


if ! systemctl is-active --quiet snmpd 2>/dev/null; then
  systemctl disable --now snmpd >/dev/null 2>&1 || true
  echo "[양호] SNMP 서비스 미사용(비활성)"
  exec >/dev/tty 2>/dev/tty || true
  echo "U-59 조치완료"
  exit 0
fi

ts() { date +"%Y%m%d%H%M%S"; }

SNMPV3_USER="${SNMPV3_USER:-myuser}"
SNMPV3_AUTH_PROTO="${SNMPV3_AUTH_PROTO:-SHA}"
SNMPV3_PRIV_PROTO="${SNMPV3_PRIV_PROTO:-AES}"
SNMP_AGENT_ADDRESS="${SNMP_AGENT_ADDRESS:-udp:127.0.0.1:161,udp6:[::1]:161}"

SNMPV3_AUTH_PASS="${SNMPV3_AUTH_PASS:-}"
SNMPV3_PRIV_PASS="${SNMPV3_PRIV_PASS:-}"

CONF="/etc/snmp/snmpd.conf"
DEFAULTS="/etc/default/snmpd"
STATE="/var/lib/snmp/snmpd.conf"

gen_pass() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24 | tr -d '\n' | tr -d '/+=' | cut -c1-20
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20
  fi
}

SNMPD_RUN_USER="$(systemctl show -p User snmpd 2>/dev/null | awk -F= '{print $2}')"
if [ -z "$SNMPD_RUN_USER" ]; then
  if id Debian-snmp >/dev/null 2>&1; then
    SNMPD_RUN_USER="Debian-snmp"
  else
    SNMPD_RUN_USER="root"
  fi
fi

if [ -z "$SNMPV3_AUTH_PASS" ]; then SNMPV3_AUTH_PASS="$(gen_pass)"; fi
if [ -z "$SNMPV3_PRIV_PASS" ]; then SNMPV3_PRIV_PASS="$(gen_pass)"; fi

BK_DIR="/root/u59_snmp_backup_$(ts)"
mkdir -p "$BK_DIR" >/dev/null 2>&1 || true

[ -f "$CONF" ] && cp -a "$CONF" "$BK_DIR/snmpd.conf.bak" >/dev/null 2>&1 || true
[ -f "$DEFAULTS" ] && cp -a "$DEFAULTS" "$BK_DIR/snmpd.defaults.bak" >/dev/null 2>&1 || true
[ -f "$STATE" ] && cp -a "$STATE" "$BK_DIR/snmpd.state.bak" >/dev/null 2>&1 || true

systemctl stop snmpd >/dev/null 2>&1 || true

while IFS= read -r f; do
  [ -f "$f" ] || continue
  [ "$f" = "$CONF" ] && continue
  mv -f "$f" "$BK_DIR/$(basename "$f").disabled" >/dev/null 2>&1 || true
done < <(grep -RIlE "rocommunity|rwcommunity|com2sec|community" /etc/snmp 2>/dev/null || true)

if ls "$BK_DIR"/*.disabled >/dev/null 2>&1; then
  ((FIX_COUNT++))
fi

cat > "$CONF" <<EOF

agentAddress ${SNMP_AGENT_ADDRESS}

disableAuthorization no

createUser ${SNMPV3_USER} ${SNMPV3_AUTH_PROTO} ${SNMPV3_AUTH_PASS} ${SNMPV3_PRIV_PROTO} ${SNMPV3_PRIV_PASS}

rouser ${SNMPV3_USER} authpriv

sysLocation "unknown"
sysContact  "root"
EOF

chown root:root "$CONF" >/dev/null 2>&1 || true
chmod 600 "$CONF" >/dev/null 2>&1 || true
((FIX_COUNT++))


if [ ! -f "$STATE" ]; then
  install -o "$SNMPD_RUN_USER" -g "$SNMPD_RUN_USER" -m 600 /dev/null "$STATE" >/dev/null 2>&1 || true
else
  chown "$SNMPD_RUN_USER:$SNMPD_RUN_USER" "$STATE" >/dev/null 2>&1 || true
  chmod 600 "$STATE" >/dev/null 2>&1 || true
fi

systemctl enable snmpd >/dev/null 2>&1 || true
systemctl restart snmpd >/dev/null 2>&1 || true

if snmpget -t 1 -r 0 -v2c -c public 127.0.0.1 sysDescr.0 >/dev/null 2>&1; then
  echo "[ERROR] v2c(public) 요청이 아직 성공함 (취약)"
  exit 2
fi

if ! snmpget -t 2 -r 1 -v3 -l authPriv -u "$SNMPV3_USER" \
  -a "$SNMPV3_AUTH_PROTO" -A "$SNMPV3_AUTH_PASS" \
  -x "$SNMPV3_PRIV_PROTO" -X "$SNMPV3_PRIV_PASS" \
  127.0.0.1 sysDescr.0 >/dev/null 2>&1; then
  echo "[ERROR] v3(authPriv) 요청 실패 (설정/서비스 상태 확인 필요)"
  exit 3
fi

CRED_FILE="/root/snmpv3_u59_cred.txt"
cat > "$CRED_FILE" <<EOF
U-59 SNMPv3 (authPriv)
user: $SNMPV3_USER
auth: $SNMPV3_AUTH_PROTO / $SNMPV3_AUTH_PASS
priv: $SNMPV3_PRIV_PROTO / $SNMPV3_PRIV_PASS
agentAddress: $SNMP_AGENT_ADDRESS

test(v3):
snmpget -v3 -l authPriv -u $SNMPV3_USER -a $SNMPV3_AUTH_PROTO -A '$SNMPV3_AUTH_PASS' -x $SNMPV3_PRIV_PROTO -X '$SNMPV3_PRIV_PASS' 127.0.0.1 sysDescr.0

test(v2c should fail):
snmpget -v2c -c public 127.0.0.1 sysDescr.0
EOF
chmod 600 "$CRED_FILE" >/dev/null 2>&1 || true

if [ "$FIX_COUNT" -eq 0 ]; then
  echo "[양호] 조치 불필요"
else
  echo "[완료] U-59 조치 완료 (수정: ${FIX_COUNT}개)"
  echo "[INFO] SNMPv3 자격 정보 저장: $CRED_FILE"
fi

exec >/dev/tty 2>/dev/tty || true
echo "U-59 조치완료"
}

U_60() {
if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] root 권한 필요"
  exit 1
fi

FIX_COUNT=0

DIST="unknown"
if [ -f /etc/os-release ]; then
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian) DIST="debian" ;;
    rhel|centos|rocky|almalinux|fedora) DIST="redhat" ;;
    *)
      if echo "${ID_LIKE:-}" | grep -qiE 'rhel|fedora|centos'; then
        DIST="redhat"
      elif echo "${ID_LIKE:-}" | grep -qiE 'debian|ubuntu'; then
        DIST="debian"
      fi
      ;;
  esac
fi

if ! command -v snmpd >/dev/null 2>&1; then
  echo "[양호] SNMP 서비스 미설치"
  exit 0
fi

if ! systemctl is-active --quiet snmpd 2>/dev/null; then
  systemctl disable --now snmpd >/dev/null 2>&1 || true
  echo "[양호] SNMP 서비스 미사용(비활성)"
  exit 0
fi

SNMPD_CONF="/etc/snmp/snmpd.conf"
CONF_D="/etc/snmp/snmpd.conf.d"

CONF_FILES=()
[ -f "$SNMPD_CONF" ] && CONF_FILES+=("$SNMPD_CONF")
if [ -d "$CONF_D" ]; then
  while IFS= read -r -d '' f; do
    CONF_FILES+=("$f")
  done < <(find "$CONF_D" -maxdepth 1 -type f -name "*.conf" -print0 2>/dev/null)
fi

gen_comm() {
  local c has_alpha has_digit
  while :; do
    c="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)"
    [ ${#c} -ge 10 ] || continue
    echo "$c" | grep -qE '[A-Za-z]' && has_alpha=1 || has_alpha=0
    echo "$c" | grep -qE '[0-9]' && has_digit=1 || has_digit=0
    if [ "$has_alpha" -eq 1 ] && [ "$has_digit" -eq 1 ] && [ "$c" != "public" ] && [ "$c" != "private" ]; then
      echo "$c"
      return 0
    fi
  done
}

is_good_comm() {
  local c="$1"

  c="$(echo "$c" | tr -d '[:space:]')"
  [ -n "$c" ] || return 1

  if [ "$c" = "public" ] || [ "$c" = "private" ]; then
    return 1
  fi

  if echo "$c" | grep -qE '[A-Za-z]' && echo "$c" | grep -qE '[0-9]' && [ "${#c}" -ge 10 ]; then
    return 0
  fi

  if echo "$c" | grep -qE '[A-Za-z]' && echo "$c" | grep -qE '[0-9]' && echo "$c" | grep -qE '[^A-Za-z0-9]' && [ "${#c}" -ge 8 ]; then
    return 0
  fi

  return 1
}

backup_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  cp "$f" "${f}.bak.$(date +%Y%m%d%H%M%S)" >/dev/null 2>&1 || true
}

get_first_comm() {
  local f="$1"
  [ -f "$f" ] || return 1
  awk '
    function ltrim(s){ sub(/^[ \t\r\n]+/, "", s); return s }
    {
      line=ltrim($0)
      if (line ~ /^#/) next
      split(line,a,/[\t ]+/)
      if (a[1] ~ /^(rocommunity6?|rwcommunity6?)$/ && a[2] != "") { print a[2]; exit }
      if (a[1] ~ /^(com2sec6?)$/ && a[4] != "") { print a[4]; exit }
    }
  ' "$f" 2>/dev/null
}

NEED_FIX=0
EXISTING_COMM=""

for f in "${CONF_FILES[@]}"; do
  c="$(get_first_comm "$f")"
  if [ -n "$c" ]; then
    EXISTING_COMM="$c"
    if ! is_good_comm "$c"; then
      NEED_FIX=1
      break
    fi
  fi
done

if [ -z "$EXISTING_COMM" ]; then
  echo "[양호] SNMP Community String 설정 없음(SNMPv1/v2c 미사용)"
  exit 0
fi

if [ "$NEED_FIX" -eq 0 ]; then
  echo "[양호] SNMP Community String 이미 양호 기준 충족"
  exit 0
fi

NEW_COMM="$(gen_comm)"

edit_file() {
  local f="$1"
  [ -f "$f" ] || return 0

  local changed=0
  local tmp
  tmp="$(mktemp)"

  awk -v NEW="$NEW_COMM" '
    function ltrim(s){ sub(/^[ \t\r\n]+/, "", s); return s }
    {
      orig=$0
      line=ltrim($0)

      if (line ~ /^#/) { print orig; next }

      split(line,a,/[\t ]+/)

      if (a[1] ~ /^(rocommunity6?|rwcommunity6?)$/ && a[2] != "") {
       
        $0=line
        $2=NEW
        print $0
        next
      }

      if (a[1] ~ /^(com2sec6?)$/ && a[4] != "") {
        $0=line
        $4=NEW
        print $0
        next
      }

      print orig
    }
  ' "$f" > "$tmp" 2>/dev/null

  if ! cmp -s "$f" "$tmp" 2>/dev/null; then
    backup_file "$f"
    cat "$tmp" > "$f"
    changed=1
  fi

  rm -f "$tmp" >/dev/null 2>&1 || true

  if [ "$changed" -eq 1 ]; then
    ((FIX_COUNT++))
  fi
}

for f in "${CONF_FILES[@]}"; do
  edit_file "$f"
done

systemctl restart snmpd >/dev/null 2>&1 || true

CRED_FILE="/root/snmp_community_u60.txt"
cat > "$CRED_FILE" <<EOF
U-60 SNMP Community String (v1/v2c)
community: $NEW_COMM

test(v2c):
snmpget -v2c -c $NEW_COMM 127.0.0.1 1.3.6.1.2.1.1.1.0
EOF
chmod 600 "$CRED_FILE" >/dev/null 2>&1 || true

if [ $FIX_COUNT -eq 0 ]; then
  echo "[양호] 조치 불필요"
else
  echo "[완료] U-60 조치 완료 (수정: ${FIX_COUNT}개)"
  echo "[INFO] 변경된 Community 저장: $CRED_FILE"
fi
}

U_62() {
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] root 권한 필요"
    exit 1
fi

FIX_COUNT=0

WARNING_MSG="************************************************************************
*                          WARNING                                   *
* Unauthorized access to this system is forbidden and will be        *
* prosecuted by law. By accessing this system, you agree that        *
* your actions may be monitored if unauthorized usage is suspected.  *
************************************************************************"


if [ ! -f "/etc/motd" ] || ! grep -q "WARNING" "/etc/motd" 2>/dev/null; then
    echo "$WARNING_MSG" > /etc/motd
    ((FIX_COUNT++))
fi

if [ ! -f "/etc/issue" ] || ! grep -q "WARNING" "/etc/issue" 2>/dev/null; then
    echo "$WARNING_MSG" > /etc/issue
    ((FIX_COUNT++))
fi

if [ ! -f "/etc/issue.net" ] || ! grep -q "WARNING" "/etc/issue.net" 2>/dev/null; then
    echo "$WARNING_MSG" > /etc/issue.net
    ((FIX_COUNT++))
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
  
    if ! grep -q "^Banner /etc/issue.net" "$SSHD_CONFIG" 2>/dev/null; then
      
        sed -i 's/^Banner/#Banner/' "$SSHD_CONFIG"
     
        echo "Banner /etc/issue.net" >> "$SSHD_CONFIG"
        ((FIX_COUNT++))
        
      
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    fi
fi

if systemctl is-active --quiet sendmail 2>/dev/null; then
    SENDMAIL_CF="/etc/mail/sendmail.cf"
    if [ -f "$SENDMAIL_CF" ]; then
        if ! grep -q "SmtpGreetingMessage=.*WARNING" "$SENDMAIL_CF" 2>/dev/null; then
           
            if grep -q "^O SmtpGreetingMessage=" "$SENDMAIL_CF"; then
                sed -i 's/^O SmtpGreetingMessage=.*/O SmtpGreetingMessage=WARNING: Authorized use only/' "$SENDMAIL_CF"
            else
                echo "O SmtpGreetingMessage=WARNING: Authorized use only" >> "$SENDMAIL_CF"
            fi
            ((FIX_COUNT++))
            systemctl restart sendmail 2>/dev/null
        fi
    fi
fi

if systemctl is-active --quiet postfix 2>/dev/null; then
    POSTFIX_MAIN="/etc/postfix/main.cf"
    if [ -f "$POSTFIX_MAIN" ]; then
        if ! grep -q "smtpd_banner.*WARNING" "$POSTFIX_MAIN" 2>/dev/null; then
       
            if grep -q "^smtpd_banner" "$POSTFIX_MAIN"; then
                sed -i 's/^smtpd_banner.*/smtpd_banner = WARNING: Authorized use only/' "$POSTFIX_MAIN"
            else
                echo "smtpd_banner = WARNING: Authorized use only" >> "$POSTFIX_MAIN"
            fi
            ((FIX_COUNT++))
            systemctl restart postfix 2>/dev/null
        fi
    fi
fi

if systemctl is-active --quiet exim 2>/dev/null || systemctl is-active --quiet exim4 2>/dev/null; then
    EXIM_CONF=""
    if [ -f "/etc/exim/exim.conf" ]; then
        EXIM_CONF="/etc/exim/exim.conf"
    elif [ -f "/etc/exim4/exim4.conf" ]; then
        EXIM_CONF="/etc/exim4/exim4.conf"
    fi
    
    if [ -n "$EXIM_CONF" ]; then
        if ! grep -q "smtp_banner.*WARNING" "$EXIM_CONF" 2>/dev/null; then
            if grep -q "^smtp_banner" "$EXIM_CONF"; then
                sed -i 's/^smtp_banner.*/smtp_banner = WARNING: Authorized use only/' "$EXIM_CONF"
            else
                echo "smtp_banner = WARNING: Authorized use only" >> "$EXIM_CONF"
            fi
            ((FIX_COUNT++))
            systemctl restart exim 2>/dev/null || systemctl restart exim4 2>/dev/null
        fi
    fi
fi

if systemctl is-active --quiet vsftpd 2>/dev/null; then
    VSFTPD_CONF=""
    if [ -f "/etc/vsftpd.conf" ]; then
        VSFTPD_CONF="/etc/vsftpd.conf"
    elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
        VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
    fi
    
    if [ -n "$VSFTPD_CONF" ]; then
        if ! grep -q "ftpd_banner.*WARNING" "$VSFTPD_CONF" 2>/dev/null; then
            if grep -q "^ftpd_banner" "$VSFTPD_CONF"; then
                sed -i 's/^ftpd_banner.*/ftpd_banner=WARNING: Authorized use only/' "$VSFTPD_CONF"
            else
                echo "ftpd_banner=WARNING: Authorized use only" >> "$VSFTPD_CONF"
            fi
            ((FIX_COUNT++))
            systemctl restart vsftpd 2>/dev/null
        fi
    fi
fi


if systemctl is-active --quiet proftpd 2>/dev/null; then
    PROFTPD_CONF=""
    if [ -f "/etc/proftpd.conf" ]; then
        PROFTPD_CONF="/etc/proftpd.conf"
    elif [ -f "/etc/proftpd/proftpd.conf" ]; then
        PROFTPD_CONF="/etc/proftpd/proftpd.conf"
    fi
    
    if [ -n "$PROFTPD_CONF" ]; then
     
        WELCOME_MSG="/etc/proftpd/welcome.msg"
        
        if ! grep -q "^DisplayLogin" "$PROFTPD_CONF"; then
            echo "DisplayLogin $WELCOME_MSG" >> "$PROFTPD_CONF"
        fi
     
        echo "$WARNING_MSG" > "$WELCOME_MSG"
        ((FIX_COUNT++))
        systemctl restart proftpd 2>/dev/null
    fi
fi


if systemctl is-active --quiet named 2>/dev/null || systemctl is-active --quiet bind9 2>/dev/null; then
    NAMED_CONF=""
    if [ -f "/etc/named.conf" ]; then
        NAMED_CONF="/etc/named.conf"
    elif [ -f "/etc/bind/named.conf.options" ]; then
        NAMED_CONF="/etc/bind/named.conf.options"
    fi
    
    if [ -n "$NAMED_CONF" ]; then
        if ! grep -q "version.*WARNING" "$NAMED_CONF" 2>/dev/null; then
          
            if grep -q "version" "$NAMED_CONF"; then
                sed -i 's/.*version.*/    version "WARNING: Authorized use only";/' "$NAMED_CONF"
            else
               
                if grep -q "options {" "$NAMED_CONF"; then
                    sed -i '/options {/a\    version "WARNING: Authorized use only";' "$NAMED_CONF"
                else
                    echo 'options { version "WARNING: Authorized use only"; };' >> "$NAMED_CONF"
                fi
            fi
            ((FIX_COUNT++))
            systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null
        fi
    fi
fi

if [ $FIX_COUNT -eq 0 ]; then
    echo "[양호] 조치 불필요"
else
    echo "[완료] U-62 조치 완료 (수정: ${FIX_COUNT}개)"
fi
}

U_63() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    SUDOERS_FILE="/etc/sudoers"

    if [ ! -f "$SUDOERS_FILE" ]; then
        echo "[ERROR] $SUDOERS_FILE 파일 없음"
        exit 1
    fi

    CURRENT_OWNER=$(stat -c '%U' "$SUDOERS_FILE" 2>/dev/null)
    CURRENT_PERM=$(stat -c '%a' "$SUDOERS_FILE" 2>/dev/null)

    NEED_FIX=0

    if [ "$CURRENT_OWNER" != "root" ]; then
        NEED_FIX=1
    fi

    if [ "$CURRENT_PERM" != "640" ]; then
        NEED_FIX=1
    fi

    if [ $NEED_FIX -eq 1 ]; then
        chown root "$SUDOERS_FILE" 2>/dev/null && chmod 640 "$SUDOERS_FILE" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "[완료] U-63 조치 완료 (소유자: root, 권한: 640)"
        else
            echo "[실패] 조치 실패"
            exit 1
        fi
    else
        echo "[양호] 조치 불필요"
    fi
}

U_64() {
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] root 권한 필요"
    exit 1
fi

REPORT_FILE="/root/os_kernel_version_report.txt"

echo "[INFO] 최신 패키지 정보를 가져오는 중..."
apt-get update -qq

source /etc/os-release
OS_NAME=$NAME
OS_VERSION=$VERSION_ID
OS_CODENAME=$VERSION_CODENAME
CURRENT_KERNEL=$(uname -r)

LATEST_KERNEL_CANDIDATE=$(apt-cache policy linux-image-generic | grep "Candidate:" | awk '{print $2}')

SECURITY_UPDATES=$(apt list --upgradable 2>/dev/null | grep -i "security" | wc -l)
TOTAL_UPDATES=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)

EOL_STATUS="정상 (지원 중)"
EOL_DATE="확인 필요"

case $OS_VERSION in
    "24.04") EOL_DATE="2029-04 (Standard Support)" ;;
    "22.04") EOL_DATE="2027-04 (Standard Support)" ;;
    "20.04") 
        EOL_DATE="2025-04 (Standard Support 종료됨)"
        EOL_STATUS="주의 (LTS Maintenance 모드)" 
        ;;
    "18.04"|"16.04") 
        EOL_DATE="지원 종료됨 (EOL)"
        EOL_STATUS="취약 (업그레이드 필수)" 
        ;;
    *) EOL_DATE="N/A (커뮤니티 확인 필요)" ;;
esac

cat > "$REPORT_FILE" << EOF
================================================
OS 및 Kernel 버전 상세 비교 보고서
================================================
점검 일시: $(date '+%Y-%m-%d %H:%M:%S')

[1. OS 배포판 정보]
- 운영체제: $OS_NAME
- 현재 버전: $OS_VERSION ($OS_CODENAME)
- 지원 상태: $EOL_STATUS
- 지원 종료 예정일: $EOL_DATE

[2. 커널(Kernel) 정보]
- 현재 실행 중인 커널: $CURRENT_KERNEL
- 레포지토리 최신 커널: ${LATEST_KERNEL_CANDIDATE:-"정보 없음"}
※ 현재 커널과 최신 커널 버전이 다르면 재부팅이 필요할 수 있습니다.

[3. 패키지 업데이트 현황]
- 총 업데이트 가능 항목: $TOTAL_UPDATES 개
- 그 중 보안 패치 항목: $SECURITY_UPDATES 개

[4. 권장 조치사항]
1) 보안 패치 적용:
   # sudo apt-get install --only-upgrade \$(apt list --upgradable | grep -i security | cut -d/ -f1)
2) 커널 업데이트 후 재부팅:
   # sudo apt-get update && sudo apt-get dist-upgrade
================================================
EOF

chmod 600 "$REPORT_FILE"

# ============================================
# 결과 요약 화면 출력
# ============================================
echo ""
echo "------------------------------------------------"
printf "%-20s | %-25s\n" "항목" "상태/정보"
echo "------------------------------------------------"
printf "%-20s | %-25s\n" "운영체제" "$OS_NAME $OS_VERSION"
printf "%-20s | %-25s\n" "지원 상태" "$EOL_STATUS"
printf "%-20s | %-25s\n" "현재 커널" "$CURRENT_KERNEL"
printf "%-20s | %-25s\n" "최신 가용 커널" "${LATEST_KERNEL_CANDIDATE:-N/A}"
printf "%-20s | %-25s\n" "보안 업데이트" "$SECURITY_UPDATES 건 대기 중"
echo "------------------------------------------------"
echo "상세 보고서 저장 위치: $REPORT_FILE"

if [[ "$EOL_STATUS" == *"취약"* ]]; then
    echo -e "\033[31m[결과: 취약] OS 버전이 지원 종료되었거나 매우 노후되었습니다.\033[0m"
    exit 1
elif [ "$SECURITY_UPDATES" -gt 0 ]; then
    echo -e "\033[33m[결과: 주의] 미적용 보안 패치가 존재합니다.\033[0m"
else
    echo -e "\033[32m[결과: 양호] 시스템이 최신 보안 상태를 유지하고 있습니다.\033[0m"
fi
}

U_65() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        exit 1
    fi

    U_65_impl() {
  echo "=========================================================="
  echo " [U-65] NTP/시각 동기화 설정 조치 (Ubuntu 24.04)"
  echo "=========================================================="

  if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] root 권한 필요"
    return 0
  fi

  local NTP_SERVERS="0.ko.pool.ntp.org 1.ko.pool.ntp.org 2.ko.pool.ntp.org 3.ko.pool.ntp.org"
  local UPDATED=0

  timedatectl_ntp() { timedatectl show -p NTP --value 2>/dev/null | tr -d '\r'; }
  timedatectl_sync() { timedatectl show -p NTPSynchronized --value 2>/dev/null | tr -d '\r'; }

  already_good() {
    [ "$(timedatectl_ntp)" = "yes" ] && [ "$(timedatectl_sync)" = "yes" ]
  }

  is_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

  if already_good; then
    echo "    [완료] 이미 NTP=yes, NTPSynchronized=yes 상태"
    echo "=========================================================="
    return 0
  fi

  local DROPIN_DIR="/etc/systemd/timesyncd.conf.d"
  local DROPIN_FILE="${DROPIN_DIR}/99-u65.conf"

  mkdir -p "$DROPIN_DIR" 2>/dev/null
  if [ -f "$DROPIN_FILE" ]; then
    cp -p "$DROPIN_FILE" "${DROPIN_FILE}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null
  fi

  cat > "$DROPIN_FILE" <<EOF
[Time]
NTP=${NTP_SERVERS}
FallbackNTP=pool.ntp.org
EOF

  [ -f "$DROPIN_FILE" ] && UPDATED=1

  if is_active chrony; then
    systemctl stop chrony 2>/dev/null
    systemctl disable chrony 2>/dev/null
  fi
  if is_active ntp; then
    systemctl stop ntp 2>/dev/null
    systemctl disable ntp 2>/dev/null
  fi

  timedatectl set-ntp true 2>/dev/null
  systemctl unmask systemd-timesyncd 2>/dev/null
  systemctl enable systemd-timesyncd 2>/dev/null
  systemctl restart systemd-timesyncd 2>/dev/null

  local i
  for i in $(seq 1 90); do
    if already_good; then
      echo "    [완료] timesyncd 동기화 성공 (NTP=yes, NTPSynchronized=yes)"
      echo "=========================================================="
      return 0
    fi
    sleep 1
  done

  timedatectl set-ntp false 2>/dev/null
  systemctl stop systemd-timesyncd 2>/dev/null
  systemctl disable systemd-timesyncd 2>/dev/null

  if ! command -v chronyc >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq chrony >/dev/null 2>&1
  fi

  local CHRONY_CONF="/etc/chrony/chrony.conf"
  if [ ! -f "$CHRONY_CONF" ]; then
    mkdir -p /etc/chrony 2>/dev/null
    touch "$CHRONY_CONF" 2>/dev/null
  fi

  if [ -f "$CHRONY_CONF" ]; then
    cp -p "$CHRONY_CONF" "${CHRONY_CONF}.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null

    sed -i -E 's/^[[:space:]]*(server|pool)[[:space:]]+/#&/I' "$CHRONY_CONF"

    sed -i -E '/^[[:space:]]*#?[[:space:]]*(server|pool)[[:space:]]+([0-9]\.)?ko\.pool\.ntp\.org(\s|$)/Id' "$CHRONY_CONF"
    sed -i -E '/^[[:space:]]*#?[[:space:]]*(server|pool)[[:space:]]+time\.google\.com(\s|$)/Id' "$CHRONY_CONF"

    {
      echo ""
      echo "# U-65 managed servers"
      echo "server 0.ko.pool.ntp.org iburst"
      echo "server 1.ko.pool.ntp.org iburst"
      echo "server 2.ko.pool.ntp.org iburst"
      echo "server 3.ko.pool.ntp.org iburst"
      echo "server time.google.com iburst"
    } >> "$CHRONY_CONF"
  fi

  if is_active ntp; then
    systemctl stop ntp 2>/dev/null
    systemctl disable ntp 2>/dev/null
  fi

  systemctl enable chrony 2>/dev/null
  systemctl restart chrony 2>/dev/null

  if command -v chronyc >/dev/null 2>&1; then
    chronyc -a makestep >/dev/null 2>&1
  fi

  for i in $(seq 1 90); do
    if command -v chronyc >/dev/null 2>&1; then
      if chronyc -n sources 2>/dev/null | grep -qE '^\^\*|^\^\+'; then
        echo "    [완료] chrony 동기화 성공 (chronyc sources에서 동기화 확인)"
        echo "=========================================================="
        return 0
      fi
    fi
    sleep 1
  done

  echo "    [실패] 설정/서비스 적용은 했지만 동기화 성공을 확인하지 못했습니다."
  echo "    [원인] 외부 NTP(UDP 123) 차단, DNS 실패, 사내 NTP 필요, 네트워크 미연결 등의 가능성이 큽니다."
  echo "    [대응] 사내 NTP 서버 IP/도메인을 NTP_SERVERS에 넣고 재실행해야 양호로 바뀝니다."
  echo "=========================================================="
  return 0
    }

    U_65_impl
    return 0
}


U_66() {
    if [ "$EUID" -ne 0 ]; then
        echo "[오류] root 권한으로 실행하세요: sudo $0"
        exit 1
    fi

    FIX_COUNT=0
    NEED_RESTART=0

    if ! command -v rsyslogd >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "✗ U-66 조치 실패 (apt update 실패 - 네트워크/저장소 상태 확인 필요)"
            return 0
        fi

        apt-get install -y rsyslog >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "✗ U-66 조치 실패 (rsyslog 설치 실패)"
            return 0
        fi
        ((FIX_COUNT++))
    fi

    systemctl unmask rsyslog >/dev/null 2>&1 || true

    systemctl enable --now rsyslog >/dev/null 2>&1 || true

    if ! systemctl is-active --quiet rsyslog 2>/dev/null; then
        echo "✗ U-66 조치 실패 (rsyslog 서비스가 실행되지 않음 - systemctl status rsyslog로 원인 확인)"
        return 0
    fi

    local MAIN_CONF="/etc/rsyslog.conf"
    local POLICY_FILE="/etc/rsyslog.d/60-u66-kisa.conf"

    if [ -f "$MAIN_CONF" ]; then
        if ! grep -qE '^[[:space:]]*\$IncludeConfig[[:space:]]+/etc/rsyslog\.d/\*\.conf' "$MAIN_CONF" 2>/dev/null; then
            cp -p "$MAIN_CONF" "${MAIN_CONF}.bak.$(date +%Y%m%d%H%M%S)"
            echo "" >> "$MAIN_CONF"
            echo '$IncludeConfig /etc/rsyslog.d/*.conf' >> "$MAIN_CONF"
            ((FIX_COUNT++))
            NEED_RESTART=1
        fi
    fi

   
    local POLICY_CONTENT
    POLICY_CONTENT="$(cat <<'EOF'

*.info;mail.none;authpriv.none;cron.none    /var/log/messages
auth,authpriv.*                              /var/log/secure
mail.*                                       /var/log/maillog
cron.*                                       /var/log/cron
*.alert                                      /dev/console
*.emerg                                      *
EOF
)"

    if [ -f "$POLICY_FILE" ]; then
        if ! cmp -s <(printf "%s\n" "$POLICY_CONTENT") "$POLICY_FILE" 2>/dev/null; then
            cp -p "$POLICY_FILE" "${POLICY_FILE}.bak.$(date +%Y%m%d%H%M%S)"
            printf "%s\n" "$POLICY_CONTENT" > "$POLICY_FILE"
            chmod 644 "$POLICY_FILE"
            ((FIX_COUNT++))
            NEED_RESTART=1
        fi
    else
        printf "%s\n" "$POLICY_CONTENT" > "$POLICY_FILE"
        chmod 644 "$POLICY_FILE"
        ((FIX_COUNT++))
        NEED_RESTART=1
    fi
    
    local LOG_FILES=(/var/log/messages /var/log/secure /var/log/maillog /var/log/cron)

    for f in "${LOG_FILES[@]}"; do
        if [ ! -f "$f" ]; then
            touch "$f" 2>/dev/null
            ((FIX_COUNT++))
        fi

        if getent group adm >/dev/null 2>&1; then
            chown root:adm "$f" 2>/dev/null || chown root:root "$f" 2>/dev/null
        else
            chown root:root "$f" 2>/dev/null
        fi

        chmod 640 "$f" 2>/dev/null
    done


    if [ "$NEED_RESTART" -eq 1 ]; then
        systemctl restart rsyslog >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "✗ U-66 조치 실패 (rsyslog 재시작 실패)"
            return 0
        fi
    fi

    logger -p user.notice "U-66 test log $(date +%F_%T)" >/dev/null 2>&1 || true
    sleep 1


    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        echo "✓ U-66 조치 완료 (rsyslog 실행 중, 정책 파일: $POLICY_FILE)"
    else
        echo "✗ U-66 조치 실패 (rsyslog 비활성 상태)"
        return 0
    fi
}

U_67() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[ERROR] root 권한 필요"
        exit 1
    fi

    VULN_COUNT=0
    FIX_COUNT=0

    LOG_DIR="/var/log"

    if [ ! -d "$LOG_DIR" ]; then
        echo "[ERROR] $LOG_DIR 디렉터리 없음"
        exit 1
    fi

    while IFS= read -r file; do
      
        if [ -f "$file" ]; then
            NEED_FIX=0
            OWNER=$(stat -c '%U' "$file" 2>/dev/null)
            PERM=$(stat -c '%a' "$file" 2>/dev/null)
           
            if [ "$OWNER" != "root" ] || [ "$PERM" -gt 644 ]; then
                NEED_FIX=1
            fi
            
            if [ $NEED_FIX -eq 1 ]; then
                ((VULN_COUNT++))
                chown root "$file" 2>/dev/null && chmod 644 "$file" 2>/dev/null
                if [ $? -eq 0 ]; then
                    ((FIX_COUNT++))
                fi
            fi
        fi
    done < <(find "$LOG_DIR" -type f 2>/dev/null)

    if [ $VULN_COUNT -eq 0 ]; then
        echo "[양호] 조치 불필요"
    else
        echo "[완료] U-67 조치 완료 (수정: ${FIX_COUNT}개)"
    fi
}

FUNC_NAME=$(echo "$TARGET_CODE" | tr '-' '_')

if declare -f "$FUNC_NAME" > /dev/null; then
    $FUNC_NAME
else
    echo "Invalid Code: $TARGET_CODE"
    exit 1
fi
