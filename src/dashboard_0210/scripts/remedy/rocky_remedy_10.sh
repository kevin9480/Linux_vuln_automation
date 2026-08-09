#!/bin/bash

TARGET_CODE="$1"

U_01() {
    echo "[U-01] root 직접 접속 차단 조치 시작"
    echo "------------------------------------------"

    echo "[Step 1] SSH 서비스 설정 확인 및 조치"
    SSH_CONFIG="/etc/ssh/sshd_config"

    if [ -f "$SSH_CONFIG" ]; then
        if grep -qEi "^PermitRootLogin" "$SSH_CONFIG"; then
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/Ig' "$SSH_CONFIG"
            echo " - $SSH_CONFIG: PermitRootLogin 설정을 no로 변경하였습니다."
        else
            echo "PermitRootLogin no" >> "$SSH_CONFIG"
            echo " - $SSH_CONFIG: PermitRootLogin no 설정을 추가하였습니다."
        fi
    
        systemctl restart sshd 2>/dev/null
        echo " - SSH 서비스를 재시작하였습니다."
    else
        echo " - SSH 설정 파일을 찾을 수 없어 건너뜁니다."
    fi

    echo -e "\n[Step 2] Telnet 서비스 설정 확인 및 조치"
    SECURETTY="/etc/securetty"
    PAM_LOGIN="/etc/pam.d/login"

    if [ -f "$SECURETTY" ]; then
        echo " - $SECURETTY 파일이 존재합니다. Telnet 조치를 수행합니다."

        if [ -f "$PAM_LOGIN" ]; then
            if ! grep -q "pam_securetty.so" "$PAM_LOGIN"; then
                sed -i '/auth/i auth required pam_securetty.so' "$PAM_LOGIN"
                echo " - $PAM_LOGIN: pam_securetty.so 모듈을 추가하였습니다."
            else
                echo " - $PAM_LOGIN: 이미 pam_securetty.so 설정이 존재합니다."
            fi
        fi

        sed -i 's/^\(pts\/.*\)/#\1/g' "$SECURETTY"
        echo " - $SECURETTY: 모든 pts/ 설정값을 주석 처리하였습니다."
    else
        echo " - $SECURETTY 파일이 존재하지 않습니다. SSH 항목만 조치하고 건너뜁니다."
    fi

    echo "------------------------------------------"
    echo "[U-01] 조치 완료"
}

U_02() {
  echo "[시작] 비밀번호 관리 정책 조치를 시작합니다."

  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs

  sed -i '/^minlen/d; /^dcredit/d; /^ucredit/d; /^lcredit/d; /^ocredit/d; /^enforce_for_root/d' /etc/security/pwquality.conf
  cat <<EOF >> /etc/security/pwquality.conf
minlen = 8
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
enforce_for_root
EOF

  sed -i '/^remember/d; /^enforce_for_root/d' /etc/security/pwhistory.conf
  cat <<EOF >> /etc/security/pwhistory.conf
remember = 4
enforce_for_root
EOF

  if grep -q "pam_pwquality.so" /etc/pam.d/system-auth; then
    if ! grep "pam_pwquality.so" /etc/pam.d/system-auth | grep -q "enforce_for_root"; then
      sed -i '/pam_pwquality.so/ s/$/ enforce_for_root/' /etc/pam.d/system-auth
    fi
  fi

  if grep -q "pam_pwhistory.so" /etc/pam.d/system-auth; then
    if ! grep "pam_pwhistory.so" /etc/pam.d/system-auth | grep -q "enforce_for_root"; then
      sed -i '/pam_pwhistory.so/ s/$/ enforce_for_root/' /etc/pam.d/system-auth
    fi
  fi

  echo "[완료] 모든 비밀번호 정책 조치가 완료되었습니다."
}

U_03() {
    echo "=========================================================="
    echo " [U-03] 계정 잠금 임계값 설정 "
    echo "=========================================================="
    local PAM_FILE="/etc/pam.d/system-auth"
    local PASS_FILE="/etc/pam.d/password-auth"

    if command -v authselect &>/dev/null; then
        echo "[1] authselect를 지원하는 시스템입니다. 표준 명령어로 조치합니다."
        authselect enable-feature with-faillock &>> "$LOG_FILE"
        authselect apply-changes &>> "$LOG_FILE"
 
        if [ -f "/etc/security/faillock.conf" ]; then
            sed -i 's/^#* *deny =.*/deny = 10/' /etc/security/faillock.conf
            sed -i 's/^#* *unlock_time =.*/unlock_time = 120/' /etc/security/faillock.conf
            echo "    [완료] authselect 및 faillock.conf 설정 완료" | tee -a "$LOG_FILE"
            return 0
        fi
    fi

    local MODULE_NAME=""
    local MODULE_PATH=""

    for mod in "pam_faillock.so" "pam_tally2.so" "pam_tally.so"; do
        MODULE_PATH=$(find /lib64/security /lib/security -name "$mod" 2>/dev/null | head -n 1)
        if [ -n "$MODULE_PATH" ]; then
            MODULE_NAME=$(echo "$mod" | cut -d. -f1)
            break
        fi
    done

    if [ -z "$MODULE_NAME" ]; then
        echo "    [!] 오류: 사용 가능한 잠금 모듈(faillock, tally2, tally)이 없습니다." | tee -a "$LOG_FILE"
        echo "    [!] 시스템 보호를 위해 조치를 중단합니다."
        return 1
    fi

    echo "[2] 발견된 모듈($MODULE_NAME)에 맞춰 설정을 진행합니다."

    for target in "$PAM_FILE" "$PASS_FILE"; do
        [ ! -f "$target" ] && continue
        cp -p "$target" "${target}.bak_u03"

        sed -i "/pam_faillock.so/d; /pam_tally2.so/d; /pam_tally.so/d" "$target"

        if [ "$MODULE_NAME" == "pam_faillock" ]; then
            sed -i "/^auth.*required.*pam_env.so/a auth        required      pam_faillock.so preauth silent deny=10 unlock_time=120" "$target"
            sed -i "/^auth.*sufficient.*pam_unix.so/a auth        [default=die] pam_faillock.so authfail deny=10 unlock_time=120" "$target"
            sed -i "/^account.*required.*pam_unix.so/i account     required      pam_faillock.so" "$target"
        else
            sed -i "/^auth.*required.*pam_env.so/i auth        required      $MODULE_NAME.so deny=10 unlock_time=120 no_magic_root" "$target"
            sed -i "/^account.*required.*pam_unix.so/i account     required      $MODULE_NAME.so no_magic_root reset" "$target"
        fi
        echo "    [완료] $target 설정 완료" | tee -a "$LOG_FILE"
    done

    echo "=========================================================="
}

U_04() {
  echo "[시작] U-04 비밀번호 파일 보호(Shadow 방식 적용)를 시작합니다."

  local unshadowed_check=$(grep -v '^[^:]*:x:' /etc/passwd)

  if [ -z "$unshadowed_check" ]; then
    echo "[양호] 이미 모든 계정이 Shadow 패스워드(x)를 사용 중입니다."
  else
    echo "[정보] Shadow 패스워드 미사용 계정 발견. 조치를 진행합니다."

    pwconv

    if [ $? -eq 0 ]; then
      echo "[완료] pwconv 조치가 성공적으로 완료되었습니다."
    else
      echo "[오류] pwconv 실행 중 문제가 발생했습니다."
      return 1
    fi
  fi
}

U_05() {
  echo "[시작] U-05 root 이외의 UID '0' 계정 조치를 시작합니다."

  local extra_roots=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

  if [ -z "$extra_roots" ]; then
    echo "[양호] root 이외에 UID가 0인 계정이 없습니다."
    return 0
  fi

  for user in $extra_roots; do
    echo "[경고] UID 0인 계정 발견: $user"

    local new_uid=5000
    while getent passwd $new_uid > /dev/null; do
      ((new_uid++))
    done
    echo "[조치] $user 계정의 UID를 0에서 $new_uid (으)로 직접 변경합니다."

    sed -i "s/^$user:x:0:/$user:x:$new_uid:/" /etc/passwd

    if [ $? -eq 0 ]; then
      echo "[완료] /etc/passwd 파일 수정 성공 ($user -> UID $new_uid)"
    else
      echo "[오류] 파일 수정 실패"
    fi
  done
}

U_06() {
    echo "[U-06] su 명령어 사용 제한 조치 시작"
    echo "------------------------------------------"

    echo "[Step 1] wheel 그룹 확인 및 생성"
    if ! grep -q "^wheel:" /etc/group; then
        groupadd wheel
        echo " - wheel 그룹이 존재하지 않아 생성하였습니다."
    else
        echo " - wheel 그룹이 이미 존재합니다."
    fi

    echo "[Step 2] /usr/bin/su 파일 권한 설정 (4750, group=wheel)"
    SU_PATH="/usr/bin/su"
    if [ -f "$SU_PATH" ]; then
        chgrp wheel "$SU_PATH"
        chmod 4750 "$SU_PATH"
        echo " - $SU_PATH 의 소유 그룹을 wheel로 변경하고 권한을 4750으로 설정했습니다."
    else
        echo " - $SU_PATH 파일을 찾을 수 없습니다."
    fi
    
    PAM_SU="/etc/pam.d/su"
    if [ -f "$PAM_SU" ]; then

        if grep -v '^#' "$PAM_SU" | grep -q "pam_wheel.so"; then
            echo " - $PAM_SU: 이미 설정이 활성화되어 있습니다."

        elif grep -q "^#.*pam_wheel.so" "$PAM_SU"; then
            sed -i 's/^#*\(auth\s\+required\s\+pam_wheel.so\s\+use_uid\)/\1/' "$PAM_SU"
            echo " - $PAM_SU: 기존 설정의 주석을 해제하였습니다."
    
        else
            sed -i '0,/auth/s//auth            required        pam_wheel.so use_uid\n&/' "$PAM_SU"
            echo " - $PAM_SU: 설정을 새로 추가하였습니다."
        fi
    fi
    echo "------------------------------------------"
    echo "[U-06] 조치 완료"
    echo "※ 주의: 이제 wheel 그룹에 속하지 않은 일반 사용자는 su 명령어를 사용할 수 없습니다."
    echo "※ 계정 추가 방법: usermod -G wheel <사용자계정>"
}

U_07() {
  echo "[시작] U-07 불필요한 계정 제거를 시작합니다."

  local TARGET_USERS=("lp" "uucp" "nuucp" "news" "games")

  for user in "${TARGET_USERS[@]}"; do
    if getent passwd "$user" > /dev/null; then
      echo "[조치] 불필요한 계정 발견 및 삭제: $user"
    
      userdel "$user"
      
      if [ $? -eq 0 ]; then
        echo "[완료] $user 계정이 성공적으로 제거되었습니다."
      else
        echo "[오류] $user 계정 제거 실패"
      fi
    else
      echo "[정보] $user 계정이 이미 존재하지 않습니다."
    fi
  done

  echo "--------------------------------------------------"
  echo "[참고] 최근 로그인 기록(last)입니다. 아래 목록 중 모르는 계정이 있다면 수동으로 제거하세요."
  last -n 10
  echo "--------------------------------------------------"
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

U_09() {
  echo "[시작] U-09 계정이 존재하지 않는 GID 조치를 시작합니다."

  local all_gids=$(awk -F: '$3 >= 1000 {print $3}' /etc/group)
  local passwd_gids=$(awk -F: '{print $4}' /etc/passwd | sort -u)
  
  local target_groups=()

  for gid in $all_gids; do
    local gname=$(grep -E ":$gid:" /etc/group | cut -d: -f1)
    local gmembers=$(grep "^$gname:" /etc/group | cut -d: -f4)

    if ! echo "$passwd_gids" | grep -qw "$gid"; then
      if [ -z "$gmembers" ]; then
        target_groups+=("$gname")
      fi
    fi
  done

  if [ ${#target_groups[@]} -eq 0 ]; then
    echo "[양호] 계정이 존재하지 않는 불필요한 그룹이 없습니다."
    return 0
  fi

  for gname in "${target_groups[@]}"; do
    echo "[조치] 불필요한 그룹 발견 및 제거 시도: $gname"
   
    local file_count=$(find / -group "$gname" 2>/dev/null | wc -l)
    if [ "$file_count" -gt 0 ]; then
      echo "[주의] $gname 그룹 소유의 파일이 $file_count 개 존재합니다. 수동 확인을 위해 건너뜁니다."
      continue
    fi

    groupdel "$gname"
    
    if [ $? -eq 0 ]; then
      echo "[완료] $gname 그룹이 성공적으로 제거되었습니다."
    else
      echo "[오류] $gname 그룹 제거 실패"
    fi
  done
}

U_10() {
  echo "[시작] U-10 동일한 UID 금지 조치를 시작합니다."

  local duplicate_uids=$(cut -d: -f3 /etc/passwd | sort | uniq -d)

  if [ -z "$duplicate_uids" ]; then
    echo "[양호] 중복된 UID를 사용하는 계정이 없습니다."
    return 0
  fi

  for uid in $duplicate_uids; do
    local users=($(awk -F: -v u="$uid" '$3 == u {print $1}' /etc/passwd))
    local master_user=${users[0]}
    
    echo "[정보] 중복 UID ($uid) 발견: ${users[*]}"

    for ((i=1; i<${#users[@]}; i++)); do
      local target_user=${users[$i]}
  
      local new_uid=$(awk -F: '{if($3>=1000) print $3}' /etc/passwd | sort -n | tail -1)
      new_uid=$((new_uid + 1))
      [ $new_uid -lt 1000 ] && new_uid=1001

      echo "[조치] $target_user 계정의 UID를 $uid 에서 $new_uid (으)로 변경합니다."
   
      usermod -u "$new_uid" "$target_user"

      if [ $? -eq 0 ]; then
        echo "[완료] $target_user 조치 성공. (기존 파일 권한 확인이 필요합니다.)"
      else
        echo "[오류] $target_user 조치 실패."
      fi
    done
  done
}

U_11() {
  echo "[시작] U-11 사용자 shell 점검 및 조치를 시작합니다."

  local SYSTEM_USERS=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")

  for user in "${SYSTEM_USERS[@]}"; do
    if getent passwd "$user" > /dev/null; then
      local current_shell=$(getent passwd "$user" | cut -d: -f7)
      
      if [[ "$current_shell" != "/sbin/nologin" && "$current_shell" != "/bin/false" ]]; then
        echo "[조치] $user 계정의 쉘을 $current_shell 에서 /sbin/nologin 으로 변경합니다."
        
        usermod -s /sbin/nologin "$user"
        
        if [ $? -eq 0 ]; then
          echo "[완료] $user 계정 조치 성공"
        else
          echo "[오류] $user 계정 조치 실패"
        fi
      else
        echo "[양호] $user 계정은 이미 로그인 불가능한 쉘($current_shell)을 사용 중입니다."
      fi
    fi
  done
}

U_12() {
  echo "[시작] U-12 세션 종료 시간(10분) 설정 조치를 시작합니다."

  if [ -f "/etc/profile" ]; then

    sed -i '/TMOUT/d' /etc/profile
    echo "TMOUT=600" >> /etc/profile
    echo "export TMOUT" >> /etc/profile
    echo "[완료] /etc/profile 에 TMOUT=600 설정을 완료했습니다."
  fi

  if [ -f "/etc/csh.cshrc" ]; then
    
    sed -i '/autologout/d' /etc/csh.cshrc
    echo "set autologout=10" >> /etc/csh.cshrc
    echo "[완료] /etc/csh.cshrc 에 autologout=10 설정을 완료했습니다."
  fi

  echo "[주의] 설정 적용을 위해 현재 세션을 재시작하거나 'source /etc/profile'을 입력하세요."
}

U_13() {
  echo "[시작] U-13 비밀번호 암호화 알고리즘(SHA512) 조치를 시작합니다."

  if [ -f "/etc/login.defs" ]; then
 
    sed -i '/^ENCRYPT_METHOD/d' /etc/login.defs
    echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
    echo "[완료] /etc/login.defs 내 ENCRYPT_METHOD SHA512 설정 완료"
  fi

  local PAM_FILE="/etc/pam.d/system-auth"
  if [ -f "$PAM_FILE" ]; then
  
    if grep -q "pam_unix.so" "$PAM_FILE"; then
      if ! grep "pam_unix.so" "$PAM_FILE" | grep -q "sha512"; then
        sed -i '/pam_unix.so/ s/$/ sha512/' "$PAM_FILE"
      fi
    fi
    echo "[완료] $PAM_FILE 내 pam_unix.so sha512 옵션 적용 완료"
  fi

  echo "[정보] 조치 이후 비밀번호를 변경하는 계정부터 SHA512가 적용됩니다."
}

U_14() {
  echo "[시작] U-14 PATH 환경변수 조치를 시작합니다."

  local TARGET_FILES=("/etc/profile" "/root/.bash_profile" "/root/.bashrc" "/root/.profile")

  for file in "${TARGET_FILES[@]}"; do
    if [ -f "$file" ]; then
      echo "[정보] $file 검사 중..."

      if grep -q "PATH=" "$file"; then
        sed -i 's/:\.:/:/g' "$file"
        sed -i 's/\.:/:/g' "$file"
        sed -i 's/::/:/g' "$file"
        
        
        echo "[완료] $file 조치 완료"
      fi
    fi
  done

  echo "[주의] 현재 세션에 즉시 적용하려면 'source /etc/profile'을 입력하세요."
}

U_15() {
  echo "[시작] U-15 소유자 미존재 파일 및 디렉터리 정비를 시작합니다."

  echo "[정보] 시스템 내 소유자 없는 파일을 검색 중입니다. 잠시만 기다려 주세요..."
  local NO_OWNER_FILES=$(find / \( -nouser -o -nogroup \) -xdev 2>/dev/null)

  if [ -z "$NO_OWNER_FILES" ]; then
    echo "[양호] 소유자나 그룹이 없는 파일이 존재하지 않습니다."
    return 0
  fi

  local LOG_FILE="/root/u15_delete_log.txt"
  echo "--- U-15 삭제 조치 기록 ($(date)) ---" > "$LOG_FILE"

  echo "[경고] 소유자 없는 파일을 삭제합니다."
  for file in $NO_OWNER_FILES; do

    rm -rf "$file" 2>/dev/null
    
    if [ $? -eq 0 ]; then
      echo "[완료] 삭제됨: $file" | tee -a "$LOG_FILE"
    else
      echo "[오류] 삭제 실패: $file (권한 문제 등)" | tee -a "$LOG_FILE"
    fi
  done

  echo "------------------------------------------"
  echo "[종료] 모든 소유자 미존재 파일 삭제 처리가 완료되었습니다."
  echo "[참고] 삭제된 상세 내역은 $LOG_FILE 을 확인하세요."
}

U_16() {
  echo "[시작] U-16 /etc/passwd 파일 소유자 및 권한 조치를 시작합니다."

  local FILE="/etc/passwd"

  if [ -f "$FILE" ]; then

    chown root "$FILE"

    chmod 644 "$FILE"

    echo "[완료] $FILE 의 소유자를 root로, 권한을 644로 변경하였습니다."
    ls -l "$FILE"
  else
    echo "[오류] $FILE 파일을 찾을 수 없습니다."
    return 1
  fi
}

U_17() {
  echo "[시작] U-17 시스템 시작 스크립트 권한 조치를 시작합니다."
  local LOG_FILE="/root/u17_remediation_log.txt"
  echo "--- U-17 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local TARGET_PATHS=(
    "/etc/rc.local"
    "/etc/rc.d/rc.local"
    "/etc/systemd/system"
    "/usr/lib/systemd/system"
  )

  for path in "${TARGET_PATHS[@]}"; do
    if [ -e "$path" ]; then
     
      find -L "$path" -maxdepth 2 -type f 2>/dev/null | while read -r file; do
       
        chown root:root "$file" 2>/dev/null
     
        chmod 755 "$file" 2>/dev/null
  
        if [ -L "$path" ]; then
            chown -h root "$path" 2>/dev/null
        fi

        echo "[완료] $file (소유자: root, 권한: 755 완료)" >> "$LOG_FILE"
      done
    fi
  done

  echo "----------------------------------------------------------"
  echo "[완료] 조치가 마무리되었습니다. 다시 진단해 보세요."
}

U_18() {
  echo "[시작] U-18 /etc/shadow 파일 소유자 및 권한 조치를 시작합니다."

  local FILE="/etc/shadow"

  if [ -f "$FILE" ]; then
    chown root "$FILE"
 
    chmod 400 "$FILE"

    echo "[완료] $FILE 의 소유자를 root로, 권한을 400으로 변경하였습니다."
    ls -l "$FILE"
  else
    echo "[오류] $FILE 파일을 찾을 수 없습니다."
    return 1
  fi
}

U_19() {
  echo "[시작] U-19 /etc/hosts 파일 소유자 및 권한 조치를 시작합니다."

  local FILE="/etc/hosts"

  if [ -f "$FILE" ]; then
 
    chown root "$FILE"
    
    chmod 644 "$FILE"

    echo "[완료] $FILE 의 소유자를 root로, 권한을 644로 변경하였습니다."
    ls -l "$FILE"
  else
    echo "[오류] $FILE 파일을 찾을 수 없습니다."
    return 1
  fi
}

U_20() {
  echo "=========================================================="
  echo " [U-20] (x)inetd 및 systemd 설정 파일 권한 조치"
  echo "=========================================================="
  local LOG_FILE="/root/u20_remediation_log.txt"

  local INET_FILES=("/etc/inetd.conf" "/etc/xinetd.conf")
  for file in "${INET_FILES[@]}"; do
    if [ -f "$file" ]; then
      chown root "$file" && chmod 600 "$file"
      echo "[완료] $file -> root:600" >> "$LOG_FILE"
    fi
  done

  if [ -d "/etc/xinetd.d" ]; then
    chown -R root /etc/xinetd.d/
    find /etc/xinetd.d/ -type f -exec chmod 600 {} \;
    echo "[완료] /etc/xinetd.d/ 내 파일 조치 완료" >> "$LOG_FILE"
  fi

  if [ -f "/etc/systemd/system.conf" ]; then
    chown root /etc/systemd/system.conf && chmod 600 /etc/systemd/system.conf
  fi

  if [ -d "/etc/systemd" ]; then
    chown -R root /etc/systemd/
    find /etc/systemd/ -type f -exec chmod 600 {} \;
    echo "[완료] /etc/systemd/ 내 파일 조치 완료 (600)" >> "$LOG_FILE"
  fi
}

U_21() {
  echo "[시작] U-21 /etc/(r)syslog.conf 파일 소유자 및 권한 조치를 시작합니다."

  local TARGET_FILES=("/etc/syslog.conf" "/etc/rsyslog.conf")
  local file_found=0

  for file in "${TARGET_FILES[@]}"; do
    if [ -f "$file" ]; then
      file_found=1
      echo "[정보] 대상 파일 발견: $file"

      chown root "$file"
      chmod 640 "$file"

      echo "[완료] $file 의 소유자를 root로, 권한을 640으로 변경하였습니다."
      ls -l "$file"
    fi
  done

  if [ $file_found -eq 0 ]; then
    echo "[정보] 시스템에 syslog.conf 또는 rsyslog.conf 파일이 존재하지 않습니다."
  fi
}

U_22() {
  echo "[시작] U-22 /etc/services 파일 소유자 및 권한 조치를 시작합니다."

  local FILE="/etc/services"

  if [ -f "$FILE" ]; then
    chown root "$FILE"

    chmod 644 "$FILE"

    echo "[완료] $FILE 의 소유자를 root로, 권한을 644로 변경하였습니다."
    ls -l "$FILE"
  else
    echo "[오류] $FILE 파일을 찾을 수 없습니다."
    return 1
  fi
}

U_23() {
  echo "[시작] U-23 SUID, SGID 설정 파일 점검을 시작합니다."
  echo "[정보] 시스템 전체를 스캔하므로 시간이 다소 걸릴 수 있습니다..."

  local LOG_FILE="/root/u23_suid_scan_log.txt"
  echo "--- U-23 SUID/SGID Scan Log ($(date)) ---" > "$LOG_FILE"

  find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al {} \; >> "$LOG_FILE" 2>/dev/null

  if [ $? -eq 0 ]; then
    echo "[완료] 점검이 완료되었습니다."
    echo "[확인] 로그 파일($LOG_FILE)을 열어 의심스러운 파일이 있는지 확인하세요."
    echo "--------------------------------------------------"
    echo "  불필요한 파일 발견 시 조치 방법 (예시):"
    echo "  1) 권한만 제거: chmod -s <파일경로>"
    echo "  2) 특정 그룹에만 허용: chgrp <그룹명> <파일경로> && chmod 4750 <파일경로>"
    echo "--------------------------------------------------"
  else
    echo "[오류] 점검 중 문제가 발생했습니다."
  fi
}

U_24() {
  echo "=========================================================="
  echo " [U-24] 환경변수 파일 소유자 및 권한 조치"
  echo "=========================================================="
  local LOG_FILE="/root/u24_remediation_log.txt"
  echo "--- U-24 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local ENV_FILES=(
    ".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" 
    ".bash_login" ".bash_logout" ".exrc" ".vimrc" ".netrc" 
    ".forward" ".rhosts" ".shosts"
  )

  local USER_LIST=$(awk -F: '$7!~/(nologin|false)/ {print $1":"$6}' /etc/passwd)

  for line in $USER_LIST; do
    local user=${line%%:*}
    local home=${line#*:}

    if [ -d "$home" ]; then
      for env_f in "${ENV_FILES[@]}"; do
        local target="$home/$env_f"
        
        if [ -f "$target" ]; then
          local owner=$(stat -c '%U' "$target" 2>/dev/null)
          if [ "$owner" != "root" ] && [ "$owner" != "$user" ]; then
            chown "$user" "$target" 2>/dev/null
            echo "    [소유자 변경] $target : $owner -> $user" >> "$LOG_FILE"
          fi
    
          chmod go-w "$target" 2>/dev/null
    
          if [[ "$env_f" == ".netrc" || "$env_f" == ".rhosts" || "$env_f" == ".shosts" ]]; then
            chmod 600 "$target" 2>/dev/null
          fi
          
          echo "    [완료] $target 조치 완료" >> "$LOG_FILE"
        fi
      done
    fi
  done

  echo "[완료] 가이드라인에 따른 모든 환경변수 파일 조치가 완료되었습니다."
}

U_25() {
  echo "[시작] U-25 World Writable 파일 점검 및 조치를 시작합니다."
  echo "[정보] 시스템 전체를 스캔하므로 시간이 걸릴 수 있습니다..."

  local LOG_FILE="/root/u25_world_writable_log.txt"
  echo "--- U-25 World Writable Remediation Log ($(date)) ---" > "$LOG_FILE"

  if [ -z "$WW_FILES" ]; then
    echo "[양호] World Writable 파일이 존재하지 않습니다."
    return 0
  fi

  echo "[정보] World Writable 파일이 발견되어 타인 쓰기 권한(o-w)을 제거합니다."

  for file in $WW_FILES; do
    ls -l "$file" >> "$LOG_FILE" 2>/dev/null
  
    chmod o-w "$file" 2>/dev/null
    
    if [ $? -eq 0 ]; then
      echo "[완료] $file -> 타인 쓰기 권한 제거됨" >> "$LOG_FILE"
    else
      echo "[오류] $file 조치 실패 (수동 확인 필요)" >> "$LOG_FILE"
    fi
  done

  echo "[완료] 조치가 마무리되었습니다. 상세 내역은 $LOG_FILE 을 확인하세요."

  echo "----------------------------------------------------------------------"
  echo "[주의] 일반 사용자의 쓰기 권한을 제거했으나, 시스템에 불필요한 파일일 수 있습니다."
  echo "       로그 파일을 검토하여 관리자가 직접 삭제 여부를 판단하시기 바랍니다."
  echo "       - 파일 삭제 명령어 예시: rm -f <파일명>"
  echo "       - 삭제 전 로그 확인 명령어: cat $LOG_FILE"
  echo "----------------------------------------------------------------------"
}

U_26() {
  echo "[시작] U-26 /dev 디렉터리 내 불필요 파일 점검 및 조치를 시작합니다."

  local EXTRA_FILES=$(find /dev -type f 2>/dev/null)
  local LOG_FILE="/root/u26_remediation_log.txt"
  
  echo "--- U-23 Remediation Log ($(date)) ---" > "$LOG_FILE"

  if [ -z "$EXTRA_FILES" ]; then
    echo "[양호] /dev 디렉터리 내에 불필요한 일반 파일이 존재하지 않습니다."
    return 0
  fi

  echo "[정보] 불필요한 일반 파일이 발견되어 삭제를 진행합니다."
  
  for file in $EXTRA_FILES; do
    ls -l "$file" >> "$LOG_FILE"

    rm -f "$file"
    
    if [ $? -eq 0 ]; then
      echo "[완료] 삭제됨: $file" | tee -a "$LOG_FILE"
    else
      echo "[오류] 삭제 실패: $file (수동 확인 필요)" | tee -a "$LOG_FILE"
    fi
  done

  echo "[완료] 조치가 마무리되었습니다. 상세 내역은 $LOG_FILE 을 확인하세요."
}

U_27() {
  echo "[시작] U-27 rhosts 및 hosts.equiv 파일 조치를 시작합니다."
  local LOG_FILE="/root/u27_remediation_log.txt"
  echo "--- U-27 Remediation Log ($(date)) ---" > "$LOG_FILE"

  if [ -f "/etc/hosts.equiv" ]; then
    echo "[정보] /etc/hosts.equiv 파일 발견"
    cp -p /etc/hosts.equiv /etc/hosts.equiv.bak_u27
 
    chown root /etc/hosts.equiv
    chmod 600 /etc/hosts.equiv

    sed -i '/+/d' /etc/hosts.equiv
    echo "[완료] /etc/hosts.equiv 조치 완료" >> "$LOG_FILE"
  fi

  awk -F: '$3 >= 1000 || $3 == 0 { print $1 ":" $6 }' /etc/passwd | while read -r line; do
    local user=$(echo "$line" | cut -d: -f1)
    local home=$(echo "$line" | cut -d: -f2)
    local rhost_file="$home/.rhosts"

    if [ -f "$rhost_file" ]; then
      echo "[정보] $user 의 .rhosts 파일 발견: $rhost_file"
      cp -p "$rhost_file" "${rhost_file}.bak_u27"

      chown "$user" "$rhost_file"
      chmod 600 "$rhost_file"

      sed -i '/+/d' "$rhost_file"
      echo "[완료] $rhost_file 조치 완료" >> "$LOG_FILE"
    fi
  done

  echo "[완료] 모든 r-commands 관련 설정 파일 조치가 완료되었습니다."
  echo "[참고] 상세 내역은 $LOG_FILE 을 확인하세요."
}

U_28() {
  echo "=========================================================="
  echo " [U-28] 접속 IP 및 포트 제한 - 시스템 환경 진단"
  echo "=========================================================="
  
  echo -n "[1/4] TCP Wrapper 상태: "
  if [ -f "/etc/hosts.allow" ] || [ -f "/etc/hosts.deny" ]; then
    echo "활성화 (설정 파일 존재)"
    echo "    - /etc/hosts.allow: 허용 리스트"
    echo "    - /etc/hosts.deny: 차단 리스트"
  else
    echo "미사용 (파일 없음)"
  fi

  echo -n "[2/4] Firewalld 상태: "
  if systemctl is-active --quiet firewalld; then
    echo "실행 중 (Active)"
  else
    echo "중지됨 (Inactive)"
  fi

  echo -n "[3/4] Iptables 상태: "
  if systemctl is-active --quiet iptables; then
    echo "실행 중 (Active)"
  elif which iptables > /dev/null 2>&1; then
    echo "설치되어 있으나 중지됨"
  else
    echo "미설치"
  fi

  echo -n "[4/4] UFW 상태: "
  if which ufw > /dev/null 2>&1 && systemctl is-active --quiet ufw; then
    echo "실행 중 (Active)"
  else
    echo "미사용 또는 미설치"
  fi

  echo "----------------------------------------------------------"
  echo " [수동 조치 가이드] 권장하는 설정 순서 (예시)"
  echo "----------------------------------------------------------"
  echo " 1. TCP Wrapper 설정 (강력 권장)"
  echo "    - echo 'ALL:ALL' >> /etc/hosts.deny  (전체 차단)"
  echo "    - echo 'sshd : <관리자IP>' >> /etc/hosts.allow (관리자 허용)"
  echo ""
  
  if systemctl is-active --quiet firewalld; then
    echo " 2. Firewalld 설정 방법 (현재 시스템 사용 중)"
    echo "    - firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"<허용IP>\" port protocol=\"tcp\" port=\"22\" accept'"
    echo "    - firewall-cmd --reload"
  elif which ufw > /dev/null 2>&1; then
    echo " 2. UFW 설정 방법 (현재 시스템 사용 가능)"
    echo "    - ufw allow from <허용IP> to any port 22"
  else
    echo " 2. Iptables 설정 방법"
    echo "    - iptables -A INPUT -p tcp -s <허용IP> --dport 22 -j ACCEPT"
    echo "    - iptables -A INPUT -p tcp --dport 22 -j DROP"
  fi
  
  echo "----------------------------------------------------------"
  echo " ※ 주의: 반드시 본인의 접속 IP를 먼저 허용 리스트에 추가한 후"
  echo "    차단 정책을 적용하십시오. 실수할 경우 SSH 접속이 끊길 수 있습니다."
  echo "=========================================================="
}

U_29() {
  echo "[시작] U-29 /etc/hosts.lpd 파일 소유자 및 권한 조치를 시작합니다."

  local FILE="/etc/hosts.lpd"

  if [ -f "$FILE" ]; then
    echo "[정보] $FILE 파일이 발견되었습니다. 조치를 시작합니다."

    chown root "$FILE"
    chmod 600 "$FILE"

    echo "[완료] $FILE 의 소유자를 root로, 권한을 644에서 600으로 변경하였습니다."
    ls -l "$FILE"
  else
    echo "[양호] $FILE 파일이 존재하지 않으므로 조치가 필요 없습니다."
  fi
}

U_30() {
  echo "[시작] U-30 UMASK 설정 관리 조치를 시작합니다."

  if [ -f "/etc/profile" ]; then
 
    if grep -iq "umask" /etc/profile; then
      sed -i 's/umask [0-9]\{3\}/umask 022/gI' /etc/profile
    else
      echo "umask 022" >> /etc/profile
    fi
    echo "[완료] /etc/profile: umask 022 설정 완료" 
  fi

  if [ -f "/etc/login.defs" ]; then
  
    if grep -iq "^UMASK" /etc/login.defs; then
      sed -i 's/^UMASK.*/UMASK           022/gI' /etc/login.defs
    else
      echo "UMASK           022" >> /etc/login.defs
    fi
    echo "[완료] /etc/login.defs: UMASK 022 설정 완료" 
  fi

  echo "[완료] UMASK 조치가 마무리되었습니다."
  echo "[주의] 현재 쉘에는 바로 적용되지 않으므로 'source /etc/profile'을 실행하거나 재접속하세요."
}

U_31() {
  echo "[시작] U-31 홈 디렉터리 소유자 및 권한 조치를 시작합니다."

  awk -F: '$3 >= 1000 || $3 == 0 { print $1 ":" $6 }' /etc/passwd | while read -r line; do
    local user=$(echo "$line" | cut -d: -f1)
    local home=$(echo "$line" | cut -d: -f2)

    if [ -d "$home" ]; then
      echo "[점검] 사용자: $user, 경로: $home"

      chown "$user" "$home" 2>/dev/null

      chmod o-w "$home" 2>/dev/null

      echo "[완료] $home -> 소유자($user) 설정 및 타인 쓰기권한 제거 완료" 
    else
      echo "[경고] $user 의 홈 디렉터리($home)가 존재하지 않습니다." 
    fi
  done

  echo "[완료] 모든 홈 디렉터리에 대한 조치가 마무리되었습니다."
}

U_32() {
  echo "[시작] U-32 홈 디렉터리 존재 여부 점검 및 계정 삭제를 시작합니다."
  local LOG_FILE="/root/u32_remediation_log.txt"
  echo "--- U-32 Remediation Log ($(date)) ---" > "$LOG_FILE"

  awk -F: '$3 >= 1000 || $3 == 0 { print $1 ":" $6 }' /etc/passwd | while read -r line; do
    local user=$(echo "$line" | cut -d: -f1)
    local home=$(echo "$line" | cut -d: -f2)

    if [ "$user" == "root" ]; then
      continue
    fi

    if [ ! -d "$home" ]; then
      echo "[발견] 홈 디렉터리가 없는 계정: $user (경로: $home)" | tee -a "$LOG_FILE"

      if [ "$home" == "/dev/null" ] || [ "$home" == "/" ]; then
        echo "      -> [주의] 시스템 가상 경로($home) 설정 계정입니다. 안전을 위해 삭제하지 않습니다." >> "$LOG_FILE"
      else
        echo "      -> [조치] 홈 디렉터리 부재로 인한 계정($user) 삭제 수행" >> "$LOG_FILE"
        userdel "$user" 2>/dev/null
        
        if [ $? -eq 0 ]; then
          echo "      [완료] 계정($user) 삭제 완료" >> "$LOG_FILE"
        else
          echo "      [실패] 계정($user) 삭제 중 오류 발생 (현재 사용 중인 계정일 수 있음)" >> "$LOG_FILE"
        fi
      fi
    fi
  done

  echo "--------------------------------------------------"
  echo "[완료] 점검 및 계정 삭제 조치가 마무리되었습니다."
  echo "[확인] 상세 삭제 내역은 로그($LOG_FILE)를 확인하세요."
}

U_33() {
  echo "[시작] U-33 숨겨진 파일 및 디렉터리 점검을 시작합니다."
  echo "[정보] 시스템 전체를 스캔하므로 시간이 다소 걸릴 수 있습니다..."

  local LOG_FILE="/root/u33_hidden_files_scan.txt"
  echo "--- U-33 Hidden Files Scan Log ($(date)) ---" > "$LOG_FILE"

  find / \( -type f -o -type d \) -name ".*" -not -name "." -not -name ".." -xdev -exec ls -lad {} \; >> "$LOG_FILE" 2>/dev/null

  if [ $? -eq 0 ]; then
    echo "[완료] 점검이 완료되었습니다."
    echo "--------------------------------------------------"
    echo "  [확인 방법]"
    echo "  로그 파일($LOG_FILE)을 열어 의심스러운 파일을 점검하세요."
    echo ""
    echo "  [주의 사항]"
    echo "  .bashrc, .ssh, .bash_profile 등은 시스템 정상 파일입니다."
    echo "  생소한 이름(예: .temp, .... , .hidden_script)은 삭제를 검토하세요."
    echo "--------------------------------------------------"
  else
    echo "[오류] 점검 중 문제가 발생했습니다."
  fi
}

U_34() {
  echo "[시작] U-34 Finger 서비스 비활성화 조치를 시작합니다."

  if [ -f "/etc/inetd.conf" ]; then
    cp -p /etc/inetd.conf /etc/inetd.conf.bak_u34
    if grep -iq "finger" /etc/inetd.conf; then
      sed -i '/finger/s/^/#/' /etc/inetd.conf
      echo "[완료] /etc/inetd.conf: finger 서비스 주석 처리 완료" 
    fi
  fi

  if [ -f "/etc/xinetd.d/finger" ]; then
    cp -p /etc/xinetd.d/finger /etc/xinetd.d/finger.bak_u34
    sed -i 's/disable\s*=\s*no/disable = yes/g' /etc/xinetd.d/finger
    echo "[완료] /etc/xinetd.d/finger: disable = yes 설정 완료" 
    systemctl restart xinetd 2>/dev/null
  fi

  if systemctl is-active --quiet finger-server 2>/dev/null; then
    systemctl stop finger-server
    systemctl disable finger-server
    echo "[완료] finger-server 서비스 중지 및 비활성화 완료" 
  fi

  echo "[결과] Finger 서비스 비활성화 조치가 마무리되었습니다."
}

U_35() {
  echo "[시작] U-35 공유 서비스 익명 접근 제한 조치를 시작합니다."

  for user in "ftp" "anonymous"; do
    if id "$user" &>/dev/null; then
      userdel "$user" 2>/dev/null
      echo "[완료] FTP 계정 제거: $user" 
    fi
  done

  local VSFTP_CONF_LIST=("/etc/vsftpd.conf" "/etc/vsftpd/vsftpd.conf")
  for conf in "${VSFTP_CONF_LIST[@]}"; do
    if [ -f "$conf" ]; then
      if grep -iq "anonymous_enable" "$conf"; then
        sed -i 's/anonymous_enable=YES/anonymous_enable=NO/gI' "$conf"
      else
        echo "anonymous_enable=NO" >> "$conf"
      fi
      systemctl restart vsftpd 2>/dev/null
      echo "[완료] vsFTP 조치 완료 ($conf)" >> "$LOG_FILE"
    fi
  done

  local PROFTP_CONF_LIST=("/etc/proftpd.conf" "/etc/proftpd/proftpd.conf")
  for conf in "${PROFTP_CONF_LIST[@]}"; do
    if [ -f "$conf" ]; then
      sed -i '/<Anonymous/,/<\/Anonymous>/ s/^/#/' "$conf"
      systemctl restart proftpd 2>/dev/null
      echo "[완료] ProFTP 조치 완료 ($conf)" >> "$LOG_FILE"
    fi
  done


  if [ -f "/etc/exports" ]; then
    sed -i 's/,anonuid=[0-9]*//g; s/anonuid=[0-9]*,//g; s/anonuid=[0-9]*//g' /etc/exports
    sed -i 's/,anongid=[0-9]*//g; s/anongid=[0-9]*,//g; s/anongid=[0-9]*//g' /etc/exports
    exportfs -ra 2>/dev/null
    echo "[완료] NFS 익명 옵션 제거 완료" >> "$LOG_FILE"
  fi

  if [ -f "/etc/samba/smb.conf" ]; then
    sed -i 's/guest ok = yes/guest ok = no/gI' /etc/samba/smb.conf
    smbcontrol all reload-config 2>/dev/null
    echo "[완료] Samba guest ok = no 설정 완료" >> "$LOG_FILE"
  fi

  echo "[결과] 공유 서비스 익명 접근 제한 조치가 마무리되었습니다."
}

U_36() {
  echo "=========================================================="
  echo " [U-36] r 계열 서비스 비활성화 조치 시작"
  echo "=========================================================="
  local LOG_FILE="/root/u36_remediation_log.txt"
  echo "--- U-36 Remediation Log ($(date)) ---" > "$LOG_FILE"

  echo "[1/2] systemd 서비스 점검 및 조치:"
  local r_services=("rsh.service" "rlogin.service" "rexec.service" "rsh" "rlogin" "rexec")

  for svc in "${r_services[@]}"; do
    if systemctl list-unit-files "$svc" &>/dev/null; then
      echo "    [발견] $svc 서비스가 존재합니다. 조치를 시작합니다." | tee -a "$LOG_FILE"
      
      systemctl stop "$svc" 2>/dev/null
      systemctl disable "$svc" 2>/dev/null
      
      echo "    [완료] $svc 서비스 중지 및 비활성화 완료" | tee -a "$LOG_FILE"
    fi
  done

  echo -e "\n[2/2] xinetd 및 inetd 설정 점검:"
 
  if [ -d "/etc/xinetd.d" ]; then
    local xinetd_files=("rlogin" "rsh" "rexec" "shell" "login" "exec")
    for file in "${xinetd_files[@]}"; do
      if [ -f "/etc/xinetd.d/$file" ]; then
        echo "    [발견] /etc/xinetd.d/$file 설정 발견. 비활성화 중..." | tee -a "$LOG_FILE"
        sed -i 's/disable\s*=\s*no/disable = yes/g' "/etc/xinetd.d/$file"
        echo "    [완료] /etc/xinetd.d/$file 비활성화(disable = yes) 완료" | tee -a "$LOG_FILE"
        local xinetd_restart_needed=1
      fi
    done
  fi

  if [ "$xinetd_restart_needed" == "1" ]; then
    systemctl restart xinetd 2>/dev/null
    echo "    [알림] xinetd 서비스를 재시작하여 설정을 적용했습니다." >> "$LOG_FILE"
  fi

  if [ -f "/etc/inetd.conf" ]; then
    echo "    [발견] /etc/inetd.conf 설정 발견. 주석 처리 중..." | tee -a "$LOG_FILE"
    sed -i '/^rlogin/s/^/#/' /etc/inetd.conf
    sed -i '/^rsh/s/^/#/' /etc/inetd.conf
    sed -i '/^rexec/s/^/#/' /etc/inetd.conf
    echo "    [완료] /etc/inetd.conf 내 r 계열 서비스 주석 처리 완료" >> "$LOG_FILE"
  fi

  echo "----------------------------------------------------------"
  echo " [완료] r 계열 서비스 자동 조치가 마무리되었습니다."
  echo " [참조] 상세 조치 내역: $LOG_FILE"
  echo "=========================================================="
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
  echo "=========================================================="
  echo " [U-38] DoS 취약 서비스 조치 (inetd/xinetd/systemd)"
  echo "=========================================================="
  local LOG_FILE="/root/u38_remediation_log.txt"

  if [ -f "/etc/inetd.conf" ]; then
    echo "[1/3] inetd.conf 서비스 주석 처리 중..."
    sed -i -E 's/^(echo|discard|daytime|chargen)/#\1/' /etc/inetd.conf
  
    systemctl restart inetd 2>/dev/null || pkill -HUP inetd 2>/dev/null
  fi

  if [ -d "/etc/xinetd.d" ]; then
    echo "[2/3] xinetd 서비스 비활성화 중..."
    local x_targets=("echo" "discard" "daytime" "chargen")
    for x_svc in "${x_targets[@]}"; do
      if [ -f "/etc/xinetd.d/$x_svc" ]; then
        
        sed -i 's/disable\s*=\s*no/disable = yes/g' "/etc/xinetd.d/$x_svc"
        
        grep -q "disable" "/etc/xinetd.d/$x_svc" || sed -i '/{/a \ \ \ \ disable = yes' "/etc/xinetd.d/$x_svc"
      fi
    done
    systemctl restart xinetd 2>/dev/null
  fi

  echo "[3/3] systemd 서비스 및 소켓 중지 중..."
  local systemd_units=(
    "echo.service" "echo.socket" "discard.service" "discard.socket"
    "daytime.service" "daytime.socket" "chargen.service" "chargen.socket"
    "snmpd.service" "named.service" "bind9.service"
  )

  for unit in "${systemd_units[@]}"; do
    if systemctl list-unit-files "$unit" &>/dev/null; then
      systemctl stop "$unit" 2>/dev/null
      systemctl disable "$unit" 2>/dev/null
      echo "    [완료] $unit 비활성화" >> "$LOG_FILE"
    fi
  done

  echo "[결과] DoS 취약 서비스 가이드라인에 따른 조치 완료."
}

U_39() {
  echo "=========================================================="
  echo " [U-39] NFS 서비스 조치 (가이드라인 Step 1-3 반영)"
  echo "=========================================================="
  local LOG_FILE="/root/u39_remediation_log.txt"
  echo "--- U-39 Remediation Log ($(date)) ---" > "$LOG_FILE"

  echo "[1/4] 마운트된 NFS 디렉터리 및 공유 설정 정리 중..."
  local MOUNT_POINTS=$(mount | grep -i nfs | awk '{print $3}')
  for mp in $MOUNT_POINTS; do
    umount -f -l "$mp" 2>/dev/null
    echo "    - 마운트 해제: $mp" >> "$LOG_FILE"
  done

  [ -f /etc/exports ] && sed -i 's/^[^#]/#&/' /etc/exports
  [ -f /etc/fstab ] && sed -i '/nfs/s/^[^#]/#&/' /etc/fstab

  echo "[2/4] NFS 관련 서비스 중지 및 비활성화 시작..."
  local NFS_UNITS=("nfs-server" "rpcbind" "nfs-mountd" "nfs-idmapd" "rpc-statd")

  for unit in "${NFS_UNITS[@]}"; do
    if systemctl list-unit-files "$unit.service" &>/dev/null || systemctl is-active --quiet "$unit"; then
      systemctl stop "$unit" 2>/dev/null
    
      systemctl disable "$unit" 2>/dev/null

      systemctl mask "$unit" 2>/dev/null
   
      if [ "$unit" == "rpcbind" ]; then
        systemctl stop rpcbind.socket 2>/dev/null
        systemctl mask rpcbind.socket 2>/dev/null
      fi
      echo "    - $unit: 중지 및 Mask 완료" >> "$LOG_FILE"
    fi
  done

  echo "[3/4] 잔여 NFS 프로세스 정리 중..."
  local KILL_LIST=("nfsd" "rpcbind" "rpc.mountd" "rpc.statd" "rpc.idmapd")
  for proc in "${KILL_LIST[@]}"; do
    pkill -9 -f "$proc" 2>/dev/null
  done

  echo "[4/4] 조치 결과 확인..."
  if ! systemctl is-active --quiet nfs-server; then
     echo "    [성공] NFS 서비스가 완전히 비활성화되었습니다." | tee -a "$LOG_FILE"
  fi

  echo "=========================================================="
}

U_40() {
  echo "[시작] U-40 NFS 접근 통제 및 설정 파일 권한 조치를 시작합니다."
  local EXPORTS="/etc/exports"

  if [ ! -f "$EXPORTS" ]; then
    echo "[양호] $EXPORTS 파일이 존재하지 않아 조치가 필요 없습니다."
    return 0
  fi

  echo "[1/2] $EXPORTS 파일 권한 및 소유자 변경 중..."
  
  chown root "$EXPORTS"
  chmod 644 "$EXPORTS"
  echo "[완료] 소유자 root, 권한 644 설정 완료" >> "$LOG_FILE"

  echo "[2/2] 접근 통제 설정 상태를 진단합니다."

  local INSECURE_CONFIG=$(grep -v "^#" "$EXPORTS" | grep "\*")
  
  if [ -n "$INSECURE_CONFIG" ]; then
    echo "----------------------------------------------------------"
    echo " [!] 경고: 전체 허용('*') 설정이 발견되었습니다."
    echo "     비인가자의 접근 위험이 있으니 특정 IP/호스트로 수정하십시오."
    echo "----------------------------------------------------------"
    echo "$INSECURE_CONFIG" | sed 's/^/    /'
    echo "[취약] 전체 허용 설정 발견" >> "$LOG_FILE"
  else
    echo "    [v] 현재 설정 내역:"
    grep -v "^#" "$EXPORTS" | sed 's/^/    /'
    echo "[양호] 특정 호스트 위주의 접근 통제가 설정되어 있습니다." >> "$LOG_FILE"
  fi

  exportfs -ra 2>/dev/null
  echo "[완료] 변경된 설정을 시스템에 적용하였습니다."

  echo "----------------------------------------------------------"
  echo " [결과] 조치가 마무리되었습니다."
  echo "=========================================================="
}

U_41() {
  echo "=========================================================="
  echo " [U-41] 불필요한 automountd 자동 비활성화 시작"
  echo "=========================================================="
  local LOG_FILE="/root/u41_remediation_log.txt"
  echo "--- U-41 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local AUTO_SVCS=("autofs.service" "autofs" "automount.service")

  echo "[1/2] automount 관련 서비스 중지 및 비활성화:"
  for svc in "${AUTO_SVCS[@]}"; do
    if systemctl list-unit-files "$svc" &>/dev/null || systemctl is-active --quiet "$svc" 2>/dev/null; then
      echo "    [조치] $svc 서비스를 발견하여 중지 및 비활성화합니다." | tee -a "$LOG_FILE"
      
      systemctl stop "$svc" 2>/dev/null
     
      systemctl disable "$svc" 2>/dev/null
     
      systemctl mask "$svc" 2>/dev/null
      
      echo "    [완료] $svc 조치 완료 (stop, disable, mask)" >> "$LOG_FILE"
    fi
  done

  echo -e "\n[2/2] 관련 설정 파일(/etc/auto.*) 점검:"
  local AUTO_FILES=$(ls /etc/auto.* /etc/auto_* 2>/dev/null)
  
  if [ -n "$AUTO_FILES" ]; then
    echo "    [정보] 기존 설정 파일이 존재합니다. (파일은 유지하되 서비스만 비활성화함)" | tee -a "$LOG_FILE"
    echo "$AUTO_FILES" | sed 's/^/    - /' >> "$LOG_FILE"
  else
    echo "    - 발견된 automount 설정 파일이 없습니다."
  fi

  echo "----------------------------------------------------------"
  echo " [완료] automountd 서비스 자동 조치가 마무리되었습니다."
  echo " [참조] 상세 조치 내역: $LOG_FILE"
  echo "=========================================================="
}

U_42() {
  echo "=========================================================="
  echo " [U-42] 불필요한 RPC 서비스 자동 비활성화 시작"
  echo "=========================================================="
  local LOG_FILE="/root/u42_remediation_log.txt"
  echo "--- U-42 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local RPC_UNITS=(
    "rpcbind.service" "rpcbind.socket"
    "rpc-statd.service" "rpc-mountd.service"
    "rpc-idmapd.service" "rpc-gssd.service"
    "rpc-svcgssd.service"
  )

  echo "[1/2] systemd RPC 관련 유닛 중지 및 비활성화:"
  for unit in "${RPC_UNITS[@]}"; do
    if systemctl list-unit-files "$unit" &>/dev/null || systemctl is-active --quiet "$unit" 2>/dev/null; then
      echo "    [조치] $unit 유닛을 발견하여 중지 및 비활성화합니다." | tee -a "$LOG_FILE"
   
      systemctl stop "$unit" 2>/dev/null
      systemctl disable "$unit" 2>/dev/null
      systemctl mask "$unit" 2>/dev/null
      
      echo "    [완료] $unit 조치 완료 (stop, disable, mask)" >> "$LOG_FILE"
    fi
  done

  echo -e "\n[2/2] xinetd 내 RPC 설정 점검 및 조치:"
  if [ -d "/etc/xinetd.d" ]; then
    local x_rpc_files=$(ls /etc/xinetd.d/ 2>/dev/null | grep -E "rpc|statd|mountd")
    local restart_xinetd=0

    if [ -n "$x_rpc_files" ]; then
      for file in $x_rpc_files; do
        echo "    [조치] /etc/xinetd.d/$file 비활성화 중..." | tee -a "$LOG_FILE"
        sed -i 's/disable\s*=\s*no/disable = yes/g' "/etc/xinetd.d/$file"
        restart_xinetd=1
      done
    fi

    if [ "$restart_xinetd" -eq 1 ]; then
      systemctl restart xinetd 2>/dev/null
      echo "    [알림] xinetd 서비스를 재시작하여 설정을 적용했습니다." >> "$LOG_FILE"
    fi
  fi

  if [ -f "/etc/inetd.conf" ]; then
    if grep -i "rpc" /etc/inetd.conf | grep -v "^#" &>/dev/null; then
      echo "[3/3] /etc/inetd.conf 내 RPC 설정 주석 처리 중..." | tee -a "$LOG_FILE"
      sed -i '/rpc/s/^/#/' /etc/inetd.conf
    fi
  fi

  echo "----------------------------------------------------------"
  echo " [완료] RPC 관련 모든 서비스 자동 조치가 마무리되었습니다."
  echo " [참조] 상세 조치 내역: $LOG_FILE"
  echo "=========================================================="
}

U_43() {
  echo "=========================================================="
  echo " [U-43] NIS, NIS+ 서비스 점검 - 시스템 진단"
  echo "=========================================================="

  echo "[1/2] NIS 데몬 상태 점검 (ypserv, ypbind 등):"

  local NIS_SVCS=$(systemctl list-units --type=service --all | grep -E "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated")
  
  if [ -n "$NIS_SVCS" ]; then
    echo "    [!] 발견: 아래 NIS 관련 서비스가 존재하거나 실행 중입니다."
    echo "$NIS_SVCS" | sed 's/^/    /'
    echo -e "\n    [!] 경고: NIS는 보안에 취약합니다. NIS+로 업그레이드하거나"
    echo "        LDAP, AD 등 보안이 강화된 인증 서비스 사용을 권고합니다."
  else
    echo "    [v] 양호: 실행 중인 NIS 관련 서비스가 없습니다."
  fi

  echo -e "\n[2/2] NIS 패키지 설치 점검 (yp-tools, ypbind 등):"
  if rpm -qa | grep -E "ypbind|ypserv|yp-tools" > /dev/null; then
    echo "    [!] 확인: NIS 관련 패키지가 설치되어 있습니다."
    rpm -qa | grep -E "ypbind|ypserv|yp-tools" | sed 's/^/    - /'
  else
    echo "    [v] 양호: 설치된 NIS 관련 패키지가 없습니다."
  fi

  echo "----------------------------------------------------------"
  echo " [!] 조치 전 주의사항"
  echo "  - 이 서비스를 중지하기 전, 현재 서버가 외부 NIS 서버를 통해"
  echo "    사용자 인증을 처리하고 있는지 반드시 확인하십시오."
  echo "  - 미사용 시 즉시 중지 및 비활성화를 권장합니다."
  echo "----------------------------------------------------------"
  echo " [수동 조치 가이드]"
  echo " 1. 서비스 중지 및 비활성화:"
  echo "    systemctl stop <서비스명>"
  echo "    systemctl disable <서비스명>"
  echo "=========================================================="
}

U_44() {
  echo "=========================================================="
  echo " [U-44] tftp, talk, ntalk 서비스 자동 비활성화 시작"
  echo "=========================================================="
  local LOG_FILE="/root/u44_remediation_log.txt"
  echo "--- U-44 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local TARGET_SVCS=("tftp" "talk" "ntalk" "tftp.socket" "tftpd")

  echo "[1/2] systemd 서비스/소켓 중지 및 비활성화:"
  for svc in "${TARGET_SVCS[@]}"; do
    if systemctl list-unit-files "$svc" &>/dev/null || systemctl is-active --quiet "$svc" 2>/dev/null; then
      echo "    [조치] $svc 유닛을 발견하여 중지 및 비활성화합니다." | tee -a "$LOG_FILE"
      
      systemctl stop "$svc" 2>/dev/null
      systemctl disable "$svc" 2>/dev/null
      systemctl mask "$svc" 2>/dev/null 
      
      echo "    [완료] $svc 조치 완료 (stop, disable, mask)" >> "$LOG_FILE"
    fi
  done

  echo -e "\n[2/2] xinetd 설정 점검 및 조치:"
  if [ -d "/etc/xinetd.d" ]; then
    local x_targets=("tftp" "talk" "ntalk")
    local restart_xinetd=0

    for file in "${x_targets[@]}"; do
      if [ -f "/etc/xinetd.d/$file" ]; then
        echo "    [조치] /etc/xinetd.d/$file 비활성화 중..." | tee -a "$LOG_FILE"
        
        sed -i 's/disable\s*=\s*no/disable = yes/g' "/etc/xinetd.d/$file"
        
        echo "    [완료] /etc/xinetd.d/$file 비활성화 완료" | tee -a "$LOG_FILE"
        restart_xinetd=1
      fi
    done

    if [ "$restart_xinetd" -eq 1 ]; then
      systemctl restart xinetd 2>/dev/null
      echo "    [알림] xinetd 서비스를 재시작하여 설정을 적용했습니다." >> "$LOG_FILE"
    fi
  fi

  if [ -f "/etc/inetd.conf" ]; then
    if grep -E "tftp|talk|ntalk" /etc/inetd.conf | grep -v "^#" &>/dev/null; then
      echo "[3/3] /etc/inetd.conf 내 관련 서비스 주석 처리 중..." | tee -a "$LOG_FILE"
      sed -i '/tftp/s/^/#/' /etc/inetd.conf
      sed -i '/talk/s/^/#/' /etc/inetd.conf
      sed -i '/ntalk/s/^/#/' /etc/inetd.conf
    fi
  fi

  echo "----------------------------------------------------------"
  echo " [완료] tftp, talk, ntalk 자동 조치가 마무리되었습니다."
  echo " [참조] 상세 조치 내역: $LOG_FILE"
  echo "=========================================================="
}

U_45() {
  echo "=========================================================="
  echo " [U-45] 메일 서비스 버전 점검 및 조치 영향도 진단"
  echo "=========================================================="

  echo "[1/2] 메일 서비스 식별 및 버전 확인:"
  
  if rpm -qa | grep -q postfix; then
    echo "    [!] Postfix 발견 | 버전: $(postconf -h mail_version 2>/dev/null)"
    systemctl is-active --quiet postfix && echo "        -> 현재 서비스 '가동 중' (주의)"
  fi

  if rpm -qa | grep -q sendmail; then
    echo "    [!] Sendmail 발견 | 버전: $(sendmail -d0.1 -bt < /dev/null 2>&1 | grep 'Version' | awk '{print $2}')"
    systemctl is-active --quiet sendmail && echo "        -> 현재 서비스 '가동 중' (주의)"
  fi

  echo -e "\n[2/2] 조치 시 영향도(Impact) 및 권장 조치:"
  echo "----------------------------------------------------------"
  echo " [!] 서비스 중지 시 위험 요소"
  echo "  1. 시스템 알림 중단: Cron 작업 결과, 시스템 장애 로그 등"
  echo "     서버 내부 알림 메일 수신이 불가능해집니다."
  echo "  2. 앱 기능 마비: 웹 애플리케이션의 회원가입, 비밀번호 찾기 등"
  echo "     메일 발송 기능이 중단됩니다."
  echo ""
  echo " [!] 업데이트 시 위험 요소"
  echo "  - 메일 서비스 구성 방식에 따라 업데이트 후 기존 설정값과의"
  echo "    호환성 검토가 반드시 필요합니다."
  echo ""
  echo " [v] 권장 조치 사항"
  echo "  - 메일 발송 기능이 필수적인 서버인지 먼저 확인하십시오."
  echo "  - 메일 서비스가 불필요하다면 중지하되, 시스템 로그는"
  echo "    별도의 로그 서버나 모니터링 도구로 대체 설정하십시오."
  echo "----------------------------------------------------------"
  
  echo " [수동 조치 가이드]"
  echo " - 미사용 시: systemctl stop <서비스명> && systemctl disable <서비스명>"
  echo " - 사용 시: dnf update <패키지명> (OS 벤더 패치 적용 권장)"
  echo "=========================================================="
}

U_46() {
  echo "[시작] U-46 일반 사용자의 메일 서비스 실행 방지 조치를 시작합니다."

  if [ -f "/etc/mail/sendmail.cf" ]; then
    echo "[1/3] Sendmail 설정 수정 중..."
  
    if grep -q "PrivacyOptions" /etc/mail/sendmail.cf; then
      if ! grep "PrivacyOptions" /etc/mail/sendmail.cf | grep -q "restrictqrun"; then
        sed -i '/O PrivacyOptions=/ s/$/ ,restrictqrun/' /etc/mail/sendmail.cf
        echo "[완료] Sendmail: PrivacyOptions에 restrictqrun 추가" 
      fi
    else
      echo "O PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun" >> /etc/mail/sendmail.cf
      echo "[완료] Sendmail: PrivacyOptions 라인 신설"
    fi
    systemctl restart sendmail 2>/dev/null
  fi

  if [ -f "/usr/sbin/postsuper" ]; then
    echo "[2/3] Postfix 실행 권한 제한 중..."
    chmod o-x /usr/sbin/postsuper
    echo "[완료] Postfix: /usr/sbin/postsuper 일반 사용자 실행 권한 제거"
  fi

  if [ -f "/usr/sbin/exiqgrep" ]; then
    echo "[3/3] Exim 실행 권한 제한 중..."
    chmod o-x /usr/sbin/exiqgrep
    echo "[완료] Exim: /usr/sbin/exiqgrep 일반 사용자 실행 권한 제거"
  fi

  echo "----------------------------------------------------------"
  echo "[결과] 메일 서비스 실행 제한 조치가 완료되었습니다."
  echo "=========================================================="
}

U_47() {
  echo "=========================================================="
  echo " [U-47] 스팸 메일 릴레이 제한 "
  echo "=========================================================="
  local LOG_FILE="/root/u47_remediation_log.txt"
  echo "--- U-47 Remediation Log ($(date)) ---" > "$LOG_FILE"

  if [ -f "/etc/mail/sendmail.cf" ]; then
    echo "[1/2] Sendmail 점검 결과:"
    if grep -q "promiscuous_relay" /etc/mail/sendmail.mc 2>/dev/null; then
      cp -p /etc/mail/sendmail.mc /etc/mail/sendmail.mc.bak_u47
      sed -i '/promiscuous_relay/d' /etc/mail/sendmail.mc
      echo "    [!] 자동조치: promiscuous_relay(전체허용) 설정을 삭제했습니다." | tee -a "$LOG_FILE"
    fi
   
    if [ -f "/etc/mail/access" ]; then
      makemap hash /etc/mail/access.db < /etc/mail/access
      echo "    [v] 알림: /etc/mail/access 기반으로 릴레이 DB를 갱신했습니다."
    fi
  fi

  if [ -f "/etc/postfix/main.cf" ]; then
    echo -e "\n[2/2] Postfix 점검 결과:"
    local MYNETWORKS=$(grep "^mynetworks =" /etc/postfix/main.cf)
    echo "    [*] 현재 설정된 허용 범위: $MYNETWORKS"
    
    if [[ "$MYNETWORKS" == *"0.0.0.0/0"* ]]; then
      echo "    [!] 취약: 모든 IP(0.0.0.0/0)에 대해 릴레이가 허용되어 있습니다!"
    fi
  fi
  
  echo -e "\n----------------------------------------------------------"
  echo " [!] 관리자 수동 조치 필요 사항 (필독)"
  echo "----------------------------------------------------------"

  if [ -f "/etc/mail/sendmail.mc" ]; then
    echo " 1. Sendmail 설정 최종 적용 (명령어 직접 입력):"
    echo "    # m4 /etc/mail/sendmail.mc > /etc/mail/sendmail.cf"
    echo "    # systemctl restart sendmail"
    echo "    (위 명령어를 입력해야 변경된 매크로가 실제 설정에 반영됩니다.)"
    echo ""
  fi
  
  if [ -f "/etc/postfix/main.cf" ]; then
    echo " 2. Postfix 릴레이 범위 수동 수정:"
    echo "    - 'vi /etc/postfix/main.cf' 를 실행하여"
    echo "    - mynetworks 항목을 신뢰할 수 있는 IP(예: 127.0.0.0/8)로 수정하세요."
    echo "    - 수정 후 'postfix reload' 를 입력하세요."
    echo ""
  fi

  echo " 3. 공통: 외부 메일 릴레이 테스트"
  echo "    - 외부망에서 'telnet <서버IP> 25' 접속 후 외부 메일 발송 시"
  echo "    - 'Relaying denied' 메시지가 나오는지 꼭 확인하십시오."
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_48() {
  echo "=========================================================="
  echo " [U-48] expn, vrfy 명령어 제한 "
  echo "=========================================================="
  local LOG_FILE="/root/u48_remediation_log.txt"
  echo "--- U-48 Remediation Log ($(date)) ---" > "$LOG_FILE"

  if [ -f "/etc/mail/sendmail.cf" ]; then
    echo "[1/2] Sendmail 설정 점검 및 수정 중..."
    cp -p /etc/mail/sendmail.cf /etc/mail/sendmail.cf.bak_u48
   
    if grep -q "O PrivacyOptions=" /etc/mail/sendmail.cf; then
      if ! grep "O PrivacyOptions=" /etc/mail/sendmail.cf | grep -iE "goaway|novrfy|noexpn"; then
        sed -i 's/O PrivacyOptions=/O PrivacyOptions=authwarnings,novrfy,noexpn,/' /etc/mail/sendmail.cf
        echo "[완료] Sendmail: PrivacyOptions에 novrfy, noexpn 옵션 추가" >> "$LOG_FILE"
      else
        echo "[양호] Sendmail: 이미 보안 옵션이 설정되어 있습니다."
      fi
    else
      echo "O PrivacyOptions=authwarnings,novrfy,noexpn,restrictqrun" >> /etc/mail/sendmail.cf
      echo "[완료] Sendmail: PrivacyOptions 설정 신설" >> "$LOG_FILE"
    fi
    systemctl restart sendmail 2>/dev/null
  fi

  if [ -f "/etc/postfix/main.cf" ]; then
    echo "[2/2] Postfix 설정 점검 및 수정 중..."
    
    if grep -q "^disable_vrfy_command" /etc/postfix/main.cf; then
      sed -i 's/^disable_vrfy_command.*/disable_vrfy_command = yes/' /etc/postfix/main.cf
      echo "[완료] Postfix: disable_vrfy_command = yes 설정 완료" >> "$LOG_FILE"
    else
      echo "disable_vrfy_command = yes" >> /etc/postfix/main.cf
      echo "[완료] Postfix: disable_vrfy_command 옵션 추가" >> "$LOG_FILE"
    fi
    postfix reload 2>/dev/null
  else
    if [ ! -f "/etc/mail/sendmail.cf" ]; then
      echo "[양호] 시스템에 Sendmail 또는 Postfix 서비스가 설치되어 있지 않습니다."
    fi
  fi

  echo "----------------------------------------------------------"
  echo " [결과] 조치가 완료되었습니다."
  echo " [로그] $LOG_FILE"
  echo "=========================================================="
}

U_49() {
  echo "=========================================================="
  echo " [U-49] DNS 보안 버전 패치"
  echo "=========================================================="
  local LOG_FILE="/root/u49_remediation_log.txt"
  echo "--- U-49 Remediation Log ($(date)) ---" > "$LOG_FILE"

  echo "[1/2] DNS 서비스(named) 상태 확인 및 조치:"
  if systemctl list-units --type=service --all | grep -q "named"; then
    local NAMED_VER=$(named -v 2>/dev/null)
    echo "    [*] 발견: BIND(named) 서비스가 존재합니다."
    echo "    [*] 현재 버전: $NAMED_VER"

 
    systemctl disable named 2>/dev/null
    echo "    [완료] named 서비스 중지 및 비활성화 완료" | tee -a "$LOG_FILE"
  else
    echo "    [v] 시스템에 설치되거나 가동 중인 named 서비스가 없습니다."
  fi

  echo -e "\n[2/2] 조치 시 영향도(Impact) 및 권장사항:"
  echo "----------------------------------------------------------"
  echo " [!] 서비스 중지 시 위험 요소"
  echo "  - 이 서버가 DNS 서버 역할을 수행 중인 경우, 서비스 중지 시"
  echo "    네트워크 내 도메인 해석이 불가능해져 장애가 발생합니다."
  echo ""
  echo " [v] 권장 조치 사항"
  echo "  - DNS 서비스가 필수적인 서버라면 서비스를 다시 시작하고"
  echo "    최신 보안 패치를 적용하십시오. (dnf update bind)"
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_50() {
  echo "=========================================================="
  echo " [U-50] DNS ZoneTransfer 설정"
  echo "=========================================================="
  local LOG_FILE="/root/u50_remediation_log.txt"
  echo "--- U-50 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local NAMED_CONF="/etc/named.conf"
  [ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/bind/named.conf.options"

  if [ -f "$NAMED_CONF" ]; then
    echo "[1/2] DNS 설정 파일 보안 조치:"
    if grep -q "allow-transfer" "$NAMED_CONF"; then
      if grep "allow-transfer" "$NAMED_CONF" | grep -q "any"; then
        sed -i 's/allow-transfer\s*{\s*any;\s*}/allow-transfer { localhost; }/g' "$NAMED_CONF"
        echo "    [완료] allow-transfer { any; } 설정을 { localhost; }로 강화했습니다." | tee -a "$LOG_FILE"
      else
        echo "    [*] 현재 설정 내역:"
        grep "allow-transfer" "$NAMED_CONF" | sed 's/^/    /'
      fi
    else
      sed -i '/options {/a \        allow-transfer { localhost; };' "$NAMED_CONF"
      echo "    [완료] allow-transfer { localhost; } 설정을 새로 추가했습니다." | tee -a "$LOG_FILE"
    fi
    
    systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null
  else
    echo "    [v] 시스템에 DNS 설정 파일(${NAMED_CONF})이 없습니다."
  fi

  echo -e "\n[2/2] 조치 시 영향도(Impact) 및 권장사항:"
  echo "----------------------------------------------------------"
  echo " [!] 서비스 장애 주의"
  echo "  - 보조(Slave) DNS 서버를 운영 중인 경우, 해당 서버의 IP를"
  echo "    반드시 allow-transfer 리스트에 수동으로 추가해야 합니다."
  echo ""
  echo " [v] 권장 조치 사항 (수동 수정)"
  echo "  - 'vi $NAMED_CONF' 를 실행하여 IP를 추가하십시오."
  echo "    예: allow-transfer { localhost; 192.168.1.10; };"
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_51() {
  echo "=========================================================="
  echo " [U-51] DNS 서비스의 취약한 동적 업데이트 설정 금지"
  echo "=========================================================="
  local LOG_FILE="/root/u51_remediation_log.txt"
  echo "--- U-51 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local NAMED_CONF="/etc/named.conf"
  [ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/bind/named.conf.options"

  if [ -f "$NAMED_CONF" ]; then
    echo "[1/2] DNS 동적 업데이트 설정 보안 조치:"

    if grep -q "allow-update" "$NAMED_CONF"; then
      if grep "allow-update" "$NAMED_CONF" | grep -qE "any|{.*};"; then
        sed -i 's/allow-update\s*{\s*any;\s*}/allow-update { none; }/g' "$NAMED_CONF"
        echo "    [완료] allow-update { any; } 설정을 { none; }으로 강화했습니다." | tee -a "$LOG_FILE"
      else
        echo "    [*] 현재 설정 내역:"
        grep "allow-update" "$NAMED_CONF" | sed 's/^/    /'
      fi
    else
      sed -i '/options {/a \        allow-update { none; };' "$NAMED_CONF"
      echo "    [완료] allow-update { none; } 설정을 새로 추가했습니다." | tee -a "$LOG_FILE"
    fi
  
    systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null
  else
    echo "    [v] 시스템에 DNS 설정 파일(${NAMED_CONF})이 없습니다."
  fi

  echo -e "\n[2/2] 조치 시 영향도(Impact) 및 권장사항:"
  echo "----------------------------------------------------------"
  echo " [!] 동적 업데이트 필요 여부 확인"
  echo "  - DHCP를 통해 클라이언트 정보를 자동 갱신해야 하거나"
  echo "    AD(Active Directory) 환경인 경우 none 설정 시 장애가 발생합니다."
  echo ""
  echo " [v] 권장 조치 사항 (수동 수정)"
  echo "  - 동적 업데이트가 반드시 필요한 IP가 있다면 직접 추가하십시오."
  echo "    예: allow-update { 192.168.1.100; };"
  echo "  - 'vi $NAMED_CONF' 를 실행하여 수정할 수 있습니다."
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_52() {
  echo "=========================================================="
  echo " [U-52] Telnet 서비스 비활성화"
  echo "=========================================================="
  local LOG_FILE="/root/u52_remediation_log.txt"
  echo "--- U-52 Remediation Log ($(date)) ---" > "$LOG_FILE"

  echo "[1/3] Telnet 서비스(systemd) 상태 확인 및 조치:"
  local units=("telnet.socket" "telnet.service" "telnet@.service" "telnetd.service")
  
  for u in "${units[@]}"; do
    if systemctl list-unit-files "$u" >/dev/null 2>&1; then
      echo "    [조치] $u 발견 - 중지 및 비활성화"
      systemctl stop "$u" 2>/dev/null
      systemctl disable "$u" 2>/dev/null
      systemctl mask "$u" 2>/dev/null 
      echo "    [완료] $u 조치 완료" | tee -a "$LOG_FILE"
    fi
  done

  echo -e "\n[2/3] 레거시(xinetd/inetd) Telnet 설정 확인:"

  if [ -f "/etc/xinetd.d/telnet" ]; then
    sed -i 's/disable.*/disable = yes/g' /etc/xinetd.d/telnet
    systemctl restart xinetd 2>/dev/null
    echo "    [완료] /etc/xinetd.d/telnet 비활성화 완료" | tee -a "$LOG_FILE"
  fi

  if [ -f "/etc/inetd.conf" ]; then
    sed -i '/telnet/s/^/#/' /etc/inetd.conf
    systemctl restart inetd 2>/dev/null
    echo "    [완료] /etc/inetd.conf 내 telnet 서비스 주석 처리" | tee -a "$LOG_FILE"
  fi

  echo -e "\n[3/3] 대체 서비스(SSH) 상태 확인:"
  if systemctl is-active --quiet sshd; then
    echo "    [v] SSH 서비스가 정상적으로 가동 중입니다."
  else
    echo "    [!] 경고: SSH 서비스가 중지되어 있습니다. 서비스를 시작합니다."
    systemctl start sshd
    systemctl enable sshd
    echo "    [완료] SSH 서비스 시작 및 활성화" | tee -a "$LOG_FILE"
  fi

  echo -e "\n----------------------------------------------------------"
  echo " [!] 조치 시 영향도 및 권장사항"
  echo "  - Telnet은 보안상 매우 취약하므로 SSH 사용을 강력 권고합니다."
  echo "  - 조치 후 기존 Telnet 접속자는 연결이 끊기므로 반드시"
  echo "    SSH(Port 22)로 접속하도록 안내하십시오."
  echo "  - 외부망 방화벽에서 22번 포트가 허용되어 있는지 확인하십시오."
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_53() {
  echo "=========================================================="
  echo " [U-53] FTP 서비스 정보 노출 제한"
  echo "=========================================================="
  local LOG_FILE="/root/u53_remediation_log.txt"
  echo "--- U-53 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
  [ ! -f "$VSFTPD_CONF" ] && VSFTPD_CONF="/etc/vsftpd.conf"

  if [ -f "$VSFTPD_CONF" ]; then
    echo "[1/2] vsftpd 배너 설정 조치:"
 
    if grep -q "ftpd_banner" "$VSFTPD_CONF"; then
      sed -i 's/^#*ftpd_banner=.*/ftpd_banner=Authorized users only./' "$VSFTPD_CONF"
    else
      echo "ftpd_banner=Authorized users only." >> "$VSFTPD_CONF"
    fi
    
    systemctl restart vsftpd 2>/dev/null
    echo "    [완료] vsftpd: 배너 정보를 'Authorized users only.'로 제한했습니다." | tee -a "$LOG_FILE"
  else
    echo "    [v] 시스템에 vsftpd 설정 파일이 없습니다."
  fi

  local PROFTPD_CONF="/etc/proftpd/proftpd.conf"
  [ ! -f "$PROFTPD_CONF" ] && PROFTPD_CONF="/etc/proftpd.conf"

  if [ -f "$PROFTPD_CONF" ]; then
    echo -e "\n[2/2] ProFTPD 배너 설정 조치:"
    
    if grep -q "ServerIdent" "$PROFTPD_CONF"; then
      sed -i 's/^#*ServerIdent.*/ServerIdent off/' "$PROFTPD_CONF"
    else
      echo "ServerIdent off" >> "$PROFTPD_CONF"
    fi
    
    systemctl restart proftpd 2>/dev/null
    echo "    [완료] ProFTPD: ServerIdent off 설정을 통해 정보를 차단했습니다." | tee -a "$LOG_FILE"
  else
    echo "    [v] 시스템에 ProFTPD 설정 파일이 없습니다."
  fi

  echo -e "\n----------------------------------------------------------"
  echo " [!] 조치 결과 확인"
  echo "  - FTP 클라이언트로 접속하여 버전 정보가 나타나는지 확인하십시오."
  echo "  - 예: ftp <서버IP> 실행 시 배너 확인"
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_54() {
  echo "=========================================================="
  echo " [U-54] 암호화되지 않는 FTP 서비스 비활성화"
  echo "=========================================================="
  local LOG_FILE="/root/u54_remediation_log.txt"
  echo "--- U-54 Remediation Log ($(date)) ---" > "$LOG_FILE"

  echo "[1/3] 단독 실행형(Standalone) FTP 서비스 상태 확인 및 조치:"

  if systemctl list-units --type=service --all | grep -q "vsftpd"; then
    systemctl stop vsftpd 2>/dev/null
    systemctl disable vsftpd 2>/dev/null
    echo "    [완료] vsftpd 서비스 중지 및 비활성화 완료" | tee -a "$LOG_FILE"
  else
    echo "    [v] vsftpd 서비스가 설치되어 있지 않거나 비활성 상태입니다."
  fi

  if systemctl list-units --type=service --all | grep -q "proftpd"; then
    systemctl stop proftpd 2>/dev/null
    systemctl disable proftpd 2>/dev/null
    echo "    [완료] proftpd 서비스 중지 및 비활성화 완료" | tee -a "$LOG_FILE"
  else
    echo "    [v] proftpd 서비스가 설치되어 있지 않거나 비활성 상태입니다."
  fi

  echo -e "\n[2/3] 관리 서비스(xinetd/inetd) 기반 FTP 설정 확인:"
  
  if [ -f "/etc/xinetd.d/ftp" ]; then
    sed -i 's/disable\s*=\s*no/disable = yes/g' /etc/xinetd.d/ftp
    systemctl restart xinetd 2>/dev/null
    echo "    [완료] /etc/xinetd.d/ftp 비활성화(disable = yes)" | tee -a "$LOG_FILE"
  fi

  if [ -f "/etc/inetd.conf" ]; then
    if grep -qE "^ftp\s+" /etc/inetd.conf; then
      sed -i '/^ftp\s+/s/^/#/' /etc/inetd.conf
      systemctl restart inetd 2>/dev/null
      echo "    [완료] /etc/inetd.conf 내 ftp 서비스 주석 처리" | tee -a "$LOG_FILE"
    fi
  fi

  echo -e "\n[3/3] 조치 후 권장사항 및 대체 수단 확인:"
  if systemctl is-active --quiet sshd; then
    echo "    [v] SSH(SFTP) 서비스가 활성화되어 있습니다. FTP 대신 SFTP를 사용하십시오."
  else
    echo "    [!] 경고: SSH 서비스가 비활성화 상태입니다. 원격 접속을 위해 SSH 활성화를 고려하십시오."
  fi

  echo -e "\n----------------------------------------------------------"
  echo " [!] 조치 시 영향도 및 안내"
  echo "  - 보안을 위해 평문 전송인 FTP 서비스를 전면 중단했습니다."
  echo "  - 파일 전송이 필요한 경우 SFTP(Port 22)를 사용하도록"
  echo "    사용자와 관련 담당자에게 안내하십시오."
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_55() {
  echo "=========================================================="
  echo " [U-55] FTP 계정 shell 제한"
  echo "=========================================================="
  local LOG_FILE="/root/u55_remediation_log.txt"
  echo "--- U-55 Remediation Log ($(date)) ---" > "$LOG_FILE"

    local CURRENT_SHELL=$(grep "^ftp:" /etc/passwd | cut -d: -f7)
    echo "[1/2] ftp 계정 현재 쉘 확인: $CURRENT_SHELL"

    if [[ "$CURRENT_SHELL" =~ "nologin" ]] || [[ "$CURRENT_SHELL" == "/bin/false" ]]; then
      echo "    [v] 양호: 이미 제한된 쉘이 적용되어 있습니다."
    else
      echo -e "\n[2/2] 보안 쉘 적용 조치:"
      local NOLOGIN_PATH="/sbin/nologin"
      [ ! -f "$NOLOGIN_PATH" ] && NOLOGIN_PATH="/usr/sbin/nologin"
      [ ! -f "$NOLOGIN_PATH" ] && NOLOGIN_PATH="/bin/false"

      usermod -s "$NOLOGIN_PATH" ftp 2>/dev/null
      
      local NEW_SHELL=$(grep "^ftp:" /etc/passwd | cut -d: -f7)
      echo "    [완료] ftp 계정의 쉘을 $NEW_SHELL (으)로 변경 완료" | tee -a "$LOG_FILE"
    fi
  else
    echo "    [v] 시스템에 ftp 계정이 존재하지 않아 조치가 필요 없습니다."
  fi

  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_56() {
  echo "=========================================================="
  echo " [U-56] FTP 서비스 접근 제어 설정"
  echo "=========================================================="
  local LOG_FILE="/root/u56_remediation_log.txt"
  echo "--- U-56 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local FTP_FILES=(
    "/etc/ftpusers"
    "/etc/ftpd/ftpusers"
    "/etc/vsftpd.ftpusers"
    "/etc/vsftpd/ftpusers"
    "/etc/vsftpd.user_list"
    "/etc/vsftpd/user_list"
  )
  echo "[1/2] FTP 접근 제어 파일 권한 강화:"
  for file in "${FTP_FILES[@]}"; do
    if [ -f "$file" ]; then
      
      chown root "$file"
      chmod 640 "$file"
      
      echo "    [완료] $file : 소유자 root, 권한 640 적용 완료" | tee -a "$LOG_FILE"
    fi
  done

  local VSFTPD_CONF="/etc/vsftpd/vsftpd.conf"
  [ ! -f "$VSFTPD_CONF" ] && VSFTPD_CONF="/etc/vsftpd.conf"

  if [ -f "$VSFTPD_CONF" ]; then
    echo -e "\n[2/2] vsftpd 설정 파일 보안 강화:"
    cp -p "$VSFTPD_CONF" "${VSFTPD_CONF}.bak_u56"

    if grep -q "userlist_enable" "$VSFTPD_CONF"; then
      sed -i 's/^#*userlist_enable=.*/userlist_enable=YES/' "$VSFTPD_CONF"
    else
      echo "userlist_enable=YES" >> "$VSFTPD_CONF"
    fi

    if ! grep -q "userlist_deny" "$VSFTPD_CONF"; then
      echo "userlist_deny=YES" >> "$VSFTPD_CONF"
    fi

    systemctl restart vsftpd 2>/dev/null
    echo "    [완료] vsftpd.conf: userlist_enable=YES 적용 및 재시작 완료" | tee -a "$LOG_FILE"
  else
    echo -e "\n[2/2] vsftpd 서비스가 설치되어 있지 않습니다."
  fi

  echo -e "\n----------------------------------------------------------"
  echo " [!] 관리자 수동 조치 권장사항"
  echo "  - /etc/ftpusers 파일에 root 등 관리자 계정이 등록되어 있는지 확인하세요."
  echo "    (보안상 root 계정은 FTP 접속을 차단하는 것이 기본입니다.)"
  echo "  - 특정 사용자만 허용하고 싶다면 vsftpd.conf에서 userlist_deny=NO로"
  echo "    변경한 뒤 user_list 파일에 허용할 계정만 넣으십시오."
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_57() {
  echo "=========================================================="
  echo " [U-57] Ftpusers 파일 설정"
  echo "=========================================================="
  local LOG_FILE="/root/u57_remediation_log.txt"
  echo "--- U-57 Remediation Log ($(date)) ---" > "$LOG_FILE"

  echo "[1/2] FTP 접근 제어 파일 내 root 계정 차단 설정:"
  local FTP_FILES=(
    "/etc/ftpusers"
    "/etc/ftpd/ftpusers"
    "/etc/vsftpd.ftpusers"
    "/etc/vsftpd/ftpusers"
    "/etc/vsftpd.user_list"
    "/etc/vsftpd/user_list"
  )

  for file in "${FTP_FILES[@]}"; do
    if [ -f "$file" ]; then
      if grep -qi "^#root" "$file"; then
        sed -i 's/^#root/root/g' "$file"
        echo "    [완료] $file : root 주석 제거 (차단 활성)" | tee -a "$LOG_FILE"
      elif ! grep -qx "root" "$file"; then
        echo "root" >> "$file"
        echo "    [완료] $file : root 계정 추가 (차단 활성)" | tee -a "$LOG_FILE"
      else
        echo "    [양호] $file : 이미 root 계정이 차단 목록에 있습니다."
      fi
    fi
  done

  local PROFTPD_CONF="/etc/proftpd/proftpd.conf"
  [ ! -f "$PROFTPD_CONF" ] && PROFTPD_CONF="/etc/proftpd.conf"

  if [ -f "$PROFTPD_CONF" ]; then
    echo -e "\n[2/2] ProFTPD 전용 보안 설정 점검:"

    if grep -q "RootLogin" "$PROFTPD_CONF"; then
      sed -i 's/RootLogin\s*on/RootLogin off/g' "$PROFTPD_CONF"
      echo "    [완료] ProFTPD: RootLogin off 설정 완료" | tee -a "$LOG_FILE"
    else
      echo "RootLogin off" >> "$PROFTPD_CONF"
      echo "    [완료] ProFTPD: RootLogin off 옵션 추가 완료" | tee -a "$LOG_FILE"
    fi
    systemctl restart proftpd 2>/dev/null
  fi

  systemctl restart vsftpd 2>/dev/null

  echo -e "\n----------------------------------------------------------"
  echo " [!] 조치 결과 확인 가이드"
  echo "  - 외부에서 FTP 클라이언트로 root 로그인을 시도하여"
  echo "    'Login incorrect' 또는 'Permission denied'가 뜨는지 확인하십시오."
  echo "  - 주의: vsftpd의 경우 userlist_deny=YES 설정이 되어 있어야"
  echo "    user_list 파일의 root 차단이 적용됩니다."
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_58() {
  echo "=========================================================="
  echo " [U-58] SNMP 서비스 강제 비활성화 및 잠금 조치"
  echo "=========================================================="
  local LOG_FILE="/root/u58_remediation_log.txt"
  echo "--- U-58 Remediation Log ($(date)) ---" > "$LOG_FILE"

  echo "[1/3] SNMP 관련 서비스 마스크(Mask) 처리 중..."
  local SNMP_UNITS=("snmpd" "snmptrapd")
  
  for unit in "${SNMP_UNITS[@]}"; do
    systemctl stop "$unit" 2>/dev/null
    systemctl disable "$unit" 2>/dev/null
    
    systemctl mask "$unit" 2>/dev/null
    echo "    - $unit: Mask 완료" | tee -a "$LOG_FILE"
  done

  echo "[2/3] 잔여 SNMP 프로세스 강제 종료 중..."
  pkill -9 -x snmpd 2>/dev/null
  pkill -9 -x snmptrapd 2>/dev/null

  echo "[3/3] 조치 결과 최종 확인..."
  if ! pgrep -x snmpd >/dev/null && ! pgrep -x snmptrapd >/dev/null; then
    echo "    [성공] 모든 SNMP 프로세스가 종료되었습니다." | tee -a "$LOG_FILE"
  else
    echo "    [실패] 프로세스가 여전히 살아있습니다. 수동 조치가 필요합니다." | tee -a "$LOG_FILE"
  fi

  echo "=========================================================="
  echo " [완료] U-58 조치 완료 (진단 재실행 요망)"
}

U_59() {
  echo "=========================================================="
  echo " [U-59] SNMP v1/v2c 비활성화 및 v3 전환 조치 시작"
  echo "=========================================================="
  local LOG_FILE="/root/u59_remediation_log.txt"
  local CONF_FILE="/etc/snmp/snmpd.conf"
  echo "--- U-59 Remediation Log ($(date)) ---" > "$LOG_FILE"

  if ! rpm -qa | grep -q "net-snmp"; then
    echo "    [v] 양호: SNMP 서비스가 설치되어 있지 않아 조치가 불필요합니다."
    return
  fi

  echo "[1/3] 기존 v1/v2c 커뮤니티 스트링 비활성화 중..."
  if [ -f "$CONF_FILE" ]; then
    sed -i 's/^rocommunity/#rocommunity/g' "$CONF_FILE"
    sed -i 's/^rwcommunity/#rwcommunity/g' "$CONF_FILE"
    echo "    [완료] v1/v2c 설정(rocommunity/rwcommunity) 주석 처리 완료" | tee -a "$LOG_FILE"
  fi

  echo "[2/3] SNMP v3 보안 사용자(snmpv3user) 생성 중..."
  systemctl stop snmpd 2>/dev/null

  if command -v net-snmp-create-v3-user &>/dev/null; then
    net-snmp-create-v3-user -ro -A authpass123! -X privpass123! -a SHA -x AES snmpv3user >> "$LOG_FILE" 2>&1
    
    if ! grep -q "^rouser snmpv3user" "$CONF_FILE"; then
      echo "rouser snmpv3user" >> "$CONF_FILE"
    fi
    echo "    [완료] v3 사용자(snmpv3user) 생성 및 암호화 설정 완료" | tee -a "$LOG_FILE"
  else
    echo "    [오류] net-snmp-create-v3-user 도구를 찾을 수 없습니다." | tee -a "$LOG_FILE"
  fi

  echo "[3/3] SNMP 서비스 재시작..."
  systemctl start snmpd 2>/dev/null
  systemctl enable snmpd 2>/dev/null

  echo "----------------------------------------------------------"
  echo " [완료] SNMP v3 전환 조치가 마무리되었습니다."
  echo " [주의] 생성된 계정: snmpv3user / 인증: SHA / 암호화: AES"
  echo " [참조] 상세 조치 내역: $LOG_FILE"
  echo "=========================================================="
}

U_60() {
  echo "=========================================================="
  echo " [U-60] SNMP Community String 복잡성 자동 설정 시작"
  echo "=========================================================="
  local LOG_FILE="/root/u60_remediation_log.txt"
  local SNMP_CONF="/etc/snmp/snmpd.conf"
  echo "--- U-60 Remediation Log ($(date)) ---" > "$LOG_FILE"

  if [ ! -f "$SNMP_CONF" ]; then
    echo "    [v] 양호: SNMP 설정 파일이 존재하지 않습니다. (조치 불필요)"
    return
  fi

  echo "[1/2] 기본 Community String(public/private) 제거 중..."
 
  if grep -vE '^[[:space:]]*#' "$SNMP_CONF" | grep -qE "public|private"; then
    echo "    [조치] 발견된 기본 설정(public/private)을 주석 처리합니다." | tee -a "$LOG_FILE"
    sed -i '/public/s/^/#/' "$SNMP_CONF"
    sed -i '/private/s/^/#/' "$SNMP_CONF"
  else
    echo "    - 기본 설정값이 활성화되어 있지 않습니다."
  fi

  echo -e "\n[2/2] 복잡한 신규 Community String 설정 중..."
  
  local NEW_COMMUNITY="Secure_SNMP_@2024_#!"

  if ! grep -vE '^[[:space:]]*#' "$SNMP_CONF" | grep -qE "rocommunity|rwcommunity|com2sec"; then
    echo "    [조치] 복잡한 신규 스트링($NEW_COMMUNITY)을 추가합니다." | tee -a "$LOG_FILE"
    echo "rocommunity $NEW_COMMUNITY" >> "$SNMP_CONF"
  else
    echo "    [알림] 이미 커스터마이징된 스트링이 존재할 수 있습니다. 수동 확인을 권장합니다." >> "$LOG_FILE"
  fi

  echo "[완료] snmpd 서비스를 재시작하여 설정을 적용합니다."
  systemctl restart snmpd 2>/dev/null

  echo "----------------------------------------------------------"
  echo " [완료] SNMP Community String 조치가 마무리되었습니다."
  echo " [정보] 신규 설정값: $NEW_COMMUNITY (Read-Only)"
  echo " [참조] 상세 조치 내역: $LOG_FILE"
  echo "=========================================================="
}

U_61() {
  echo "=========================================================="
  echo " [U-61] SNMP Access Control 설정"
  echo "=========================================================="
  local LOG_FILE="/root/u61_remediation_log.txt"
  echo "--- U-61 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local SNMP_CONF="/etc/snmp/snmpd.conf"

  if [ ! -f "$SNMP_CONF" ]; then
    echo "    [v] 양호: SNMP 설정 파일이 존재하지 않습니다. (서비스 미사용)"
    return
  fi

  echo "[1/2] 취약한 접근 제어 설정(default) 점검:"

  if grep "^com2sec" "$SNMP_CONF" | grep -q "default"; then
    echo "    [!] 취약: 모든 호스트(default)에 대해 SNMP 접근이 허용되어 있습니다."
    echo "    [*] 조치: 특정 관리자 IP 또는 네트워크 대역으로 제한이 필요합니다."
  else
    echo "    [v] 이미 특정 호스트로 접근 제어가 설정되어 있거나 default 설정이 없습니다."
  fi

  echo -e "\n[2/2] 관리자 수동 조치 가이드:"
  echo "----------------------------------------------------------"
  echo " [!] 접근 제어 설정 방법"
  echo "  - 'vi $SNMP_CONF' 파일을 열어 아래 설정을 수정하십시오."
  echo ""
  echo " [v] 수정 예시 (NMS 서버 IP가 192.168.1.100 인 경우)"
  echo "  - (기존) com2sec notConfigUser default  public"
  echo "  - (수정) com2sec notConfigUser 192.168.1.100  public"
  echo ""
  echo " [v] 네트워크 대역으로 허용 시 예시"
  echo "  - com2sec notConfigUser 192.168.1.0/24  public"
  echo ""
  echo " [v] 서비스 재시작"
  echo "  - # systemctl restart snmpd"
  echo "----------------------------------------------------------"
  
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_62() {
  echo "=========================================================="
  echo " [U-62] 로그인 시 경고 메시지 설정"
  echo "=========================================================="
  local LOG_FILE="/root/u62_remediation_log.txt"
  echo "--- U-62 Remediation Log ($(date)) ---" > "$LOG_FILE"
  
  local WARNING_MSG="************************************************************************
  * *
  * [WARNING] This system is for authorized users only.                 *
  * All activities may be monitored and recorded.                       *
  * Unauthorized access is strictly prohibited and subject to legal     *
  * action.                                                             *
  * *
  ************************************************************************"

  echo "[1/5] 서버 기본 경고 메시지 설정 중..."
  
  echo "$WARNING_MSG" > /etc/motd
  echo "$WARNING_MSG" > /etc/issue
  echo "$WARNING_MSG" > /etc/issue.net
  echo "    [완료] /etc/motd, issue, issue.net 설정 완료" | tee -a "$LOG_FILE"

  echo -e "\n[2/5] SSH 서비스 배너 활성화 중..."
  local SSHD_CONF="/etc/ssh/sshd_config"
  if [ -f "$SSHD_CONF" ]; then
    sed -i 's/^#*Banner.*/Banner \/etc\/issue.net/' "$SSHD_CONF"
    systemctl restart sshd 2>/dev/null
    echo "    [완료] SSH: Banner 경로를 /etc/issue.net으로 지정 완료" | tee -a "$LOG_FILE"
  fi

  echo -e "\n[3/5] FTP 서비스 배너 설정 중..."
  local VSFTPD_CONF=$(find /etc -name "vsftpd.conf")
  for conf in $VSFTPD_CONF; do
    sed -i 's/^#*ftpd_banner=.*/ftpd_banner=Authorized users only./' "$conf"
    systemctl restart vsftpd 2>/dev/null
  done
  
  
  local PROFTPD_CONF=$(find /etc -name "proftpd.conf")
  for conf in $PROFTPD_CONF; do
    sed -i 's/^#*ServerIdent.*/ServerIdent on "Authorized users only."/' "$conf"
    systemctl restart proftpd 2>/dev/null
  done

  echo -e "\n[4/5] SMTP 서비스 배너 설정 중..."

  if [ -f "/etc/postfix/main.cf" ]; then
    sed -i 's/^#*smtpd_banner =.*/smtpd_banner = Authorized users only./' /etc/postfix/main.cf
    systemctl restart postfix 2>/dev/null
  fi
 
  if [ -f "/etc/mail/sendmail.cf" ]; then
    sed -i 's/^O SmtpGreetingMessage=.*/O SmtpGreetingMessage=Authorized users only./' /etc/mail/sendmail.cf
    systemctl restart sendmail 2>/dev/null
  fi

  echo -e "\n[5/5] DNS 서비스 정보 숨김 설정 중..."
  local NAMED_CONF="/etc/named.conf"
  [ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/bind/named.conf.options"
  if [ -f "$NAMED_CONF" ]; then
    if grep -q "version" "$NAMED_CONF"; then
      sed -i 's/version\s*".*"/version "unknown"/g' "$NAMED_CONF"
    else
      sed -i '/options {/a \        version "unknown";' "$NAMED_CONF"
    fi
    systemctl restart named 2>/dev/null
    echo "    [완료] DNS: 버전을 unknown으로 숨김 처리 완료" | tee -a "$LOG_FILE"
  fi

  echo -e "\n----------------------------------------------------------"
  echo " [완료] 상세 로그 및 백업 파일은 각 경로를 확인하세요."
  echo "=========================================================="
}

U_63() {
  echo "=========================================================="
  echo " [U-63] sudo 명령어 접근 관리"
  echo "=========================================================="
  local LOG_FILE="/root/u63_remediation_log.txt"
  echo "--- U-63 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local SUDOERS_FILE="/etc/sudoers"

  if [ -f "$SUDOERS_FILE" ]; then
    echo "[1/2] /etc/sudoers 파일 소유자 및 권한 확인:"
   
    local CURRENT_OWNER=$(ls -l "$SUDOERS_FILE" | awk '{print $3}')
    local CURRENT_PERM=$(stat -c "%a" "$SUDOERS_FILE")
    
    echo "    [*] 현재 소유자: $CURRENT_OWNER"
    echo "    [*] 현재 권한: $CURRENT_PERM"

    echo -e "\n[2/2] 보안 조치 적용 중..."
  
    if [ "$CURRENT_OWNER" != "root" ]; then
      chown root "$SUDOERS_FILE"
      echo "    [완료] 소유자를 root로 변경했습니다." | tee -a "$LOG_FILE"
    fi

    if [ "$CURRENT_PERM" != "640" ]; then
      chmod 440 "$SUDOERS_FILE"
      chmod 640 "$SUDOERS_FILE"
      echo "    [완료] 권한을 640으로 변경했습니다." | tee -a "$LOG_FILE"
    fi
    
    echo "    [v] 최종 상태: $(ls -l "$SUDOERS_FILE")"
  else
    echo "    [!] 오류: /etc/sudoers 파일을 찾을 수 없습니다."
  fi

  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_64() {
  echo "=========================================================="
  echo " [U-64] 주기적 보안 패치 및 벤더 권고사항 적용"
  echo "=========================================================="
  local LOG_FILE="/root/u64_remediation_log.txt"
  echo "--- U-64 Remediation Log ($(date)) ---" > "$LOG_FILE"

  echo "[1/2] 시스템 현재 버전 정보 확인:"
  if command -v hostnamectl &> /dev/null; then
    hostnamectl | tee -a "$LOG_FILE"
  else
    echo "    - OS 정보: $(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release)"
    echo "    - 커널 정보: $(uname -a)"
  fi

  echo -e "\n[2/2] 적용 가능한 보안 패치 점검:"
  if command -v dnf &> /dev/null; then
    local SECURITY_UPDATES=$(dnf updateinfo list security --installed 2>/dev/null)
    if [ -z "$SECURITY_UPDATES" ]; then
      echo "    [v] 현재 설치된 패키지 중 즉시 적용할 보안 업데이트가 없습니다."
    else
      echo "    [!] 설치 가능한 보안 패치가 존재합니다. 아래 목록을 확인하세요."
      dnf updateinfo list security
    fi
  elif command -v yum &> /dev/null; then
    yum updateinfo list security
  fi

  echo -e "\n----------------------------------------------------------"
  echo " [!] 관리자 보안 패치 권장사항"
  echo "----------------------------------------------------------"
  echo " 1. 보안 업데이트만 적용하려면 아래 명령어를 사용하십시오:"
  echo "    # dnf upgrade --security (또는 yum update --security)"
  echo ""
  echo " 2. 커널 업데이트 후에는 반드시 재부팅이 필요합니다:"
  echo "    # reboot"
  echo ""
  echo " 3. 현재 OS가 EOL(지원종료) 상태인지 확인하고 최신 버전 유지를 권고합니다."
  echo "    (예: CentOS 7, 8 등은 이미 지원이 종료되었습니다.)"
  echo "----------------------------------------------------------"
  
  echo " [완료] 상세 정보는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_65() {
  echo "=========================================================="
  echo " [U-65] NTP/시각 동기화 설정 조치 (가이드라인 준수)"
  echo "=========================================================="
  
  local NTP_CONFS=("/etc/chrony.conf" "/etc/ntp.conf")
  local UPDATED=0

  for CONF in "${NTP_CONFS[@]}"; do
    if [ -f "$CONF" ]; then
      echo "[진행] $CONF 설정 수정 중..."
      sed -i 's/^\s*server /#server /g' "$CONF"
      sed -i 's/^\s*pool /#pool /g' "$CONF"
      
      echo "server 0.ko.pool.ntp.org iburst" >> "$CONF"
      echo "server 1.ko.pool.ntp.org iburst" >> "$CONF"
      UPDATED=1
    fi
  done

  if [ "$UPDATED" -eq 1 ]; then
    echo "[진행] NTP 서비스(chronyd) 재시작 중..."
    systemctl stop chronyd 2>/dev/null
    systemctl disable chronyd 2>/dev/null
    systemctl enable chronyd 2>/dev/null
    systemctl start chronyd 2>/dev/null
    echo "    [완료] 서비스 재시작 성공"
  else
    echo "    [오류] 설정 파일을 찾을 수 없습니다."
  fi

  echo "=========================================================="
}

U_66() {
  echo "=========================================================="
  echo " [U-66] 정책에 따른 시스템 로깅 설정"
  echo "=========================================================="
  local LOG_FILE="/root/u66_remediation_log.txt"
  echo "--- U-66 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local RSYSLOG_CONF="/etc/rsyslog.conf"
  [ ! -f "$RSYSLOG_CONF" ] && RSYSLOG_CONF="/etc/rsyslog.d/default.conf"

  if [ -f "$RSYSLOG_CONF" ]; then
    echo "[1/2] rsyslog 정책 수정 중..."
 
    local POLICIES=(
      "*.info /var/log/messages"
      "authpriv.* /var/log/secure"
      "mail.* /var/log/maillog"
      "cron.* /var/log/cron"
      "*.emerg *"
    )

    for policy in "${POLICIES[@]}"; do
      local selector=$(echo "$policy" | awk '{print $1}')
      sed -i "s|^$selector|#$selector|g" "$RSYSLOG_CONF"
      echo "$policy" >> "$RSYSLOG_CONF"
    done

    echo "[2/2] rsyslog 서비스 활성화 및 재시작 중..."
    systemctl unmask rsyslog 2>/dev/null   
    systemctl enable rsyslog 2>/dev/null   
    systemctl restart rsyslog 2>/dev/null  
    
    if ps -ef | grep -v grep | grep -q "rsyslogd"; then
      echo "    [완료] rsyslogd 데몬이 정상적으로 실행 중입니다." | tee -a "$LOG_FILE"
    else
      echo "    [경고] rsyslogd 데몬이 시작되지 않았습니다. 문법 오류를 확인하세요." | tee -a "$LOG_FILE"
    fi

  elif command -v refresh &> /dev/null && [ -f "/etc/syslog.conf" ]; then
    echo "[1/2] syslogd 정책 수정 중 (AIX 스타일)..."
    echo "*.emerg *" >> /etc/syslog.conf
    echo "*.alert /dev/console" >> /etc/syslog.conf
    refresh -s syslogd
    echo "    [완료] syslogd 정책 적용 완료" | tee -a "$LOG_FILE"
  else
    echo "    [!] 오류: rsyslog 또는 syslog 설정 파일을 찾을 수 없습니다." | tee -a "$LOG_FILE"
  fi

  echo -e "\n----------------------------------------------------------"
  echo " [!] 조치 후 권장사항"
  echo "  - /var/log 디렉토리의 잔여 용량을 주기적으로 확인하십시오."
  echo "  - logrotate 서비스가 정상 작동하는지 점검하십시오."
  echo "----------------------------------------------------------"
  echo " [완료] 상세 로그는 $LOG_FILE 을 확인하세요."
  echo "=========================================================="
}

U_67() {
  echo "=========================================================="
  echo " [U-67] 로그 파일 소유자 및 권한 조치 (Rocky 9 최적화)"
  echo "=========================================================="
  local LOG_FILE="/root/u67_remediation_log.txt"
  echo "--- U-67 Remediation Log ($(date)) ---" > "$LOG_FILE"

  local TARGET_LOGS=(
    "/var/log/messages" "/var/log/secure" "/var/log/maillog"
    "/var/log/cron" "/var/log/spooler" "/var/log/boot.log"
    "/var/log/lastlog" "/var/log/wtmp" "/var/log/btmp"
    "/var/log/syslog" "/var/log/auth.log" 
  )

  echo "[1/2] 주요 로그 파일 권한 및 소유자 조치 중..."
  for log_path in "${TARGET_LOGS[@]}"; do
    if [ -f "$log_path" ]; then
      chown root:root "$log_path" 2>/dev/null
      chmod 640 "$log_path" 2>/dev/null
      echo "    - $log_path: root / 640 적용 완료" >> "$LOG_FILE"
    fi
  done

  echo "[2/2] /var/log 디렉터리 내 기타 로그 파일 일괄 조치..."
  find /var/log -type f \( -name "*.log" -o -name "messages*" -o -name "secure*" \) -exec chown root:root {} \; -exec chmod 640 {} \; 2>/dev/null

  echo "----------------------------------------------------------"
  echo " [완료] 로그 파일 보안 조치가 완료되었습니다."
  echo " [결과] 모든 로그 파일이 root 소유 및 640(rw-r-----) 권한으로 설정됨."
  echo "=========================================================="
}

FUNC_NAME=$(echo "$TARGET_CODE" | tr '-' '_')

if declare -f "$FUNC_NAME" > /dev/null; then
    $FUNC_NAME
else
    echo "Invalid Code: $TARGET_CODE"
    exit 1
fi
