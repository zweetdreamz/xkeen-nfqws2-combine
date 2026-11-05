# shellcheck shell=sh
# State builders for the immutable engine test roots. Never source routing-modes-lib.sh.

engine_scenario_names() {
  printf '%s\n' fresh applied-default routes-matrix-1 routes-matrix-2 routes-matrix-3 \
    telegram-vless telegram-recorded-zapret imported-voice-narrow imported-voice-wide standalone \
    check-udp443-not-queued check-empty-user-list check-extra-args-empty check-legacy-fake \
    check-two-empty-lists check-custom-profile-1984 argv-corpus \
    xray-jsonc-routing xray-two-routing-files xray-broken-json-file xray-no-routing-file \
    xray-no-binary xray-test-fails no-conf no-init no-xkeen-init unknown-core no-xkeen-binary \
    snapshots-baseline snapshots-all snapshots-missing snapshots-symlink snapshots-outside \
    snapshots-dotdot snapshots-empty snapshots-two-lines snapshots-double-slash \
    nfqws-runtime-foreign-cmdline nfqws-runtime-stopped nfqws-runtime-wrong-qnum nfqws-runtime-dry-run \
    synthetic21 odd-values
}

engine_legacy_run() {
  PATH="$engine_scenario_bin:$PATH" KD_TEST_ROOT="$engine_scenario_root" KD_ALLOW_TEST_ROOT=1 \
    KDN_ENGINE=legacy sh "$SCRIPT_DIR/apply-discord-nfqws2.sh" "$@"
}

engine_stage_descriptor() {
  engine_stage_service="$1"
  engine_stage_file="$2"
  shift 2
  printf '%s\n' "$@" > "$engine_stage_file.args"
  engine_stage_id="$(
    { printf '%s\n' "$engine_stage_service" 'fixture BAT.bat' 'fixture profile'; cat "$engine_stage_file.args"; } |
      awk 'NR == 1 { text=$0; next } { text=text "\n" $0 } END { printf "%s", text }' |
      sha256sum | cut -c1-12
  )"
  jq -n --arg id "$engine_stage_id" --arg service "$engine_stage_service" --rawfile args "$engine_stage_file.args" '{
    format: 1, service: $service, candidate_id: $id,
    source_name: "fixture BAT.bat", source_sha: "s", source_url: "https://example.invalid/f",
    family: "fixture profile", args: ($args | split("\n") | map(select(length > 0))),
    notes: [], rank: 1, report: {}
  }' > "$engine_stage_file"
}

engine_scenario() {
  engine_scenario_name="$1"
  engine_scenario_root="$2"
  engine_scenario_bin="$3"
  engine_scenario_conf="$2/opt/etc/nfqws2/nfqws2.conf"
  case "$1" in
    fresh) ;;
    argv-corpus)
      printf '%s\n' '["--status"]' '["--print-plan","--wide-udp"]' \
        '["--preflight","--core","xray"]' '["--core","wrong"]' '["--bogus"]' \
        '["--telegram-route","zapret"]' '["--udp-strategy"]' > "$engine_scenario_root/argv-corpus.jsonl"
      ;;
    applied-default|routes-matrix-*|telegram-vless|imported-voice-*|check-*)
      if [ "$engine_scenario_name" = check-custom-profile-1984 ]; then
        printf '\nNFQWS_ARGS_CUSTOM="--filter-tcp=1984 --lua-desync=fake:blob=0x00000000"\n' >> "$engine_scenario_conf"
      fi
      engine_legacy_run --apply --core xray --yes-router >/dev/null || return $?
      case "$engine_scenario_name" in
        routes-matrix-1) engine_legacy_run --apply --core xray --yes-router --discord-tcp-route direct --discord-voice-route vless --youtube-route zapret >/dev/null ;;
        routes-matrix-2) engine_legacy_run --apply --core xray --yes-router --discord-tcp-route vless --discord-voice-route zapret --youtube-route direct >/dev/null ;;
        routes-matrix-3) engine_legacy_run --apply --core xray --yes-router --discord-tcp-route zapret --discord-voice-route direct --youtube-route vless >/dev/null ;;
        telegram-vless) engine_legacy_run --apply --core xray --yes-router --telegram-route vless >/dev/null ;;
        imported-voice-*)
          engine_voice_high=50100
          [ "$engine_scenario_name" != imported-voice-wide ] || engine_voice_high=65535
          engine_stage_descriptor discord-voice "$engine_scenario_root/opt/tmp/voice.json" \
            "--filter-udp=19294-19344,50000-$engine_voice_high" --filter-l7=stun,discord '--out-range=<n2' \
            --payload=stun,discord_ip_discovery --lua-desync=fake:blob=discord_udp:repeats=6
          if [ "$engine_scenario_name" = imported-voice-wide ]; then
            engine_legacy_run --apply --core xray --yes-router --wide-udp >/dev/null || return $?
          fi
          engine_legacy_run --apply-import-profile "$engine_scenario_root/opt/tmp/voice.json" --yes-router >/dev/null
          ;;
        check-udp443-not-queued) printf '\nUDP_PORTS=3478:3481,5349,19294:19344,50000:50100\n' >> "$engine_scenario_conf" ;;
        check-empty-user-list) : > "$engine_scenario_root/opt/etc/nfqws2/lists/user.list" ;;
        check-extra-args-empty) printf '\nNFQWS_EXTRA_ARGS=""\n' >> "$engine_scenario_conf" ;;
        check-legacy-fake) printf '\nNFQWS_ARGS_CUSTOM="--filter-tcp=443 --dpi-desync=fake"\n' >> "$engine_scenario_conf" ;;
        check-two-empty-lists)
          printf '\nNFQWS_ARGS_CUSTOM="--filter-tcp=443 --hostlist=/opt/etc/nfqws2/lists/missing-b.list --hostlist=/opt/etc/nfqws2/lists/missing-a.list --ipset=/opt/etc/nfqws2/lists/missing-d.list --ipset=/opt/etc/nfqws2/lists/missing-c.list"\n' >> "$engine_scenario_conf"
          ;;
        check-custom-profile-1984) : ;;
      esac
      ;;
    telegram-recorded-zapret) printf '\n# Active routes: DiscordTCP=zapret, DiscordVoice=zapret, YouTube=vless, Telegram=zapret.\n' >> "$engine_scenario_conf" ;;
    standalone) engine_legacy_run --apply --standalone-zapret --yes-router >/dev/null ;;
    xray-jsonc-routing)
      { printf '// JSONC fixture\n'; cat "$engine_scenario_root/opt/etc/xray/configs/05_routing.json"; } > "$engine_scenario_root/routing.tmp"
      mv "$engine_scenario_root/routing.tmp" "$engine_scenario_root/opt/etc/xray/configs/05_routing.json"
      ;;
    xray-two-routing-files)
      printf '%s\n' '{"routing":{"rules":[{"outboundTag":"youtube-direct"}]}}' > "$engine_scenario_root/opt/etc/xray/configs/99_routing.json"
      ;;
    xray-broken-json-file) printf '{invalid\n' > "$engine_scenario_root/opt/etc/xray/configs/99_broken.json" ;;
    xray-no-routing-file) printf '{}\n' > "$engine_scenario_root/opt/etc/xray/configs/05_routing.json" ;;
    xray-no-binary) rm "$engine_scenario_bin/xray" ;;
    xray-test-fails) : > "$engine_scenario_root/xray-test-fail" ;;
    no-conf) rm "$engine_scenario_conf" ;;
    no-init) rm "$engine_scenario_root/opt/etc/init.d/S51nfqws2" ;;
    no-xkeen-init) rm "$engine_scenario_root/opt/etc/init.d/S05xkeen" ;;
    unknown-core) sed -i 's/^name_client=.*/name_client="unknown-fixture"/' "$engine_scenario_root/opt/etc/init.d/S05xkeen" ;;
    no-xkeen-binary) rm "$engine_scenario_bin/xkeen" ;;
    snapshots-*)
      engine_state="$engine_scenario_root/opt/etc/keenetic-discord-nfqws2"
      engine_snap="$engine_state/snapshots/good"
      mkdir -p "$engine_snap"
      printf 'FORMAT\t1\nSCOPE\tintegrated\n' > "$engine_snap/STATE.tsv"
      printf '%s\n' "$engine_snap" > "$engine_state/baseline.ptr"
      case "$engine_scenario_name" in
        snapshots-baseline) ;;
        snapshots-all)
          for engine_pointer in baseline-xkeen latest-preapply; do
            mkdir -p "$engine_state/snapshots/$engine_pointer"
            printf '%s\n' "$engine_state/snapshots/$engine_pointer" > "$engine_state/$engine_pointer.ptr"
          done
          ;;
        snapshots-missing) printf '%s\n' "$engine_state/snapshots/missing" > "$engine_state/baseline.ptr" ;;
        snapshots-symlink)
          ln -s "$engine_snap" "$engine_state/snapshots/link"
          printf '%s\n' "$engine_state/snapshots/link" > "$engine_state/baseline.ptr"
          ;;
        snapshots-outside) printf '%s\n' "$engine_scenario_root" > "$engine_state/baseline.ptr" ;;
        snapshots-dotdot) printf '%s\n' "$engine_state/snapshots/../snapshots/good" > "$engine_state/baseline.ptr" ;;
        snapshots-empty) : > "$engine_state/baseline.ptr" ;;
        snapshots-two-lines) printf '%s\nignored second line\n' "$engine_snap" > "$engine_state/baseline.ptr" ;;
        snapshots-double-slash) printf '%s\n' "$engine_state/snapshots//good" > "$engine_state/baseline.ptr" ;;
        *) return 2 ;;
      esac
      ;;
    nfqws-runtime-*)
      if [ "$engine_scenario_name" = nfqws-runtime-stopped ]; then
        python3 -c 'import os; print(os.getpid())' > "$engine_scenario_root/opt/var/run/nfqws2.pid"
      else
        engine_daemon="$engine_scenario_root/opt/usr/bin/nfqws2"
        engine_queue=300
        engine_extra=''
        case "$engine_scenario_name" in
          nfqws-runtime-foreign-cmdline) engine_daemon="$engine_scenario_root/foreign-daemon" ;;
          nfqws-runtime-wrong-qnum) engine_queue=999 ;;
          nfqws-runtime-dry-run) engine_extra=--dry-run ;;
        esac
        python3 -c 'import time; time.sleep(3600)' "$engine_daemon" "--qnum=$engine_queue" "$engine_extra" </dev/null >/dev/null 2>&1 &
        printf '%s\n' "$!" > "$engine_scenario_root/opt/var/run/nfqws2.pid"
      fi
      ;;
    synthetic21)
      # Explicit synthetic 2.1 root, never a relabelled historical 2.0 capture.
      # Fresh snapshots are generated by the isolated non-deployed oracle.
      engine_legacy_run --apply --core xray --yes-router >/dev/null || return $?
      engine_legacy_run --apply --core xray --yes-router --youtube-route direct >/dev/null || return $?
      ;;
    odd-values)
      sed -i '/^name_client=/d' "$engine_scenario_root/opt/etc/init.d/S05xkeen"
      printf '\nname_client="xray\\nfixture"\r\n' >> "$engine_scenario_root/opt/etc/init.d/S05xkeen"
      printf '# odd ports\r\n80\302\240443' > "$engine_scenario_root/opt/etc/xkeen/port_proxying.lst"
      printf '\nTCP_PORTS="80,443\r"' >> "$engine_scenario_conf"
      ;;
    *) printf 'Unknown engine scenario: %s\n' "$1" >&2; return 2 ;;
  esac
}
