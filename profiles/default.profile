# AURORA C2 default profile
#
# This file is the single source of runtime configuration.
# Start with: ./start.sh [profile-name-or-path]

# ── Team server settings ─────────────────────────────────
server {
    set clear_events_on_start "true";
    set beacon_timeout "30";
    set database "teamserver/aurora.db";
    set webui_dir "webui";
    set operator_port "5001";
    set transfer_chunk_size "524288";
    set browser_upload_max_bytes "536870912";
}

# ── Operator credentials ────────────────────────────────
operator {
    set user "admin";
    set password "aurora_admin_2026";
}

# ── JWT ──────────────────────────────────────────────────
jwt {
    set secret "change_this_jwt_secret_in_production_2026";
    set algo "HS256";
    set exp_hours "24";
}

# ── Encrypted resources ──────────────────────────────────
#    AES-256 key for encrypting/decrypting files in resources/.
#    CHANGE THIS KEY in production — then re-encrypt resources.
#    rsa_key_resource: encrypted resource name for the RSA private key.
resources {
    set key "aurora_default_resource_key_change_me";
    set rsa_key_resource "rsa_private_key";
}

# ── Implant runtime ─────────────────────────────────────
#    Controls beacon runtime defaults and payload generation.
#    RSA private key is loaded from the resource specified above.
implant {
    set spawn_process "rundll32.exe";
    set user_agent "Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36";
    set default_sleep "5";
    set default_jitter "20";
}
