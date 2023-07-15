@gpg = (
    ### GPG testing (with passwords associated with keys) - first check to
    ### see if pinentry is required and disable remaining GPG tests if so
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'pinentry not required',
        'function' => \&gpg_pinentry_check,
        'cmdline'  => $default_client_gpg_args,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'rc file default key (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_gpg_args_no_get_key " .
            "--rc-file $cf{'rc_def_key'}",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_def_key'},
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'rc file default key ..._PW synonym',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_gpg_args_no_get_key " .
            "--rc-file $cf{'rc_gpg_signing_pw'}",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_signing_pw'},
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'rc file named key (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_gpg_args_no_get_key " .
            "--rc-file $cf{'rc_named_key'} -n testssh",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_named_key'},
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'rc file named key ..._PW synonym',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_gpg_args_no_get_key " .
            "--rc-file $cf{'rc_gpg_named_signing_pw'} -n testssh",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_named_signing_pw'},
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'rc file b64 named key ..._PW synonym',
        'function' => \&spa_cycle,
        'cmdline'  => "$default_client_gpg_args_no_get_key " .
            "--rc-file $cf{'rc_gpg_named_signing_pw'} -n testssh2",
        'fwknopd_cmdline' => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
        'key_file' => $cf{'rc_gpg_named_signing_pw'},
    },

    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'multi gpg-IDs (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} " .
            "-a $cf{'multi_gpg_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => "$FW_TYPE - no flush at init",
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_no_flush_init"} / .
            "-a $cf{'multi_gpg_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => "$FW_TYPE - no flush at exit",
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_no_flush_exit"} / .
            "-a $cf{'multi_gpg_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => "$FW_TYPE - no flush at init or exit",
        'function' => \&iptables_no_flush_init_exit,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline' => qq/$fwknopdCmd -c $cf{"${fw_conf_prefix}_no_flush_init_or_exit"} / .
            "-a $cf{'multi_gpg_access'} $intf_str " .
            "-d $default_digest_file -p $default_pid_file",
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/23 telnet)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/23 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/9418 git)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/9418 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (tcp/60001)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A tcp/60001 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'complete cycle (udp/53 dns)',
        'function' => \&spa_cycle,
        'cmdline' => "$fwknopCmd -A udp/53 -a $fake_ip -D $loopback_ip --get-key " .
            "$local_key_file $verbose_str " .
            "--gpg-recipient-key $gpg_server_key " .
            "--gpg-signer-key $gpg_client_key " .
            "--gpg-home-dir $gpg_client_home_dir",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'fw_rule_removed' => $NEW_RULE_REMOVED,
    },

    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'replay attack detection',
        'function' => \&replay_detection,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'server_positive_output_matches' => [qr/Replay\sdetected\sfrom\ssource\sIP/],
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (Rijndael prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'U2FsdGVkX1',
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'detect replay (GnuPG prefix)',
        'function' => \&replay_detection,
        'pkt_prefix' => 'hQ',
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline' => "$fwknopdCmd $default_server_conf_args $intf_str",
        'server_positive_output_matches' => [qr/Data\sis\snot\sa\svalid\sSPA\smessage\sformat/],
    },

    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'non-base64 altered SPA data',
        'function' => \&altered_non_base64_spa_data,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'base64 altered SPA data',
        'function' => \&altered_base64_spa_data,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'appended data to SPA pkt',
        'function' => \&appended_spa_data,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'prepended data to SPA pkt',
        'function' => \&prepended_spa_data,
        'cmdline'  => $default_client_gpg_args,
        'fwknopd_cmdline'  => $default_server_gpg_args,
    },
    {
        'category' => 'GPG',
        'subcategory' => 'client+server',
        'detail'   => 'spoof username (tcp/22 ssh)',
        'function' => \&spa_cycle,
        'cmdline'  => "SPOOF_USER=$spoof_user $default_client_gpg_args",
        'fwknopd_cmdline'  => $default_server_gpg_args,
        'positive_output_matches' => [qr/Username:\s*$spoof_user/],
        'server_positive_output_matches' => [qr/Username:\s*$spoof_user/],
    },
    {
        'category' => 'GPG',
        'subcategory' => 'server',
        'detail'   => 'digest cache structure',
        'function' => \&digest_cache_structure,
    },
);
