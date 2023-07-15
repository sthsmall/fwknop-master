@rijndael_hmac_cmd_open_close = (
    ### command open/close cycle tests
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (1)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => ['/tmp/127.0.0.2'],
        'cmd_cycle_close_file' => ['/tmp/2127.0.0.2'],
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (2)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access2'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => ['/tmp/127.0.0.2_22_6TEST'],
        'cmd_cycle_close_file' => ['/tmp/2127.0.0.2_22_6TEST'],
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (3)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access3'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => ['/tmp/127.0.0.2_127.0.0.2'],
        'cmd_cycle_close_file' => ['/tmp/2127.0.0.2_127.0.0.2'],
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (4)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access4'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => ['/tmp/127.0.0.2_127.0.0.1'],
        'cmd_cycle_close_file' => ['/tmp/2127.0.0.1_127.0.0.2'],
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (5)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access5'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => ['/tmp/127.0.0.2127.0.0.1'],
        'cmd_cycle_close_file' => ['/tmp/2127.0.0.1127.0.0.2'],
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
        {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle server -C',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => "$default_client_hmac_args --fw-timeout 30 " .
            " && $default_client_hmac_args --fw-timeout 30 " .
            " && $default_client_hmac_args --fw-timeout 30 " .
            " && $default_client_hmac_args --fw-timeout 30 ",
        'fwknopd_cmdline' => "$fwknopdCmd -C 3 -c $cf{'def'} " .
            "-a $cf{'hmac_cmd_open_close_cycle_access5'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'expect_server_stopped' => $YES,
        'weak_server_receive_check' => $YES,
        'ignore_client_error' => $YES,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Incoming packet count limit/],
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle client timeout',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => "$default_client_hmac_args --fw-timeout 2",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access7'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [
            qr/Timer expired/,
            qr/Running.*CLOSE.*in 2 seconds/,
            qr/CLOSE.*\s2\d{5}/,
        ],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle timeout (2)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => "$default_client_hmac_args --fw-timeout 2",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access8'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [
            qr/Timer expired/,
            qr/Running.*CLOSE.*in 2 seconds/,
            qr/OPEN.*\s121/,
            qr/CLOSE.*\s222/,
        ],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle close=NONE',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access6'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => ['/tmp/127.0.0.2'],
        'cmd_cycle_close_file' => ['NONE'],
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_negative_output_matches' => [
            qr/Timer expired/,
        ],
    },

    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (UDP server)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access'} --udp-server " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => ['/tmp/127.0.0.2'],
        'cmd_cycle_close_file' => ['/tmp/2127.0.0.2'],
        'key_file' => $cf{'rc_hmac_b64_key'},
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close cycle (3 cycles)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'cmdline'  => $default_client_hmac_args .
            " && $default_client_hmac_args" .
            " && $default_client_hmac_args",
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_cycle_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => ['/tmp/127.0.0.2'],
        'cmd_cycle_close_file' => ['/tmp/2127.0.0.2'],
        'relax_receive_cycle_num_check' => $YES, ### multiple SPA packets involved
        'key_file' => $cf{'rc_hmac_b64_key'},
        'sleep_cycles' => 12,
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close (multi-cycle, mixed)',
        'client_cycles_per_server_instance' => 3,
        'function' => \&spa_cmd_open_close_exec_cycle,
        'multi_cmds' => [

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key2",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key3",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key2",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key3",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key3",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key3",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key2",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str",
        ],
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_multi_cycle_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => [
            '/tmp/127.0.0.2_default_key',
            '/tmp/127.0.0.2_key2',
            '/tmp/127.0.0.2_key3'
        ],
        'cmd_cycle_close_file' => [
            '/tmp/2127.0.0.1_default_key',
            '/tmp/2127.0.0.1_key2',
            '/tmp/2127.0.0.1_key3'
        ],
        'relax_receive_cycle_num_check' => $YES, ### multiple SPA packets involved
        'key_file' => $cf{'rc_cmd_open_close_multi_cycle'},
        'sleep_cycles' => 40,
        'server_positive_output_matches' => [qr/Timer expired/],
    },
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'client+server',
        'detail'   => 'cmd open/close (multi-cycle, UDP)',
        'function' => \&spa_cmd_open_close_exec_cycle,
        'multi_cmds' => [

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key2",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key3",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key2",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key3",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key3",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key3",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str -n key2",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str",

            "LD_LIBRARY_PATH=$lib_dir " .
            "$fwknopCmd -A tcp/22 -a $fake_ip -D $loopback_ip --rc-file " .
            "$cf{'rc_cmd_open_close_multi_cycle'} $verbose_str",
        ],
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'def'} -a $cf{'hmac_cmd_open_close_multi_cycle_access'} --udp-server " .
            "-d $default_digest_file -p $default_pid_file $intf_str",
        'fw_rule_created' => $REQUIRE_NO_NEW_RULE,
        'cmd_cycle_open_file'  => [
            '/tmp/127.0.0.2_default_key',
            '/tmp/127.0.0.2_key2',
            '/tmp/127.0.0.2_key3'
        ],
        'cmd_cycle_close_file' => [
            '/tmp/20.0.0.0_default_key',
            '/tmp/20.0.0.0_key2',
            '/tmp/20.0.0.0_key3'
        ],
        'relax_receive_cycle_num_check' => $YES, ### multiple SPA packets involved
        'key_file' => $cf{'rc_cmd_open_close_multi_cycle'},
        'sleep_cycles' => 40,
        'server_positive_output_matches' => [qr/Timer expired/],
    },

);
