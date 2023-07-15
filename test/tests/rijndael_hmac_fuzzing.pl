@rijndael_hmac_fuzzing = (
    {
        'category' => 'Rijndael+HMAC',
        'subcategory' => 'FUZZING',
        'detail'   => 'pkts from fko-wrapper',
        'function' => \&cached_pkts_fuzzer,
        'spa_pkts_file' => $send_fuzz_payloads_file,
        'fwknopd_cmdline' => "$fwknopdCmd -c $cf{'disable_aging'} -a $cf{'hmac_fuzzing_access'} " .
            "-d $default_digest_file -p $default_pid_file $intf_str --test",
    },
);
