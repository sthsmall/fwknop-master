/**
 * \file client/fwknop_common.h
 *
 * \brief Header file for fwknop config_init.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 ******************************************************************************
*/
#ifndef FWKNOP_COMMON_H
#define FWKNOP_COMMON_H

#include "common.h"
#include "log_msg.h"

/* My Name and Version
*/
//名字和版本
#define MY_NAME     "fwknop"
#define MY_DESC     "Single Packet Authorization client"

/* Get our program version from VERSION (defined in config.h).
*/
//从VERSION（在config.h中定义）获取我们的程序版本。
#define MY_VERSION VERSION

/* Default config path, can override with -c
*/
//默认配置路径，可以用-c覆盖
#define DEF_CONFIG_FILE MY_NAME".conf"

/* For time offset handling
*/
//时间偏移处理
#define MAX_TIME_STR_LEN        9
#define TIME_OFFSET_SECONDS     1
#define TIME_OFFSET_MINUTES     60
#define TIME_OFFSET_HOURS       3600
#define TIME_OFFSET_DAYS        86400

/* For resolving allow IP - the default is to do this via HTTPS with
 * wget to https://www.cipherdyne.org/cgi-bin/myip, and if the user
 * permit it, to fall back to the same URL but via HTTP.
*/
//解析允许IP - 默认情况下，这是通过HTTPS解析的
//wget到https://www.cipherdyne.org/cgi-bin/myip，如果用户
//允许它，回到相同的URL，但通过HTTP。

#define HTTP_RESOLVE_HOST           "www.cipherdyne.org"
#define HTTP_BACKUP_RESOLVE_HOST    "www.cipherdyne.com"
#define HTTP_RESOLVE_URL            "/cgi-bin/myip"
#define WGET_RESOLVE_URL_SSL        "https://" HTTP_RESOLVE_HOST HTTP_RESOLVE_URL
#define HTTP_MAX_REQUEST_LEN        2000
#define HTTP_MAX_RESPONSE_LEN       2000
#define HTTP_MAX_USER_AGENT_LEN     100
#define MAX_URL_HOST_LEN            256
#define MAX_URL_PATH_LEN            1024

/* fwknop client configuration parameters and values
*/
//fwknop客户端配置参数和值
typedef struct fko_cli_options
{
    char config_file[MAX_PATH_LEN];
    char access_str[MAX_PATH_LEN];
    char rc_file[MAX_PATH_LEN];
    char key_gen_file[MAX_PATH_LEN];
    char server_command[MAX_LINE_LEN];
    char get_key_file[MAX_PATH_LEN];
    char get_hmac_key_file[MAX_PATH_LEN];
    char save_packet_file[MAX_PATH_LEN];
    int  save_packet_file_append;
    int  show_last_command;
    int  run_last_command;
    char args_save_file[MAX_PATH_LEN];
    int  no_save_args;
    int  use_hmac;
    char spa_server_str[MAX_SERVER_STR_LEN];  /* may be a hostname */
    char allow_ip_str[MAX_IPV4_STR_LEN];
    char spoof_ip_src_str[MAX_IPV4_STR_LEN];
    char spoof_user[MAX_USERNAME_LEN];
    int  rand_port;
    char gpg_recipient_key[MAX_GPG_KEY_ID];
    char gpg_signer_key[MAX_GPG_KEY_ID];
    char gpg_home_dir[MAX_PATH_LEN];
    char gpg_exe[MAX_PATH_LEN];
#if HAVE_LIBFIU
    char fault_injection_tag[MAX_FAULT_TAG_LEN];
#endif

    /* Encryption keys read from a .fwknoprc stanza
    */
   //从.fwknoprc读取的加密密钥
    char key[MAX_KEY_LEN+1]; //加密密钥
    char key_base64[MAX_B64_KEY_LEN+1]; //加密密钥base64编码
    int  key_len; //加密密钥长度
    char hmac_key[MAX_KEY_LEN+1]; //HMAC密钥(哈希密钥)
    char hmac_key_base64[MAX_B64_KEY_LEN+1]; //HMAC密钥的base64编码
    int  hmac_key_len; //HMAC密钥长度
    int  have_key; //是否已有加密密钥
    int  have_base64_key; //是否有加密密钥的base64编码
    int  have_hmac_key; //是否有HMAC的密钥
    int  have_hmac_base64_key; //是否有HMAC密钥的base64编码
    int  hmac_type; //HMAC类型(应该是指定用哪种哈希算法)

    /* NAT access
    */
   //NAT穿透
    char nat_access_str[MAX_PATH_LEN]; //NAT的类型？？
    int  nat_local; //是否为本地NAT，便于转发及修改数据包
    int  nat_port; //NAT端口号
    int  nat_rand_port; //是否启用随机端口

    /* External IP resolution via HTTP
    */
   //外部IP解析
    int  resolve_ip_http_https; //是否通过HTTP解析外部代理
    int  resolve_http_only; //是否仅使用HTTP解析外部代理
    char *resolve_url; //解析的URL
    char http_user_agent[HTTP_MAX_USER_AGENT_LEN];
    unsigned char use_wget_user_agent;
    char *wget_bin;

    /* HTTP proxy support
    */
   //http代理
    char http_proxy[HTTP_MAX_REQUEST_LEN];

    /* SPA packet transmission port and protocol
    */
   //spa包传输端口和协议
    int spa_proto;
    unsigned int spa_dst_port;
    unsigned int spa_src_port; /* only used with --source-port */

    short digest_type;
    int encryption_mode;

    int spa_icmp_type;  /* only used in '-P icmp' mode */
    int spa_icmp_code;  /* only used in '-P icmp' mode */

    /* Various command-line flags */
    //这个是用来判断是否是debug模式的
    unsigned char   verbose; /* --verbose mode */
    unsigned char   version; /* --version */
    unsigned char   test;
    unsigned char   use_gpg;
    unsigned char   use_gpg_agent;
    unsigned char   gpg_no_signing_pw;
    unsigned char   key_gen;
    int             time_offset_plus;
    int             time_offset_minus;
    int             fw_timeout;

    unsigned char   no_home_dir;
    unsigned char   no_rc_file;
    char            use_rc_stanza[MAX_LINE_LEN];
    unsigned char   got_named_stanza;
    unsigned char   save_rc_stanza;
    unsigned char   force_save_rc_stanza;
    unsigned char   stanza_list;
    int             spa_server_resolve_ipv4;

    int input_fd;

    //char            config_file[MAX_PATH_LEN];

} fko_cli_options_t;

void free_configs(fko_cli_options_t *opts);

#endif /* FWKNOP_COMMON_H */

/***EOF***/
