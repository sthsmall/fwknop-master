/**
 * \file server/fwknopd_common.h
 *
 * \brief Header file for fwknopd source files.
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
#ifndef FWKNOPD_COMMON_H
#define FWKNOPD_COMMON_H

#include "common.h"
//检测是否是openbsd系统
#if PLATFORM_OPENBSD
  #include <netinet/in.h>
#endif

#if HAVE_SYS_STAT_H
  #include <sys/stat.h>
#endif

#if USE_LIBPCAP
  #include <pcap.h>
#endif

/* My Name and Version
*/
//我的名字和版本
#define MY_NAME     "fwknopd"
#define MY_DESC     "Single Packet Authorization server"

/* Get our program version from VERSION (defined in config.h).
*/
//从VERSION（在config.h中定义）获取我们的程序版本。
#define MY_VERSION VERSION

/* Some program defaults.
*/
//一些程序默认值。
#ifndef DEF_CONF_DIR
  /* Our default config directory is based on SYSCONFDIR as set by the
   * configure script.
  */
 //我们的默认配置目录基于由配置脚本设置的SYSCONFDIR。
  #define DEF_CONF_DIR      SYSCONFDIR"/"PACKAGE_NAME
#endif

#define DEF_CONFIG_FILE     DEF_CONF_DIR"/"MY_NAME".conf"
#define DEF_ACCESS_FILE     DEF_CONF_DIR"/access.conf"

#ifndef DEF_RUN_DIR
  /* Our default run directory is based on LOCALSTATEDIR as set by the
   * configure script. This is where we put the PID and digest cache files.
  */
 //我们的默认运行目录基于由配置脚本设置的LOCALSTATEDIR。这是我们放置PID和摘要缓存文件的地方。
  #define DEF_RUN_DIR       SYSRUNDIR"/"PACKAGE_NAME
#endif

/* More Conf defaults
*/
//更多Conf默认值
#define DEF_PID_FILENAME                MY_NAME".pid"
#if USE_FILE_CACHE
  #define DEF_DIGEST_CACHE_FILENAME       "digest.cache"
#else
  #define DEF_DIGEST_CACHE_DB_FILENAME    "digest_db.cache"
#endif

#define DEF_INTERFACE                   "eth0"
#define DEF_ENABLE_PCAP_PROMISC         "N"
#define DEF_PCAP_FILTER                 "udp port 62201"
#define DEF_PCAP_DISPATCH_COUNT         "100"
#define DEF_PCAP_LOOP_SLEEP             "100000" /* a tenth of a second (in microseconds) */
#define DEF_ENABLE_PCAP_ANY_DIRECTION   "N"
#define DEF_EXIT_AT_INTF_DOWN           "Y"
#define DEF_ENABLE_SPA_PACKET_AGING     "Y"
#define DEF_MAX_SPA_PACKET_AGE          "120"
#define DEF_ENABLE_DIGEST_PERSISTENCE   "Y"
#define DEF_RULES_CHECK_THRESHOLD       "20"
#define DEF_MAX_SNIFF_BYTES             "1500"
#define DEF_GPG_HOME_DIR                "/root/.gnupg"
#define DEF_ENABLE_X_FORWARDED_FOR      "N"
#define DEF_ENABLE_RULE_PREPEND         "N"
#define DEF_ENABLE_NAT_DNS              "Y"
#ifdef  GPG_EXE
  #define DEF_GPG_EXE                   GPG_EXE
#else
  #define DEF_GPG_EXE                   "/usr/bin/gpg"
#endif
#ifdef  SUDO_EXE
  #define DEF_SUDO_EXE                   SUDO_EXE
#else
  #define DEF_SUDO_EXE                   "/usr/bin/sudo"
#endif
#define DEF_ENABLE_SPA_OVER_HTTP        "N"
#define DEF_ALLOW_ANY_USER_AGENT        "N"
#define DEF_ENABLE_TCP_SERVER           "N"
#define DEF_TCPSERV_PORT                "62201"
#if USE_LIBPCAP
  #define DEF_ENABLE_UDP_SERVER           "N"
#else
  #define DEF_ENABLE_UDP_SERVER           "Y"
#endif
#if USE_LIBNETFILTER_QUEUE
  #define DEF_ENABLE_NFQ_CAPTURE          "N"
  #define DEF_NFQ_INTERFACE               ""
  #define DEF_NFQ_PORT                    "62201"
  #define DEF_NFQ_TABLE                   "mangle"
  #define DEF_NFQ_CHAIN                   "FWKNOP_NFQ"
  #define DEF_NFQ_QUEUE_NUMBER            "1"
  #define DEF_CONF_NFQ_LOOP_SLEEP         "500000" /* half a second (in microseconds) */

#endif
#define DEF_UDPSERV_PORT                "62201"
#define DEF_UDPSERV_SELECT_TIMEOUT      "500000" /* half a second (in microseconds) */
#define DEF_SYSLOG_IDENTITY             MY_NAME
#define DEF_SYSLOG_FACILITY             "LOG_DAEMON"
#define DEF_ENABLE_DESTINATION_RULE     "N"

#define DEF_FW_ACCESS_TIMEOUT           30
#define DEF_MAX_FW_TIMEOUT              300

/* For integer variable range checking
*/
#define RCHK_MAX_PCAP_LOOP_SLEEP        (2 << 22)
#define RCHK_MAX_SPA_PACKET_AGE         100000  /* seconds, can disable */
#define RCHK_MAX_SNIFF_BYTES            (2 << 14)
#define RCHK_MAX_TCPSERV_PORT           ((2 << 16) - 1)
#define RCHK_MAX_UDPSERV_PORT           ((2 << 16) - 1)
#define RCHK_MAX_UDPSERV_SELECT_TIMEOUT (2 << 22)
#define RCHK_MAX_PCAP_DISPATCH_COUNT    (2 << 22)
#define RCHK_MAX_FW_TIMEOUT             (2 << 22) /* seconds */
#define RCHK_MAX_CMD_CYCLE_TIMER        (2 << 22) /* seconds */
#define RCHK_MIN_CMD_CYCLE_TIMER        1
#define RCHK_MAX_RULES_CHECK_THRESHOLD  ((2 << 16) - 1)

/* FirewallD-specific defines
*/
//防火墙特定定义
#if FIREWALL_FIREWALLD

  #define DEF_FLUSH_FIREWD_AT_INIT         "Y"
  #define DEF_FLUSH_FIREWD_AT_EXIT         "Y"
  #define DEF_ENABLE_FIREWD_FORWARDING     "N"
  #define DEF_ENABLE_FIREWD_LOCAL_NAT      "N"
  #define DEF_ENABLE_FIREWD_SNAT           "N"
  #define DEF_ENABLE_FIREWD_OUTPUT         "N"
  #define DEF_ENABLE_FIREWD_COMMENT_CHECK  "Y"
  #define DEF_FIREWD_INPUT_ACCESS          "ACCEPT, filter, INPUT, 1, FWKNOP_INPUT, 1"
  #define DEF_FIREWD_OUTPUT_ACCESS         "ACCEPT, filter, OUTPUT, 1, FWKNOP_OUTPUT, 1"
  #define DEF_FIREWD_FORWARD_ACCESS        "ACCEPT, filter, FORWARD, 1, FWKNOP_FORWARD, 1"
  #define DEF_FIREWD_DNAT_ACCESS           "DNAT, nat, PREROUTING, 1, FWKNOP_PREROUTING, 1"
  #define DEF_FIREWD_SNAT_ACCESS           "SNAT, nat, POSTROUTING, 1, FWKNOP_POSTROUTING, 1"
  #define DEF_FIREWD_MASQUERADE_ACCESS     "MASQUERADE, nat, POSTROUTING, 1, FWKNOP_MASQUERADE, 1"

  #define RCHK_MAX_FIREWD_RULE_NUM         (2 << 15)

/* Iptables-specific defines
*/
//iptables特定定义
#elif FIREWALL_IPTABLES

  #define DEF_FLUSH_IPT_AT_INIT         "Y"
  #define DEF_FLUSH_IPT_AT_EXIT         "Y"
  #define DEF_ENABLE_IPT_FORWARDING     "N"
  #define DEF_ENABLE_IPT_LOCAL_NAT      "N"
  #define DEF_ENABLE_IPT_SNAT           "N"
  #define DEF_ENABLE_IPT_OUTPUT         "N"
  #define DEF_ENABLE_IPT_COMMENT_CHECK  "Y"
  #define DEF_IPT_INPUT_ACCESS          "ACCEPT, filter, INPUT, 1, FWKNOP_INPUT, 1"
  #define DEF_IPT_OUTPUT_ACCESS         "ACCEPT, filter, OUTPUT, 1, FWKNOP_OUTPUT, 1"
  #define DEF_IPT_FORWARD_ACCESS        "ACCEPT, filter, FORWARD, 1, FWKNOP_FORWARD, 1"
  #define DEF_IPT_DNAT_ACCESS           "DNAT, nat, PREROUTING, 1, FWKNOP_PREROUTING, 1"
  #define DEF_IPT_SNAT_ACCESS           "SNAT, nat, POSTROUTING, 1, FWKNOP_POSTROUTING, 1"
  #define DEF_IPT_MASQUERADE_ACCESS     "MASQUERADE, nat, POSTROUTING, 1, FWKNOP_MASQUERADE, 1"

  #define RCHK_MAX_IPT_RULE_NUM         (2 << 15)

/* Ipfw-specific defines
*/
//  Ipfw特定定义
#elif FIREWALL_IPFW

  #define DEF_FLUSH_IPFW_AT_INIT         "Y"
  #define DEF_FLUSH_IPFW_AT_EXIT         "Y"
  #define DEF_IPFW_START_RULE_NUM        "10000"
  #define DEF_IPFW_MAX_RULES             "65535"
  #define DEF_IPFW_ACTIVE_SET_NUM        "1"
  #define DEF_IPFW_EXPIRE_SET_NUM        "2"
  #define DEF_IPFW_EXPIRE_PURGE_INTERVAL "30"
  #define DEF_IPFW_ADD_CHECK_STATE       "N"

  #define RCHK_MAX_IPFW_START_RULE_NUM   ((2 << 16) - 1)
  #define RCHK_MAX_IPFW_MAX_RULES        ((2 << 16) - 1)
  #define RCHK_MAX_IPFW_SET_NUM          ((2 << 5) - 1)
  #define RCHK_MAX_IPFW_PURGE_INTERVAL   ((2 << 16) - 1)

#elif FIREWALL_PF

  #define DEF_PF_ANCHOR_NAME             "fwknop"
  #define DEF_PF_EXPIRE_INTERVAL         "30"

  #define RCHK_MAX_PF_EXPIRE_INTERVAL    ((2 << 16) - 1)

#elif FIREWALL_IPF

    /* --DSS Place-holder */

#endif /* FIREWALL Type */

/* fwknopd-specific limits
*/
//fwknopd特定限制
#define MAX_PCAP_FILTER_LEN     1024
#define MAX_IFNAME_LEN          128
#define MAX_SPA_PACKET_LEN      1500 /* --DSS check this? */
#define MAX_DECRYPTED_SPA_LEN   1024

/* The minimum possible valid SPA data size.
*/
//最小可能的有效SPA数据大小
#define MIN_SPA_DATA_SIZE   140

/* Configuration file parameter tags.
 * This will correspond to entries in the configuration parameters
 * array.
 *
 * Note: It is important to maintain an equivalence between this enum and the
 *       config_map[] array in server/cmd_opts.h
*/
//配置文件参数标签
//这将对应于配置参数数组中的条目
//注意:重要的是要保持这个枚举和server/cmd_opts.h中的config_map[]数组之间的等价性
enum {
    CONF_CONFIG_FILE = 0,
    CONF_OVERRIDE_CONFIG,
    //CONF_FIREWALL_TYPE,
    CONF_PCAP_INTF,
    CONF_PCAP_FILE,
    CONF_ENABLE_PCAP_PROMISC,
    CONF_PCAP_FILTER,
    CONF_PCAP_DISPATCH_COUNT,
    CONF_PCAP_LOOP_SLEEP,
    CONF_ENABLE_PCAP_ANY_DIRECTION,
    CONF_EXIT_AT_INTF_DOWN,
    CONF_MAX_SNIFF_BYTES,
    CONF_ENABLE_SPA_PACKET_AGING,
    CONF_MAX_SPA_PACKET_AGE,
    CONF_ENABLE_DIGEST_PERSISTENCE,
    CONF_RULES_CHECK_THRESHOLD,
    CONF_CMD_EXEC_TIMEOUT,
    //CONF_BLACKLIST,
    CONF_ENABLE_SPA_OVER_HTTP,
    CONF_ALLOW_ANY_USER_AGENT,
    CONF_ENABLE_TCP_SERVER,
    CONF_TCPSERV_PORT,
    CONF_ENABLE_UDP_SERVER,
    CONF_UDPSERV_PORT,
    CONF_UDPSERV_SELECT_TIMEOUT,
#if USE_LIBNETFILTER_QUEUE
    CONF_ENABLE_NFQ_CAPTURE,
    CONF_NFQ_INTERFACE,
    CONF_NFQ_PORT,
    CONF_NFQ_TABLE,
    CONF_NFQ_CHAIN,
    CONF_NFQ_QUEUE_NUMBER,
    CONF_NFQ_LOOP_SLEEP,
#endif
    CONF_LOCALE,
    CONF_SYSLOG_IDENTITY,
    CONF_SYSLOG_FACILITY,
    //CONF_IPT_EXEC_TRIES,
    //CONF_ENABLE_EXTERNAL_CMDS,
    //CONF_EXTERNAL_CMD_OPEN,
    //CONF_EXTERNAL_CMD_CLOSE,
    //CONF_EXTERNAL_CMD_ALARM,
    //CONF_ENABLE_EXT_CMD_PREFIX,
    //CONF_EXT_CMD_PREFIX,
    CONF_ENABLE_X_FORWARDED_FOR,
    CONF_ENABLE_DESTINATION_RULE,
    CONF_ENABLE_RULE_PREPEND,
    CONF_ENABLE_NAT_DNS,
#if FIREWALL_FIREWALLD
    CONF_ENABLE_FIREWD_FORWARDING,
    CONF_ENABLE_FIREWD_LOCAL_NAT,
    CONF_ENABLE_FIREWD_SNAT,
    CONF_SNAT_TRANSLATE_IP,
    CONF_ENABLE_FIREWD_OUTPUT,
    CONF_FLUSH_FIREWD_AT_INIT,
    CONF_FLUSH_FIREWD_AT_EXIT,
    CONF_FIREWD_INPUT_ACCESS,
    CONF_FIREWD_OUTPUT_ACCESS,
    CONF_FIREWD_FORWARD_ACCESS,
    CONF_FIREWD_DNAT_ACCESS,
    CONF_FIREWD_SNAT_ACCESS,
    CONF_FIREWD_MASQUERADE_ACCESS,
    CONF_ENABLE_FIREWD_COMMENT_CHECK,
#elif FIREWALL_IPTABLES
    CONF_ENABLE_IPT_FORWARDING,
    CONF_ENABLE_IPT_LOCAL_NAT,
    CONF_ENABLE_IPT_SNAT,
    CONF_SNAT_TRANSLATE_IP,
    CONF_ENABLE_IPT_OUTPUT,
    CONF_FLUSH_IPT_AT_INIT,
    CONF_FLUSH_IPT_AT_EXIT,
    CONF_IPT_INPUT_ACCESS,
    CONF_IPT_OUTPUT_ACCESS,
    CONF_IPT_FORWARD_ACCESS,
    CONF_IPT_DNAT_ACCESS,
    CONF_IPT_SNAT_ACCESS,
    CONF_IPT_MASQUERADE_ACCESS,
    CONF_ENABLE_IPT_COMMENT_CHECK,
#elif FIREWALL_IPFW
    CONF_FLUSH_IPFW_AT_INIT,
    CONF_FLUSH_IPFW_AT_EXIT,
    CONF_IPFW_START_RULE_NUM,
    CONF_IPFW_MAX_RULES,
    CONF_IPFW_ACTIVE_SET_NUM,
    CONF_IPFW_EXPIRE_SET_NUM,
    CONF_IPFW_EXPIRE_PURGE_INTERVAL,
    CONF_IPFW_ADD_CHECK_STATE,
#elif FIREWALL_PF
    CONF_PF_ANCHOR_NAME,
    CONF_PF_EXPIRE_INTERVAL,
#elif FIREWALL_IPF
    /* --DSS Place-holder */
#endif /* FIREWALL type */
    CONF_FWKNOP_RUN_DIR,
    CONF_FWKNOP_CONF_DIR,
    CONF_ACCESS_FILE,
    CONF_ACCESS_FOLDER,
    CONF_FWKNOP_PID_FILE,
#if USE_FILE_CACHE
    CONF_DIGEST_FILE,
#else
    CONF_DIGEST_DB_FILE,
#endif
    CONF_GPG_HOME_DIR,
    CONF_GPG_EXE,
    CONF_SUDO_EXE,
    CONF_FIREWALL_EXE,
    CONF_VERBOSE,
#if AFL_FUZZING
    CONF_AFL_PKT_FILE,
#endif
    CONF_FAULT_INJECTION_TAG,

    NUMBER_OF_CONFIG_ENTRIES  /* Marks the end and number of entries */
};

/* A simple linked list of uints for the access stanza items that allow
 * multiple comma-separated entries.
*/
//一个简单的链表，用于允许多个逗号分隔条目的访问部分条目。
typedef struct acc_int_list
{
    unsigned int        maddr;
    unsigned int        mask;
    struct acc_int_list *next;
} acc_int_list_t;

/* A simple linked list of proto and ports for the access stanza items that
 * allow multiple comma-separated entries.
*/
//一个简单的链表，用于允许多个逗号分隔条目的访问部分条目。
typedef struct acc_port_list
{
    unsigned int            proto;
    unsigned int            port;
    struct acc_port_list    *next;
} acc_port_list_t;

/* A simple linked list of strings for the access stanza items that
 * allow multiple comma-separated entries.
*/
//一个简单的链表，用于允许多个逗号分隔条目的访问部分条目。
typedef struct acc_string_list
{
    char                    *str;
    struct acc_string_list  *next;
} acc_string_list_t;

/* Access stanza list struct.
*/
//访问部分列表结构。
typedef struct acc_stanza
{
    char                *source;
    acc_int_list_t      *source_list;
    char                *destination;
    acc_int_list_t      *destination_list;
    char                *open_ports;
    acc_port_list_t     *oport_list;
    char                *restrict_ports;
    acc_port_list_t     *rport_list;
    char                *key;
    int                  key_len;
    char                *key_base64;
    char                *hmac_key;
    int                  hmac_key_len;
    char                *hmac_key_base64;
    int                  hmac_type;
    unsigned char        use_rijndael;
    int                  fw_access_timeout;
    int                  max_fw_timeout;
    unsigned char        enable_cmd_exec;
    unsigned char        enable_cmd_sudo_exec;
    char                *cmd_sudo_exec_user;
    char                *cmd_sudo_exec_group;
    uid_t                cmd_sudo_exec_uid;
    gid_t                cmd_sudo_exec_gid;
    char                *cmd_exec_user;
    char                *cmd_exec_group;
    char                *cmd_cycle_open;
    char                *cmd_cycle_close;
    unsigned char        cmd_cycle_do_close;
    int                  cmd_cycle_timer;
    uid_t                cmd_exec_uid;
    gid_t                cmd_exec_gid;
    char                *require_username;
    unsigned char        require_source_address;
    char                *gpg_home_dir;
    char                *gpg_exe;
    char                *gpg_decrypt_id;
    char                *gpg_decrypt_pw;
    unsigned char        gpg_require_sig;
    unsigned char        gpg_disable_sig;
    unsigned char        gpg_ignore_sig_error;
    unsigned char        use_gpg;
    unsigned char        gpg_allow_no_pw;
    char                *gpg_remote_id;
    acc_string_list_t   *gpg_remote_id_list;
    char                *gpg_remote_fpr;
    acc_string_list_t   *gpg_remote_fpr_list;
    time_t               access_expire_time;
    int                  expired;
    int                  encryption_mode;

    /* NAT parameters
    */
    unsigned char        force_nat;
    char                *force_nat_ip;
    char                *force_nat_proto;
    unsigned int         force_nat_port;
    unsigned char        forward_all;
    unsigned char        disable_dnat;
    unsigned char        force_snat;
    char                *force_snat_ip;
    unsigned char        force_masquerade;

    struct acc_stanza   *next;
} acc_stanza_t;

/* A simple linked list of strings for command open/close cycles
*/
//一个简单的链表，用于命令打开/关闭周期的字符串
typedef struct cmd_cycle_list
{
    char                    src_ip[MAX_IPV4_STR_LEN];
    char                   *close_cmd;
    time_t                  expire;
    int                     stanza_num;
    struct cmd_cycle_list  *next;
} cmd_cycle_list_t;

/* Firewall-related data and types. */
//防火墙相关数据和类型。
#if FIREWALL_FIREWALLD
  /* --DSS XXX: These are arbitrary. We should determine appropriate values.
  */
  #define MAX_TABLE_NAME_LEN      64
  #define MAX_CHAIN_NAME_LEN      64
  #define MAX_TARGET_NAME_LEN     64

  /* Fwknop custom chain types
  */
  enum {
      FIREWD_INPUT_ACCESS,
      FIREWD_OUTPUT_ACCESS,
      FIREWD_FORWARD_ACCESS,
      FIREWD_DNAT_ACCESS,
      FIREWD_SNAT_ACCESS,
      FIREWD_MASQUERADE_ACCESS,
      NUM_FWKNOP_ACCESS_TYPES  /* Leave this entry last */
  };

  /* Structure to define an fwknop firewall chain configuration.
  */
  struct fw_chain {
      int     type;
      char    target[MAX_TARGET_NAME_LEN];
      //int     direction;
      char    table[MAX_TABLE_NAME_LEN];
      char    from_chain[MAX_CHAIN_NAME_LEN];
      int     jump_rule_pos;
      char    to_chain[MAX_CHAIN_NAME_LEN];
      int     rule_pos;
      int     active_rules;
      time_t  next_expire;
  };

  /* Based on the fw_chain fields (not counting type)
  */
  #define FW_NUM_CHAIN_FIELDS 6

  struct fw_config {
      struct fw_chain chain[NUM_FWKNOP_ACCESS_TYPES];
      char            fw_command[MAX_PATH_LEN];

      /* Flag for setting destination field in rule
      */
      unsigned char   use_destination;
  };

#elif FIREWALL_IPTABLES
  /* --DSS XXX: These are arbitrary. We should determine appropriate values.
  */
  #define MAX_TABLE_NAME_LEN      64
  #define MAX_CHAIN_NAME_LEN      64
  #define MAX_TARGET_NAME_LEN     64

  /* Fwknop custom chain types
  */
  enum {
      IPT_INPUT_ACCESS,
      IPT_OUTPUT_ACCESS,
      IPT_FORWARD_ACCESS,
      IPT_DNAT_ACCESS,
      IPT_SNAT_ACCESS,
      IPT_MASQUERADE_ACCESS,
      NUM_FWKNOP_ACCESS_TYPES  /* Leave this entry last */
  };

  /* Structure to define an fwknop firewall chain configuration.
  */
  struct fw_chain {
      int     type;
      char    target[MAX_TARGET_NAME_LEN];
      //int     direction;
      char    table[MAX_TABLE_NAME_LEN];
      char    from_chain[MAX_CHAIN_NAME_LEN];
      int     jump_rule_pos;
      char    to_chain[MAX_CHAIN_NAME_LEN];
      int     rule_pos;
      int     active_rules;
      time_t  next_expire;
  };

  /* Based on the fw_chain fields (not counting type)
  */
  #define FW_NUM_CHAIN_FIELDS 6

  struct fw_config {
      struct fw_chain chain[NUM_FWKNOP_ACCESS_TYPES];
      char            fw_command[MAX_PATH_LEN];

      /* Flag for setting destination field in rule
      */
      unsigned char   use_destination;
  };

#elif FIREWALL_IPFW

  struct fw_config {
      unsigned short    start_rule_num;
      unsigned short    max_rules;
      unsigned short    active_rules;
      unsigned short    total_rules;
      unsigned short    active_set_num;
      unsigned short    expire_set_num;
      unsigned short    purge_interval;
      unsigned char    *rule_map;
      time_t            next_expire;
      time_t            last_purge;
      char              fw_command[MAX_PATH_LEN];
      unsigned char     use_destination;
  };

#elif FIREWALL_PF

  #define MAX_PF_ANCHOR_LEN 64

  struct fw_config {
      unsigned short    active_rules;
      time_t            next_expire;
      char              anchor[MAX_PF_ANCHOR_LEN];
      char              fw_command[MAX_PATH_LEN];
      unsigned char     use_destination;
  };

#elif FIREWALL_IPF

    /* --DSS Place-holder */

#endif /* FIREWALL type */

/* SPA Packet info struct.
*/
//SPA数据包信息结构。
typedef struct spa_pkt_info
{
    unsigned int    packet_data_len;
    unsigned int    packet_proto;
    unsigned int    packet_src_ip;
    unsigned int    packet_dst_ip;
    unsigned short  packet_src_port;
    unsigned short  packet_dst_port;
    unsigned char   packet_data[MAX_SPA_PACKET_LEN+1];
} spa_pkt_info_t;

/* Struct for (processed and verified) SPA data used by the server.
*/
//服务器使用的（已处理和验证的）SPA数据的结构。
typedef struct spa_data
{
    char           *username;
    time_t          timestamp;
    char           *version;
    short           message_type;
    char           *spa_message;
    char            spa_message_src_ip[MAX_IPV4_STR_LEN];
    char            pkt_source_ip[MAX_IPV4_STR_LEN];
    char            pkt_source_xff_ip[MAX_IPV4_STR_LEN];
    char            pkt_destination_ip[MAX_IPV4_STR_LEN];
    char            spa_message_remain[1024]; /* --DSS FIXME: arbitrary bounds */
    char           *nat_access;
    char           *server_auth;
    unsigned int    client_timeout;
    unsigned int    fw_access_timeout;
    char            *use_src_ip;
} spa_data_t;

/* fwknopd server configuration parameters and values
*/
//fwknopd服务器配置参数和值
typedef struct fko_srv_options
{
    /* The command-line options or flags that invoke an immediate response
     * then exit.
    */
   //调用立即响应然后退出的命令行选项或标志。
    unsigned char   dump_config;        /* Dump current configuration flag 转储当前配置标志*/
    unsigned char   foreground;         /* Run in foreground flag 在前台运行标志*/
    unsigned char   kill;               /* flag to initiate kill of fwknopd 启动fwknopd杀进程的标志*/
    unsigned char   rotate_digest_cache;/* flag to force rotation of digest 强制旋转摘要缓存的标志*/
    unsigned char   restart;            /* Restart fwknopd flag 重新启动fwknopd的标志*/
    unsigned char   status;             /* Get fwknopd status flag 获取fwknopd状态的标志*/
    unsigned char   fw_list;            /* List current firewall rules 列出当前防火墙规则的标志*/
    unsigned char   fw_list_all;        /* List all current firewall rules 列出所有当前防火墙规则的标志*/
    unsigned char   fw_flush;           /* Flush current firewall rules 清空当前防火墙规则的标志*/
    unsigned char   key_gen;            /* Generate keys and exit 生成密钥并退出的标志*/
    unsigned char   exit_after_parse_config; /* Parse config and exit 解析配置并退出的标志*/
    unsigned char   exit_parse_digest_cache; /* Parse digest cache and exit 解析摘要缓存并退出的标志*/

    /* Operational flags
    */
    unsigned char   test;               /* Test mode flag 测试模式标志*/
    unsigned char   afl_fuzzing;        /* SPA pkts from stdin for AFL fuzzing 用于AFL模糊测试的SPA数据包标志*/
    unsigned char   verbose;            /* Verbose mode flag 详细模式标志*/
    unsigned char   enable_udp_server;  /* Enable UDP server mode 启用UDP服务器模式的标志*/
    unsigned char   enable_nfq_capture; /* Enable Netfilter Queue capture mode 启用Netfilter队列捕获模式的标志*/
    unsigned char   enable_fw;          /* Command modes by themselves don't
                                           need firewall support. 仅命令模式本身不需要防火墙支持的标志*/

    unsigned char   firewd_disable_check_support; /* Don't use firewall-cmd ... -C 不使用firewall-cmd ... -C的标志*/
    unsigned char   ipt_disable_check_support;    /* Don't use iptables -C 不使用iptables -C的标志*/

    /* Flag for permitting SPA packets regardless of directionality test
     * w.r.t. the sniffing interface.  This can sometimes be useful for SPA
     * packets that are sent _through_ a system and fwknopd is sniffing on
     * the outbound interface as far as these packets are concerned.
     * 用于允许SPA数据包的标志，无论嗅探接口的方向性测试如何。
     * 对于通过系统发送的SPA数据包，fwknopd在这些数据包的角度看出站接口上嗅探时，有时会很有用。
    */
    unsigned char   pcap_any_direction;

    int             data_link_offset;
    int             tcp_server_pid;
    int             lock_fd;

    /* Values used in --key-gen mode only
     * 仅在--key-gen模式下使用的值
    */
    char key_gen_file[MAX_PATH_LEN];
    int  key_len;
    int  hmac_key_len;
    int  hmac_type;

#if USE_FILE_CACHE
    struct digest_cache_list *digest_cache;   /* In-memory digest cache list */
#endif

    spa_pkt_info_t  spa_pkt;            /* The current SPA packet 当前的 SPA 数据包信息*/

    /* Counter set from the command line to exit after the specified
     * number of SPA packets are processed.
     *从命令行设置的计数器，用于在处理指定数量的 SPA 数据包后退出。
    */
    unsigned int    packet_ctr_limit;
    unsigned int    packet_ctr;  /* counts packets with >0 payload bytes 统计有效载荷字节数大于 0 的数据包*/

    /* This array holds all of the config file entry values as strings
     * indexed by their tag name.
     *这个数组保存所有配置文件条目的值，使用标签名作为索引。
    */
    char           *config[NUMBER_OF_CONFIG_ENTRIES];

    /* Data elements that are derived from configuration entries - avoids
     * calling strtol_wrapper() after the config is parsed.
     *从配置条目中派生出来的数据元素，避免在配置解析后再调用 strtol_wrapper()。
    */
    unsigned short tcpserv_port;
    unsigned short udpserv_port;
    int            udpserv_select_timeout;
    int            rules_chk_threshold;
    int            pcap_loop_sleep;
    int            pcap_dispatch_count;
    int            max_sniff_bytes;
    int            max_spa_packet_age;

    acc_stanza_t   *acc_stanzas;       /* List of access stanzas 访问配置段的链表*/

    /* Firewall config info.
    * 防火墙配置信息
    */
    struct fw_config *fw_config;

    /* Rule checking counter - this is for garbage cleanup mode to remove
     * any rules with an expired timer (even those that may have been
     * added by a third-party program).
     * 规则检查计数器 - 用于垃圾清理模式，
     * 删除任何已过期计时器的规则（甚至可能由第三方程序添加的规则）。
     * 
    */
    unsigned int check_rules_ctr;

    /* Track external command execution cycles (track source IP, access.conf
     * stanza number, and instantiation time).
     * 跟踪外部命令执行周期（跟踪源 IP、access.conf 配置段编号和实例化时间）。
    */
    cmd_cycle_list_t *cmd_cycle_list;

    /* Set to 1 when messages have to go through syslog, 0 otherwise 
    *  当消息必须通过 syslog 时设置为 1，否则为 0。 
    */
    unsigned char   syslog_enable;

} fko_srv_options_t;

/* For cleaning up memory before exiting
*/
#define FW_CLEANUP          1
#define NO_FW_CLEANUP       0

/**
 * \brief Frees all memory and exits
 *
 * \param opts Program options
 * \param fw_cleanup_flag Flag indicates whether firewall needs cleanup
 * \param exit_status Exit status to return when closing the program
 *
 */
void clean_exit(fko_srv_options_t *opts,
        unsigned int fw_cleanup_flag, unsigned int exit_status);

#endif /* FWKNOPD_COMMON_H */

/***EOF***/
