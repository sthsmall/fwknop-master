/**
 * \file    client/fwknop.c
 *
 * \brief   The fwknop client.
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
 */
//本文件头文件

//本文件头文件


#include "fwknop.h"
//设置初始化
#include "config_init.h"
//导入spa包读写操作
#include "spa_comm.h"
//导入工具头文件
#include "utils.h"
//提供了从文件读取密钥的函数
#include "getpasswd.h"


//文件状态和文件控制
#include <sys/stat.h>
#include <fcntl.h>


/* prototypes
*/

// get_keys: 用于获取密钥，包括加密密钥和 HMAC 密钥。
static int get_keys(fko_ctx_t ctx, fko_cli_options_t *options,
    char *key, int *key_len, char *hmac_key, int *hmac_key_len);

// errmsg: 用于输出错误消息。
static void errmsg(const char *msg, const int err);
// prev_exec: 用于执行保存的最后一个命令，函数内部判断是否执行最后一个保存的命令，是否将命令行参数展示，是否保存当前的命令。
static int prev_exec(fko_cli_options_t *options, int argc, char **argv);
// get_save_file: 获取不同操作系统默认的保存文件路径。
static int get_save_file(char *args_save_file);
// show_last_command: 用于显示最后一条命令。
static int show_last_command(const char * const args_save_file);
// save_args: 用于保存命令行参数。
static int save_args(int argc, char **argv, const char * const args_save_file);
// run_last_args: 从上一次调用中获取命令行参数
static int run_last_args(fko_cli_options_t *options,
        const char * const args_save_file);
// set_message_type: 用于设置消息类型。
static int set_message_type(fko_ctx_t ctx, fko_cli_options_t *options);
// set_nat_access: 用于设置 NAT 访问。
static int set_nat_access(fko_ctx_t ctx, fko_cli_options_t *options,
        const char * const access_buf);
// set_access_buf: 用于设置访问缓冲区。
static int set_access_buf(fko_ctx_t ctx, fko_cli_options_t *options,
        char *access_buf);
// get_rand_port: 用于获取随机端口。
static int get_rand_port(fko_ctx_t ctx);
// resolve_ip_https: 用于解析 HTTPS IP 地址。
int resolve_ip_https(fko_cli_options_t *options);
// resolve_ip_http: 用于解析 HTTP IP 地址。
int resolve_ip_http(fko_cli_options_t *options);
// clean_exit: 用于清理并退出程序。
static void clean_exit(fko_ctx_t ctx, fko_cli_options_t *opts,
    char *key, int *key_len, char *hmac_key, int *hmac_key_len,
    unsigned int exit_status);
// zero_buf_wrapper: 用于将缓冲区清零。
static void zero_buf_wrapper(char *buf, int len);


/*
这段代码是一个条件编译块，用于判断是否启用了libfiu库，并定义了一个名为enable_fault_injections的函数。

根据条件编译宏HAVE_LIBFIU来确定是否启用了libfiu库。如果启用了该库，则进入条件编译块。

在函数内部，定义了一个名为enable_fault_injections的函数，该函数接受一个指向fko_cli_options_t类型的指针作为参数，
并返回一个整数值。

该函数的具体实现需要根据上下文中给出的代码内容进行补充，因为当前代码中只有函数的声明，没有给出具体的实现内容。

该函数的作用是在启用了libfiu库的情况下，根据传入的opts参数来进行故障注入的设置或配置。
具体的实现需要根据代码中其他部分的逻辑来确定。

*/
#if HAVE_LIBFIU
static int enable_fault_injections(fko_cli_options_t * const opts);
#endif


/*
这段代码是一个条件编译块，用于在AFL模糊测试模式下定义两个常量。如果定义了宏AFL_FUZZING，则进入条件编译块。

在条件编译块内部，定义了两个常量：

    AFL_ENC_KEY：表示AFL模糊测试模式下使用的加密密钥，其取值为字符串"aflenckey"。
    AFL_HMAC_KEY：表示AFL模糊测试模式下使用的HMAC密钥，其取值为字符串"aflhmackey"。

这些常量的作用是在AFL模糊测试模式下使用固定的密钥和HMAC密钥，以确保每次模糊测试循环时都使用相同的密钥，
避免因密钥变动而导致不一致的测试结果。
*/
#if AFL_FUZZING
  /* These are used in AFL fuzzing mode so the fuzzing cycle is not
   * interrupted by trying to read from stdin
  */
  #define AFL_ENC_KEY               "aflenckey"
  #define AFL_HMAC_KEY              "aflhmackey"
#endif

/*
这段代码定义了三个宏常量：

    NAT_ACCESS_STR_TEMPLATE：表示一个用于解析NAT访问字符串(ip地址和端口)的模板，
    使用sscanf函数。其取值为"%s,%d"，其中%s表示字符串，%d表示整数。

    HOSTNAME_BUFSIZE：表示主机名字符串的最大长度，其取值为64。

    CTX_DUMP_BUFSIZE：表示用于FKO上下文转储的最大缓冲区大小，其取值为4096。

这些宏常量用于在代码中指定特定的字符串模板和缓冲区大小，以便在编译时进行预定义和统一控制。
这样可以提高代码的可读性和维护性，并且能够方便地对字符串和缓冲区大小进行修改。

*/
#define NAT_ACCESS_STR_TEMPLATE     "%s,%d"             /*!< Template for a nat access string ip,port with sscanf*/
#define HOSTNAME_BUFSIZE            64                  /*!< Maximum size of a hostname string */
#define CTX_DUMP_BUFSIZE            4096                /*!< Maximum size allocated to a FKO context dump */

int
main(int argc, char **argv)
{   
    /*
    这段代码声明了一些变量和数组：

    fko_ctx_t ctx = NULL; 和 fko_ctx_t ctx2 = NULL;：声明了两个类型为 fko_ctx_t 的变量 ctx 和 ctx2，
    并将其初始化为 NULL。这些变量可能是用于表示 FK0 上下文的指针。

    int res;：声明了一个名为 res 的整型变量，用于存储函数调用的返回值。

    char *spa_data=NULL, *version=NULL;：声明了两个字符指针变量 spa_data 和 version，
    并将它们初始化为 NULL。这些变量可能用于存储字符串数据。

    char access_buf[MAX_LINE_LEN] = {0};：声明了一个字符数组 access_buf，长度为 MAX_LINE_LEN，
    并将其所有元素初始化为 0。这个数组可能用于存储访问缓冲区的数据。

    char key[MAX_KEY_LEN+1] = {0}; 和 char hmac_key[MAX_KEY_LEN+1] = {0};：
    声明了两个字符数组 key 和 hmac_key，长度为 MAX_KEY_LEN+1，并将其所有元素初始化为 0。
    这些数组可能用于存储密钥或密码相关的数据。

    int key_len = 0, orig_key_len = 0, hmac_key_len = 0, enc_mode;：
    声明了四个整型变量 key_len、orig_key_len、hmac_key_len 和 enc_mode，
    并分别初始化为 0。这些变量可能用于存储长度或加密模式等相关信息。

    int tmp_port = 0;：声明了一个整型变量 tmp_port，并初始化为 0。这个变量可能用于存储临时的端口号。

    char dump_buf[CTX_DUMP_BUFSIZE];：声明了一个字符数组 dump_buf，长度为 CTX_DUMP_BUFSIZE，
    用于存储 FK0 上下文转储的数据。

    */
    //用于保存发送消息  
    fko_ctx_t           ctx  = NULL; //fkocontext的指针
    fko_ctx_t           ctx2 = NULL;
    int                 res; //用于判断函数调用是否成功
    char               *spa_data=NULL, *version=NULL; //用于存储SPA数据和版本信息
    char                access_buf[MAX_LINE_LEN] = {0}; //存储访问控制规则
    char                key[MAX_KEY_LEN+1]       = {0}; //存储加密密钥
    char                hmac_key[MAX_KEY_LEN+1]  = {0}; //HMAC密钥
    int                 key_len = 0, orig_key_len = 0, hmac_key_len = 0, enc_mode; //存储密钥的长度、加密模式
    int                 tmp_port = 0; //存储临时端口
    char                dump_buf[CTX_DUMP_BUFSIZE];

    //这个结构体用于保存命令行参数
    fko_cli_options_t   options;

    memset(&options, 0x0, sizeof(fko_cli_options_t));
    //初始化消息模块
    /* Initialize the log module */
    log_new();
    //处理命令行  
    /* Handle command line
    */
    config_init(&options, argc, argv);

/*
这段代码是一个条件编译的代码块，当宏定义 HAVE_LIBFIU 存在时执行。它用于设置故障注入点。

在这段代码中，首先调用 enable_fault_injections(&options) 函数来设置故障注入点，
&options 是一个选项结构体的指针。如果故障注入点设置失败，那么会调用 clean_exit() 函数进行清理操作，
传递了一些参数，包括 ctx 上下文指针、options 选项结构体指针、key 和 hmac_key 密钥相关的数据指针，
以及退出状态码 EXIT_FAILURE。

换句话说，该代码块用于在程序运行时通过故障注入来测试和模拟异常情况，以验证程序的稳定性和鲁棒性。
这通常用于调试和测试目的。

*/
#if HAVE_LIBFIU
        /* Set any fault injection points early
        */
        if(! enable_fault_injections(&options))
            clean_exit(ctx, &options, key, &key_len, hmac_key,
                    &hmac_key_len, EXIT_FAILURE);
#endif

    /* Handle previous execution arguments if required
    */
   //处理之前的执行参数
    if(prev_exec(&options, argc, argv) != 1)
        clean_exit(ctx, &options, key, &key_len, hmac_key,
                &hmac_key_len, EXIT_FAILURE);

    if(options.show_last_command) //显示 fwknop 使用的最后一个命令行参数
        clean_exit(ctx, &options, key, &key_len, hmac_key,
                &hmac_key_len, EXIT_SUCCESS);

    /* Intialize the context
    */
   //初始化数据包       
    res = fko_new(&ctx);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_new", res);
        clean_exit(ctx, &options, key, &key_len, hmac_key,
                &hmac_key_len, EXIT_FAILURE);
    }       

    /* Display version info and exit.
    */
   //显示版本信息
    if(options.version)
    {
        fko_get_version(ctx, &version);

        fprintf(stdout, "fwknop client %s, FKO protocol version %s\n",
            MY_VERSION, version);

        clean_exit(ctx, &options, key, &key_len,
            hmac_key, &hmac_key_len, EXIT_SUCCESS);
    }

    /* Set client timeout
    */
   //设置超时时间
    if(options.fw_timeout >= 0)
    {
        res = fko_set_spa_client_timeout(ctx, options.fw_timeout);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_client_timeout", res);
            clean_exit(ctx, &options, key, &key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
    }

    /* Set the SPA packet message type based on command line options
    */
   //设置spa消息类型基于命令行选项
    res = set_message_type(ctx, &options);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_set_spa_message_type", res);
        clean_exit(ctx, &options, key, &key_len,
            hmac_key, &hmac_key_len, EXIT_FAILURE);
    }

    /* Adjust the SPA timestamp if necessary
    */
   //调整spa时间戳
    if(options.time_offset_plus > 0)
    {
        res = fko_set_timestamp(ctx, options.time_offset_plus);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_timestamp", res);
            clean_exit(ctx, &options, key, &key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
    }
    if(options.time_offset_minus > 0)
    {
        res = fko_set_timestamp(ctx, -options.time_offset_minus);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_timestamp", res);
            clean_exit(ctx, &options, key, &key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
    }

    if(options.server_command[0] != 0x0)
    {
        /* Set the access message to a command that the server will
         * execute
        */
       //设置访问消息到服务器将执行的命令
        snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
                options.allow_ip_str, ",", options.server_command);
    }
    else
    {
        /* Resolve the client's public facing IP address if requestesd.
         * if this fails, consider it fatal.
        */
       //解析客户端的公网ip地址
        if (options.resolve_ip_http_https)
        {
            if(options.resolve_http_only)
            {
                if(resolve_ip_http(&options) < 0)
                {
                    clean_exit(ctx, &options, key, &key_len,
                        hmac_key, &hmac_key_len, EXIT_FAILURE);
                }
            }
            else
            {
                /* Default to HTTPS */
                if(resolve_ip_https(&options) < 0)
                {
                    clean_exit(ctx, &options, key, &key_len,
                        hmac_key, &hmac_key_len, EXIT_FAILURE);
                }
            }
        }

        /* Set a message string by combining the allow IP and the
         * port/protocol.  The fwknopd server allows no port/protocol
         * to be specified as well, so in this case append the string
         * "none/0" to the allow IP.
        */
       //设置消息字符串通过结合允许ip和端口/协议
       //fwknopd服务器允许没有端口/协议指定以及，所以在这种情况下附加字符串“none/0”到允许ip

        if(set_access_buf(ctx, &options, access_buf) != 1)
            clean_exit(ctx, &options, key, &key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
    }
    //设置spa消息
    res = fko_set_spa_message(ctx, access_buf);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_set_spa_message", res);
        clean_exit(ctx, &options, key, &key_len,
            hmac_key, &hmac_key_len, EXIT_FAILURE);
    }

    /* Set NAT access string
    */
   //设置nat访问字符串
    if (options.nat_local || options.nat_access_str[0] != 0x0)
    {
        res = set_nat_access(ctx, &options, access_buf);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_nat_access_str", res);
            clean_exit(ctx, &options, key, &key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
    }

    /* Set username
    */
   //设置用户名
    if(options.spoof_user[0] != 0x0)
    {
        res = fko_set_username(ctx, options.spoof_user);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_username", res);
            clean_exit(ctx, &options, key, &key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
    }

    /* Set up for using GPG if specified.
    
    */
   //设置使用gpg
   /*
   * 在软件开发或配置中，GPG 是一种常用的加密和签名工具，
   * 用于保护敏感信息和验证数据的完整性。
   * 如果在特定的设置或配置中明确指定要使用 GPG，
   * 那么相应的操作或流程需要进行适当的 GPG 设置，
   * 以确保正确地使用 GPG 加密、解密或签名等功能。
   */
    if(options.use_gpg)
    {
        /* If use-gpg-agent was not specified, then remove the GPG_AGENT_INFO
         * ENV variable if it exists.
        */
#ifndef WIN32
        if(!options.use_gpg_agent)
            unsetenv("GPG_AGENT_INFO");
#endif

        res = fko_set_spa_encryption_type(ctx, FKO_ENCRYPTION_GPG); //设置spa加密模式，例如对称加密，此时加密模式为2
        if(res != FKO_SUCCESS) //报错
        {
            errmsg("fko_set_spa_encryption_type", res);
            clean_exit(ctx, &options, key, &key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
        }

        /* Set gpg path if necessary
        */
       //设置gpb的可执行文件的路径
        if(strlen(options.gpg_exe) > 0)
        {
            res = fko_set_gpg_exe(ctx, options.gpg_exe);
            if(res != FKO_SUCCESS)
            {
                errmsg("fko_set_gpg_exe", res);
                clean_exit(ctx, &options, key, &key_len,
                        hmac_key, &hmac_key_len, EXIT_FAILURE);
            }
        }

        /* If a GPG home dir was specified, set it here.  Note: Setting
         * this has to occur before calling any of the other GPG-related
         * functions.
        */
       //如果已经指定了gpg的主目录，使用指定的主目录
        if(strlen(options.gpg_home_dir) > 0)
        {
            res = fko_set_gpg_home_dir(ctx, options.gpg_home_dir);
            if(res != FKO_SUCCESS)
            {
                errmsg("fko_set_gpg_home_dir", res);
                clean_exit(ctx, &options, key, &key_len,
                        hmac_key, &hmac_key_len, EXIT_FAILURE);
            }
        }
        //设置GPG加密的收件人，并获取相应的GPG密钥
        res = fko_set_gpg_recipient(ctx, options.gpg_recipient_key);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_gpg_recipient", res);

            if(IS_GPG_ERROR(res))
                log_msg(LOG_VERBOSITY_ERROR, "GPG ERR: %s", fko_gpg_errstr(ctx));
            clean_exit(ctx, &options, key, &key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
        }

        if(strlen(options.gpg_signer_key) > 0)
        {
            //设置签名者密钥
            res = fko_set_gpg_signer(ctx, options.gpg_signer_key);
            if(res != FKO_SUCCESS)
            {
                errmsg("fko_set_gpg_signer", res);

                if(IS_GPG_ERROR(res))
                    log_msg(LOG_VERBOSITY_ERROR, "GPG ERR: %s", fko_gpg_errstr(ctx));
                clean_exit(ctx, &options, key, &key_len,
                        hmac_key, &hmac_key_len, EXIT_FAILURE);
            }
        }

        //设置SPA数据包加密格式，这种格式是指用哪种加密算法，例如AES、DES等
        res = fko_set_spa_encryption_mode(ctx, FKO_ENC_MODE_ASYMMETRIC);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_encryption_mode", res);
            clean_exit(ctx, &options, key, &key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
    }
    //如果加密模式存在且不使用gpg加密数据
    if(options.encryption_mode && !options.use_gpg)
    {
        //直接设置SPA加密格式
        res = fko_set_spa_encryption_mode(ctx, options.encryption_mode);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_encryption_mode", res);
            clean_exit(ctx, &options, key, &key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
    }

    /* Set Digest type.
    */
   //设置摘要类型
    if(options.digest_type)
    {
        res = fko_set_spa_digest_type(ctx, options.digest_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_digest_type", res);
            clean_exit(ctx, &options, key, &key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
    }

    /* Acquire the necessary encryption/hmac keys
    */
   //获取加密和hmac密钥
    if(get_keys(ctx, &options, key, &key_len, hmac_key, &hmac_key_len) != 1)
        clean_exit(ctx, &options, key, &key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);

    orig_key_len = key_len;
    
    //判断加密格式和密钥格式有没有是否符合要求
    if(options.encryption_mode == FKO_ENC_MODE_CBC_LEGACY_IV
            && key_len > 16)
    {
        log_msg(LOG_VERBOSITY_ERROR,
                "WARNING: Encryption key in '-M legacy' mode must be <= 16 bytes");
        log_msg(LOG_VERBOSITY_ERROR,
                "long - truncating before sending SPA packet. Upgrading remote");
        log_msg(LOG_VERBOSITY_ERROR,
                "fwknopd is recommended.");
        key_len = 16;
    }

    /* Finalize the context data (encrypt and encode the SPA data)
    */
   //最终化上下文数据（加密和编码SPA数据）
    res = fko_spa_data_final(ctx, key, key_len, hmac_key, hmac_key_len);
    if(res != FKO_SUCCESS)
    {
        errmsg("fko_spa_data_final", res);

        if(IS_GPG_ERROR(res))
            log_msg(LOG_VERBOSITY_ERROR, "GPG ERR: %s", fko_gpg_errstr(ctx));
        clean_exit(ctx, &options, key, &orig_key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
    }

    /* Display the context data.
    */
   //显示上下文数据
    if (options.verbose || options.test)
    {
        res = dump_ctx_to_buffer(ctx, dump_buf, sizeof(dump_buf));
        if (res == FKO_SUCCESS)
            log_msg(LOG_VERBOSITY_NORMAL, "%s", dump_buf);
        else
            log_msg(LOG_VERBOSITY_WARNING, "Unable to dump FKO context: %s",
                    fko_errstr(res));
    }

    /* Save packet data payload if requested.
    */
   //如果请求，保存数据包数据负载。
    if (options.save_packet_file[0] != 0x0)
        write_spa_packet_data(ctx, &options);

    /* SPA packet random destination port handling
    */
   //SPA数据包随机目标端口处理
    if (options.rand_port)
    {
        tmp_port = get_rand_port(ctx);
        if(tmp_port < 0)
            clean_exit(ctx, &options, key, &orig_key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
        options.spa_dst_port = tmp_port;
    }

    /* If we are using one the "raw" modes (normally because
     * we're going to spoof the SPA packet source IP), then select
     * a random source port unless the source port is already set
    */
   //如果我们使用“原始”模式之一（通常是因为我们要欺骗SPA数据包源IP），则选择随机源端口，除非源端口已经设置

    if ((options.spa_proto == FKO_PROTO_TCP_RAW
            || options.spa_proto == FKO_PROTO_UDP_RAW
            || options.spa_proto == FKO_PROTO_ICMP)
            && !options.spa_src_port)
    {
        //获取随机端口
        tmp_port = get_rand_port(ctx);
        if(tmp_port < 0)
            clean_exit(ctx, &options, key, &orig_key_len,
                    hmac_key, &hmac_key_len, EXIT_FAILURE);
        options.spa_src_port = tmp_port;
    }
    //发送SPA数据包
    res = send_spa_packet(ctx, &options);
    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet: packet not sent.");
        clean_exit(ctx, &options, key, &orig_key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
    }
    else
    {
        log_msg(LOG_VERBOSITY_INFO, "send_spa_packet: bytes sent: %i", res);
    }

    /* Run through a decode cycle in test mode (--DSS XXX: This test/decode
     * portion should be moved elsewhere).
    */
   //在测试模式下运行解码周期（-DSS XXX：此测试/解码部分应移至其他位置）。
    if (options.test)
    {
        /************** Decoding now *****************/

        /* Now we create a new context based on data from the first one.
        */
       //现在，我们根据第一个上下文中的数据创建一个新的内容。
        res = fko_get_spa_data(ctx, &spa_data);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_get_spa_data", res);
            clean_exit(ctx, &options, key, &orig_key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
        }

        /* Pull the encryption mode.
        */
       //获取加密模式
        res = fko_get_spa_encryption_mode(ctx, &enc_mode);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_get_spa_encryption_mode", res);
            if(fko_destroy(ctx) == FKO_ERROR_ZERO_OUT_DATA)
                log_msg(LOG_VERBOSITY_ERROR,
                        "[*] Could not zero out sensitive data buffer.");
            ctx = NULL;
            clean_exit(ctx, &options, key, &orig_key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
        }

        /* If gpg-home-dir is specified, we have to defer decrypting if we
         * use the fko_new_with_data() function because we need to set the
         * gpg home dir after the context is created, but before we attempt
         * to decrypt the data.  Therefore we either pass NULL for the
         * decryption key to fko_new_with_data() or use fko_new() to create
         * an empty context, populate it with the encrypted data, set our
         * options, then decode it.
         *
         * This also verifies the HMAC and truncates it if there are no
         * problems.
        */
    //    如果指定了gpg-home-dir，则必须推迟解密，如果我们使用fko_new_with_data（）函数，
    //    因为我们需要设置gpg home dir在上下文创建之后，但在我们尝试解密数据之前。因此
    //    ，我们要么传递NULL用于解密密钥fko_new_with_data（），要么使用fko_new（）创建一个空上下文
    //    ，用加密数据填充它，设置选项，然后解码它。这也验证HMAC并在没有问题的情况下截断它。
        res = fko_new_with_data(&ctx2, spa_data, NULL,
            0, enc_mode, hmac_key, hmac_key_len, options.hmac_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_new_with_data", res);
            if(fko_destroy(ctx2) == FKO_ERROR_ZERO_OUT_DATA)
                log_msg(LOG_VERBOSITY_ERROR,
                        "[*] Could not zero out sensitive data buffer.");
            ctx2 = NULL;
            clean_exit(ctx, &options, key, &orig_key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
        //设置加密模式
        res = fko_set_spa_encryption_mode(ctx2, enc_mode);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_encryption_mode", res);
            if(fko_destroy(ctx2) == FKO_ERROR_ZERO_OUT_DATA)
                log_msg(LOG_VERBOSITY_ERROR,
                        "[*] Could not zero out sensitive data buffer.");
            ctx2 = NULL;
            clean_exit(ctx, &options, key, &orig_key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
        }

        /* See if we are using gpg and if we need to set the GPG home dir.
        */
       //如果使用gpg加密
        if(options.use_gpg)
        {
            //自定义了gpg主目录
            if(strlen(options.gpg_home_dir) > 0)
            {
                //给ctx2设置gpg主目录
                res = fko_set_gpg_home_dir(ctx2, options.gpg_home_dir);
                if(res != FKO_SUCCESS)
                {
                    errmsg("fko_set_gpg_home_dir", res);
                    if(fko_destroy(ctx2) == FKO_ERROR_ZERO_OUT_DATA)
                        log_msg(LOG_VERBOSITY_ERROR,
                                "[*] Could not zero out sensitive data buffer.");
                    ctx2 = NULL;
                    clean_exit(ctx, &options, key, &orig_key_len,
                        hmac_key, &hmac_key_len, EXIT_FAILURE);
                }
            }
        }

        /* Decrypt
        解密
        */
        res = fko_decrypt_spa_data(ctx2, key, key_len);

        if(res != FKO_SUCCESS)
        {
            errmsg("fko_decrypt_spa_data", res);

            if(IS_GPG_ERROR(res)) {
                /* we most likely could not decrypt the gpg-encrypted data
                 * because we don't have access to the private key associated
                 * with the public key we used for encryption.  Since this is
                 * expected, return 0 instead of an error condition (so calling
                 * programs like the fwknop test suite don't interpret this as
                 * an unrecoverable error), but print the error string for
                 * debugging purposes. The test suite does run a series of
                 * tests that use a single key pair for encryption and
                 * authentication, so decryption become possible for these
                 * tests. */
                //我们最有可能无法解密gpg加密的数据，因为我们没有访问与用于加密的公钥相关联的私钥。
                //由于这是预期的，返回0而不是错误条件（因此调用程序如fwknop测试套件不会将其解释为不可恢复的错误），
                //但打印错误字符串以进行调试目的。测试套件确实运行一系列使用单个密钥对进行加密和身份验证的测试，
                //因此对于这些测试，解密变得可能。

                log_msg(LOG_VERBOSITY_ERROR, "GPG ERR: %s\n%s", fko_gpg_errstr(ctx2),
                    "No access to recipient private key?");
            }
            if(fko_destroy(ctx2) == FKO_ERROR_ZERO_OUT_DATA)
                log_msg(LOG_VERBOSITY_ERROR,
                        "[*] Could not zero out sensitive data buffer.");
            ctx2 = NULL;
            clean_exit(ctx, &options, key, &orig_key_len,
                hmac_key, &hmac_key_len, EXIT_FAILURE);
        }
        /* Only dump out the SPA data after the test in verbose mode */
        if (options.verbose) {
            res = dump_ctx_to_buffer(ctx2, dump_buf, sizeof(dump_buf));
            if (res == FKO_SUCCESS)
                log_msg(LOG_VERBOSITY_NORMAL, "\nDump of the Decoded Data\n%s", dump_buf);
            else
                log_msg(LOG_VERBOSITY_WARNING, "Unable to dump FKO context: %s", fko_errstr(res));
        }

        if(fko_destroy(ctx2) == FKO_ERROR_ZERO_OUT_DATA)
            log_msg(LOG_VERBOSITY_ERROR,
                    "[*] Could not zero out sensitive data buffer.");
        ctx2 = NULL;
    }

    clean_exit(ctx, &options, key, &orig_key_len,
            hmac_key, &hmac_key_len, EXIT_SUCCESS);

    return EXIT_SUCCESS;  /* quiet down a gcc warning */
}
/**
 * 这是一个名为 free_configs 的函数，用于释放 fko_cli_options_t 结构体中的资源。

具体的操作包括：

    检查 opts->resolve_url 是否为 NULL，如果不为 NULL，则调用 free 函数释放该指针指向的内存。

    检查 opts->wget_bin 是否为 NULL，如果不为 NULL，则调用 free 函数释放该指针指向的内存。

    调用 zero_buf_wrapper 函数将 opts->key 数组中的数据清零，这里假设 zero_buf_wrapper 
    函数的作用是将指定的缓冲区清零。

    类似地，使用 zero_buf_wrapper 函数将 opts->key_base64、opts->hmac_key、
    opts->hmac_key_base64、opts->gpg_recipient_key、opts->gpg_signer_key、
    opts->gpg_home_dir 和 opts->server_command 对应的缓冲区数据清零。

这段代码的目的是在释放 fko_cli_options_t 结构体之前，确保相关的指针和数组内容被正确清理和释放，
以避免内存泄漏和悬挂指针的问题。

 * 
*/
void
free_configs(fko_cli_options_t *opts)
{
    if (opts->resolve_url != NULL)
        free(opts->resolve_url);
    if (opts->wget_bin != NULL)
        free(opts->wget_bin);
    zero_buf_wrapper(opts->key, MAX_KEY_LEN+1);
    zero_buf_wrapper(opts->key_base64, MAX_B64_KEY_LEN+1);
    zero_buf_wrapper(opts->hmac_key, MAX_KEY_LEN+1);
    zero_buf_wrapper(opts->hmac_key_base64, MAX_B64_KEY_LEN+1);
    zero_buf_wrapper(opts->gpg_recipient_key, MAX_GPG_KEY_ID);
    zero_buf_wrapper(opts->gpg_signer_key, MAX_GPG_KEY_ID);
    zero_buf_wrapper(opts->gpg_home_dir, MAX_PATH_LEN);
    zero_buf_wrapper(opts->server_command, MAX_LINE_LEN);
}
/*
这是一个名为 get_rand_port 的函数，用于获取一个随机的端口号。

具体的操作包括：

    声明了一个字符串指针 rand_val 并将其初始化为 NULL，声明了一个字符数组 port_str 并将其初始化为全零。

    声明了一些整型变量 tmpint、is_err、port 和 res，并初始化为 0。

    调用 fko_get_rand_value 函数获取一个随机值并将结果保存在 rand_val 中，
    同时将返回值保存在 res 中。如果返回值不等于 FKO_SUCCESS，则输出错误信息并返回 -1。

    使用 strlcpy 函数将 rand_val 复制到 port_str 中，确保复制的长度不超过 port_str 数组的大小。

    使用 strtol_wrapper 函数将 port_str 转换成整数型值并保存在 tmpint 中，
    同时将返回值保存在 is_err 中。如果 is_err 不等于 FKO_SUCCESS，则输出错误信息并返回 -1。

    将 tmpint 对应的端口号转换成一个介于 1024 和 65535 之间的随机值，并保存在 port 中。

    使用 fko_set_rand_value 函数将 ctx 中的随机值设为 NULL，以确保下次调用时会生成一个新的随机值。
    同时将返回值保存在 res 中。如果返回值不等于 FKO_SUCCESS，则输出错误信息并返回 -1。

    返回获取到的随机端口号 port。

这段代码的目的是获取一个随机的端口号，并确保每次调用 get_rand_port 函数时都能获得不同的随机值，
以增加安全性和保护 SPA 数据的加密内容。

*/
static int
get_rand_port(fko_ctx_t ctx)
{
    char *rand_val = NULL;
    char  port_str[MAX_PORT_STR_LEN+1] = {0};
    int   tmpint, is_err;
    int   port     = 0;
    int   res      = 0;

    res = fko_get_rand_value(ctx, &rand_val);
    if(res != FKO_SUCCESS)
    {
        errmsg("get_rand_port(), fko_get_rand_value", res);
        return -1;
    }

    strlcpy(port_str, rand_val, sizeof(port_str));

    tmpint = strtol_wrapper(port_str, 0, -1, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "[*] get_rand_port(), could not convert rand_val str '%s', to integer",
            rand_val);
        return -1;
    }

    /* Convert to a random value between 1024 and 65535
    */
    port = (MIN_HIGH_PORT + (tmpint % (MAX_PORT - MIN_HIGH_PORT)));

    /* Force libfko to calculate a new random value since we don't want to
     * give anyone a hint (via the port value) about the contents of the
     * encrypted SPA data.
    */
    res = fko_set_rand_value(ctx, NULL);
    if(res != FKO_SUCCESS)
    {
        errmsg("get_rand_port(), fko_get_rand_value", res);
        return -1;
    }

    return port;
}

/* Set access buf
*/
/**
 这是一个名为 set_access_buf 的静态函数，用于设置访问缓冲区。

具体的操作包括：

    声明了一些局部变量，包括指针 ndx，字符数组 tmp_nat_port（长度为 MAX_PORT_STR_LEN+1），
    整型变量 nat_port。并将 tmp_nat_port 数组初始化为全零。

    首先检查 options->access_str 是否不为空。如果不为空，进入条件语句。

    在选项 options 中判断是否启用了随机端口模式 nat_rand_port。如果是，
    则调用 get_rand_port 函数获取一个随机端口号，并将结果保存在 nat_port 中；
    同时将 nat_port 的值赋给 options->nat_port。如果没有启用随机端口模式，
    则判断 options->nat_port 是否非零，如果非零，则将值赋给 nat_port。

    判断 nat_port 的值是否在有效的端口范围内（大于0且小于等于 MAX_PORT）。
    如果是，则进行下一步操作；否则，将 access_buf 设置为包含 options->allow_ip_str、
    逗号和 options->access_str 的字符串，然后返回 1。

    使用 strchr 函数在 options->access_str 中查找字符 '/' 的位置，并将结果保存在 ndx 中。
    如果未找到字符 '/'，则输出错误信息并返回 0。

    使用 snprintf 函数将 options->allow_ip_str 和逗号拼接到 access_buf 中。

    将 options->access_str（从开头到字符 '/'）追加到 access_buf 中，确保长度足够。

    使用 strchr 函数查找第一个字符 '/' 之后是否还有其他字符 '/'. 如果有，则输出错误信息并返回 0。

    使用 snprintf 函数将 nat_port 转换为字符串并保存在 tmp_nat_port 中。

    将 tmp_nat_port 追加到 access_buf 中，确保长度足够。

    如果 options->access_str 为空，则重新设置 access_buf 为包含 options->allow_ip_str、
    逗号和字符串 "none/0" 的内容。

    返回 1 表示成功设置访问缓冲区。

这个函数的作用是根据输入的选项 options 设置访问缓冲区 access_buf，
并根据选项中的不同设置来调整访问字符串（options->access_str）中的端口号或生成新的访问字符串。

 * 
*/
static int
set_access_buf(fko_ctx_t ctx, fko_cli_options_t *options, char *access_buf)
{
    char   *ndx = NULL, tmp_nat_port[MAX_PORT_STR_LEN+1] = {0};
    int     nat_port = 0;

    if(options->access_str[0] != 0x0)
    {
        if (options->nat_rand_port)
        {
            nat_port = get_rand_port(ctx);
            options->nat_port = nat_port;
        }
        else if (options->nat_port)
            nat_port = options->nat_port;

        if(nat_port > 0 && nat_port <= MAX_PORT)
        {
            /* Replace the access string port with the NAT port since the
             * NAT port is manually specified (--nat-port) or derived from
             * random data (--nat-rand-port).  In the NAT modes, the fwknopd
             * server uses the port in the access string as the one to NAT,
             * and access is granted via this translated port to whatever is
             * specified with --nat-access <IP:port> (so this service is the
             * utlimate target of the incoming connection after the SPA
             * packet is sent).
            */
        //    将访问字符串的端口替换为NAT端口，因为NAT端口是手动指定的（--nat-port）
        //    或从随机数据中派生的（--nat-rand-port）。在NAT模式下，fwknopd服务器使
        //    用访问字符串中的端口作为NAT的端口，并且通过此转换后的端口授予访问权限给
        //    --nat-access IP:port所指定的目标（因此，在发送SPA数据包之后，此服务是
        //    传入连接的最终目标）。
            ndx = strchr(options->access_str, '/');
            if(ndx == NULL)
            {
                log_msg(LOG_VERBOSITY_ERROR, "[*] Expecting <proto>/<port> for -A arg.");
                return 0;
            }
            snprintf(access_buf, MAX_LINE_LEN, "%s%s",
                    options->allow_ip_str, ",");

            /* This adds in the protocol + '/' char
            */
            strlcat(access_buf, options->access_str,
                    strlen(access_buf) + (ndx - options->access_str) + 2);

            if (strchr(ndx+1, '/') != NULL)
            {
                log_msg(LOG_VERBOSITY_ERROR,
                        "[*] NAT for multiple ports/protocols not yet supported.");
                return 0;
            }

            /* Now add the NAT port
            */
            snprintf(tmp_nat_port, MAX_PORT_STR_LEN+1, "%d", nat_port);
            strlcat(access_buf, tmp_nat_port,
                    strlen(access_buf)+MAX_PORT_STR_LEN+1);
        }
        else
        {
            snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
                    options->allow_ip_str, ",", options->access_str);
        }
    }
    else
    {
        snprintf(access_buf, MAX_LINE_LEN, "%s%s%s",
                options->allow_ip_str, ",", "none/0");
    }
    return 1;
}

/* Set NAT access string
*/
/**
 * 这是一段用C语言编写的函数，实现了设置NAT（网络地址转换）访问的功能。
 * 该函数接受一个上下文对象fko_ctx_t ctx、一个命令行选项对象fko_cli_options_t *options和
 * 一个表示访问信息的字符串const char * const access_buf作为参数。函数首先初始化一些变量，
 * 然后解析命令行选项中的访问信息。如果解析不成功，会返回相应的错误代码。
接着，函数会根据命令行选项中是否指定了本地NAT转换和访问字符串，来生成NAT访问的字符串。
如果没有指定访问字符串，则会检查是否指定了NAT访问字符串。如果指定了NAT访问字符串，
则会解析主机和端口，并验证其有效性。最后，函数会输出一个日志信息，
显示分配给该访问的随机端口，并调用相关的函数设置NAT访问。

该函数的具体实现可能依赖于其他头文件和函数定义。

 * 
*/

static int
set_nat_access(fko_ctx_t ctx, fko_cli_options_t *options, const char * const access_buf)
{
    char                nat_access_buf[MAX_LINE_LEN] = {0};
    char                tmp_nat_port[MAX_LINE_LEN] = {0};
    char                tmp_access_port[MAX_PORT_STR_LEN+1] = {0}, *ndx = NULL;
    int                 access_port = 0, i = 0, is_err = 0, hostlen = 0;
    struct addrinfo     hints;

    memset(&hints, 0 , sizeof(hints));

    ndx = strchr(options->access_str, '/');
    if(ndx == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] Expecting <proto>/<port> for -A arg.");
        return FKO_ERROR_INVALID_DATA;
    }
    ndx++;

    while(*ndx != '\0' && isdigit((int)(unsigned char)*ndx) && i < MAX_PORT_STR_LEN)
    {
        tmp_access_port[i] = *ndx;
        ndx++;
        i++;
    }
    tmp_access_port[i] = '\0';

    access_port = strtol_wrapper(tmp_access_port, 1,
            MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid port value '%d' for -A arg.",
                access_port);
        return FKO_ERROR_INVALID_DATA;
    }

    if (options->nat_local && options->nat_access_str[0] == 0x0)
    {
        snprintf(nat_access_buf, MAX_LINE_LEN, NAT_ACCESS_STR_TEMPLATE,
            options->spa_server_str, access_port);
    }

    if (nat_access_buf[0] == 0x0 && options->nat_access_str[0] != 0x0)
    {
        /* Force the ':' (if any) to a ','
        */
        ndx = strchr(options->nat_access_str, ':');
        if (ndx != NULL)
            *ndx = ',';

        ndx = strchr(options->nat_access_str, ',');
        if (ndx != NULL)
        {
            hostlen = ndx - options->nat_access_str; //len of host, up til either comma or null
            *ndx = 0;

            ndx++;
            i = 0;
            while(*ndx != '\0')
            //if it goes over max length, mark as invalid

            {
                tmp_nat_port[i] = *ndx;
                if ((i > MAX_PORT_STR_LEN) || (!isdigit((int)(unsigned char)*ndx)))
                {
                    log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid port value in -N arg.");
                    return FKO_ERROR_INVALID_DATA;
                }
                ndx++;
                i++;
            }
            tmp_nat_port[i] = '\0';
            access_port = strtol_wrapper(tmp_nat_port, 1,
                        MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
            if (is_err != FKO_SUCCESS)
            {
                log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid port value in -N arg.");
                return FKO_ERROR_INVALID_DATA;
            }
        } else {
            hostlen = strlen(options->nat_access_str);
        }

        if ((access_port < 1) | (access_port > 65535))
        {
            log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid port value.");
            return FKO_ERROR_INVALID_DATA;
        }


        if (is_valid_ipv4_addr(options->nat_access_str, hostlen) || is_valid_hostname(options->nat_access_str, hostlen))
        {
            snprintf(nat_access_buf, MAX_LINE_LEN, NAT_ACCESS_STR_TEMPLATE,
                options->nat_access_str, access_port);
        }
        else
        {
            log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid NAT destination '%s' for -N arg.",
                options->nat_access_str);
            return FKO_ERROR_INVALID_DATA;
        }
    }

    if(options->nat_rand_port)
    {
        /* Must print to stdout what the random port is since
         * if not then the user will not which port will be
         * opened/NAT'd on the fwknopd side
        */
        log_msg(LOG_VERBOSITY_NORMAL,
                "[+] Randomly assigned port '%d' on: '%s' will grant access to: '%s'",
                options->nat_port, access_buf, nat_access_buf);
    }

    return fko_set_spa_nat_access(ctx, nat_access_buf);
}


/**
 * 这是一个用C语言编写的函数，用于执行前一个命令或显示前一个命令。
 * 该函数接受一个命令行选项对象fko_cli_options_t *options、参数数量int argc和参数数组char **argv作为输入。

函数首先初始化一些变量，然后检查是否指定了保存参数文件的路径。
如果指定了保存参数文件的路径，则将其复制到args_save_file数组中；
如果未指定保存参数文件的路径，则根据配置选择的模式来确定保存参数文件的路径。
如果配置为--no-home-dir模式，则必须使用-E选项设置保存参数文件的路径；
否则，将调用get_save_file函数确定保存参数文件的路径。

然后，根据命令行选项的不同，函数执行相应的操作。
如果设置了--run-last-command选项，则调用run_last_args函数执行前一个命令；
如果设置了--show-last-command选项，则调用show_last_command函数显示前一个命令；
如果没有设置--no-save-args选项，则调用save_args函数保存当前命令的参数到文件中。

最后，函数返回执行结果。

请注意，该函数的具体实现可能依赖于其他头文件和函数定义。

*/
static int
prev_exec(fko_cli_options_t *options, int argc, char **argv)
{
    char       args_save_file[MAX_PATH_LEN] = {0};
    int        res = 1;

    if(options->args_save_file[0] != 0x0)
    {//配置了保存路径
        
        strlcpy(args_save_file, options->args_save_file, sizeof(args_save_file));
    }
    else
    {//没有配置保存路径
        if(options->no_home_dir)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "In --no-home-dir mode must set the args save file path with -E");
            return 0;
        }
        else
        {
            if (get_save_file(args_save_file) != 1)
            {
                log_msg(LOG_VERBOSITY_ERROR, "Unable to determine args save file");
                return 0;
            }
        }
    }

    if(options->run_last_command)
        res = run_last_args(options, args_save_file);
    else if(options->show_last_command)
        res = show_last_command(args_save_file);
    else if (!options->no_save_args)
        res = save_args(argc, argv, args_save_file);

    return res;
}


/* Show the last command that was executed
*/
//展示最后一次执行的命令
/**
 * 这是一个用C语言编写的函数，用于显示上一个命令。
 * 该函数接受一个保存参数文件路径的字符串const char * const args_save_file作为输入。

函数首先初始化一些变量，然后尝试打开保存参数文件。
如果无法打开文件，则输出错误信息并返回0。

接下来，函数会验证文件的权限和所属权。如果权限或所属权不正确，则关闭文件并返回0。

然后，函数尝试从文件中读取一行内容，并将其存储在args_str数组中。
如果成功读取了一行内容，则输出日志信息，显示上一个命令；
否则，输出错误信息并关闭文件，然后返回0。

最后，函数关闭文件，并返回1表示执行成功。

请注意，该函数依赖于其他函数和头文件的定义，包括log_msg函数和相关的文件操作函数。

 * 
*/
static int
show_last_command(const char * const args_save_file)
{
    char args_str[MAX_LINE_LEN] = {0};
    FILE *args_file_ptr = NULL;

    if ((args_file_ptr = fopen(args_save_file, "r")) == NULL) {
        log_msg(LOG_VERBOSITY_ERROR, "Could not open args file: %s",
            args_save_file);
        return 0;
    }

#if HAVE_FILENO
    if(verify_file_perms_ownership(args_save_file, fileno(args_file_ptr)) != 1)
#else
    if(verify_file_perms_ownership(args_save_file, -1) != 1)
#endif
    {
        fclose(args_file_ptr);
        return 0;
    }

    if ((fgets(args_str, MAX_LINE_LEN, args_file_ptr)) != NULL) {
        log_msg(LOG_VERBOSITY_NORMAL,
                "Last fwknop client command line: %s", args_str);
    } else {
        log_msg(LOG_VERBOSITY_NORMAL,
                "Could not read line from file: %s", args_save_file);
        fclose(args_file_ptr);
        return 0;
    }
    fclose(args_file_ptr);

    return 1;
}

/* Get the command line arguments from the previous invocation
*/
// 从上一次调用中获取命令行参数
static int
run_last_args(fko_cli_options_t *options, const char * const args_save_file)
{
    FILE           *args_file_ptr = NULL;
    int             argc_new = 0, args_broken = 0;
    char            args_str[MAX_ARGS_LINE_LEN] = {0};
    char           *argv_new[MAX_CMDLINE_ARGS];  /* should be way more than enough */

    memset(argv_new, 0x0, sizeof(argv_new));

    if ((args_file_ptr = fopen(args_save_file, "r")) == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "Could not open args file: %s",
                args_save_file);
        return 0;
    }
    /*
    * fileno 是C语言标准库 <stdio.h> 中的一个函数，用于获取给定文件流（FILE 结构体指针）对应的文件描述符。
    * 文件描述符的值在不同的上下文中有不同的含义，常见的包括：
    * 标准输入（stdin）：文件描述符为0
    * 标准输出（stdout）：文件描述符为1
    * 标准错误输出（stderr）：文件描述符为2
    * 其他已打开的文件：文件描述符从3开始依次递增
    */
#if HAVE_FILENO
    if(verify_file_perms_ownership(args_save_file, fileno(args_file_ptr)) != 1)
#else
    if(verify_file_perms_ownership(args_save_file, -1) != 1)
#endif
    {
        fclose(args_file_ptr);
        return 0;
    }
    if ((fgets(args_str, MAX_LINE_LEN, args_file_ptr)) != NULL)
    {
        args_str[MAX_LINE_LEN-1] = '\0';
        if (options->verbose)
            log_msg(LOG_VERBOSITY_NORMAL, "Executing: %s", args_str);
        if(strtoargv(args_str, argv_new, &argc_new) != 1)
        {
            args_broken = 1;
        }
    }
    fclose(args_file_ptr);

    if(args_broken)
        return 0;

    /* Reset the options index so we can run through them again.
    */
   //重置选项索引，以便我们可以再次运行它们。
    optind = 0;

    config_init(options, argc_new, argv_new);

    /* Since we passed in our own copies, free up malloc'd memory
    */
    free_argv(argv_new, &argc_new);

    return 1;
}


//获取不同操作系统默认的保存文件路径

static int
get_save_file(char *args_save_file)
{
    char *homedir = NULL;
    int rv = 0;

#ifdef WIN32
    homedir = getenv("USERPROFILE");
#else
    homedir = getenv("HOME");
#endif
    if (homedir != NULL) {
        snprintf(args_save_file, MAX_PATH_LEN, "%s%c%s",
            homedir, PATH_SEP, ".fwknop.run");
        rv = 1;
    }

    return rv;
}

/* Save our command line arguments
*/
/**
 这是一个用C语言编写的函数，用于将命令行参数保存到文件中。
 该函数接受命令行参数的数量argc、命令行参数数组**argv和保存参数文件路径的
 字符串const char * const args_save_file作为输入。

函数首先初始化一些变量，并尝试以写入方式打开参数保存文件。如果无法打开文件，则输出错误信息并返回0。

然后，函数使用一个循环将每个命令行参数连接成一个字符串，并将其存储在args_str数组中。
如果参数字符串的长度超过了最大长度限制，则输出错误信息并关闭文件，然后返回0。

接着，函数在参数字符串的末尾添加一个换行符，并将参数字符串写入参数保存文件。
如果写入的字节数与预期的字节数不一致，则输出警告信息。

最后，函数关闭文件，并返回1表示保存成功。

请注意，该函数依赖于其他函数和头文件的定义，包括log_msg函数、open函数、close函数、strlcat函数和write函数。
此外，函数还使用了自定义的宏定义LOG_VERBOSITY_ERROR、LOG_VERBOSITY_WARNING、MAX_LINE_LEN和MAX_PATH_LEN。

 * 
*/
static int
save_args(int argc, char **argv, const char * const args_save_file)
{
    char args_str[MAX_LINE_LEN] = {0};
    int i = 0, args_str_len = 0, args_file_fd = -1;

    args_file_fd = open(args_save_file, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
    if (args_file_fd == -1) {
        log_msg(LOG_VERBOSITY_ERROR, "Could not open args file: %s",
            args_save_file);
        return 0;
    }
    else {
        for (i=0; i < argc; i++) {
            args_str_len += strlen(argv[i]);
            if (args_str_len >= MAX_PATH_LEN) {
                log_msg(LOG_VERBOSITY_ERROR, "argument string too long, exiting.");
                close(args_file_fd);
                return 0;
            }
            strlcat(args_str, argv[i], sizeof(args_str));
            strlcat(args_str, " ", sizeof(args_str));
        }
        strlcat(args_str, "\n", sizeof(args_str));
        if(write(args_file_fd, args_str, strlen(args_str))
                != strlen(args_str)) {
            log_msg(LOG_VERBOSITY_WARNING,
                "warning, did not write expected number of bytes to args save file");
        }
        close(args_file_fd);
    }
    return 1;
}

/* Set the SPA packet message type
*/
/*
 这是一个用C语言编写的函数，用于设置消息类型。
 该函数接受一个fko_ctx_t类型的上下文ctx和一个fko_cli_options_t类型的结构体指针options作为输入。

函数首先声明一个短整型变量message_type。

然后，函数根据条件判断来确定消息类型。
首先检查options->server_command[0]是否为空，如果不为空，则将消息类型设置为FKO_COMMAND_MSG。
接着，检查options->nat_local是否为真，如果为真，则进一步检查options->fw_timeout是否大于等于零。
如果是，则将消息类型设置为FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG，否则将消息类型设置为FKO_LOCAL_NAT_ACCESS_MSG。
然后，检查options->nat_access_str[0]是否为空，如果不为空，则再次检查options->fw_timeout的值来确定消息类型。
最后，如果以上条件都不满足，则根据options->fw_timeout的值将消息类型设置为相应的类型。

最后，函数调用fko_set_spa_message_type函数，将上下文和消息类型作为参数，以设置消息类型，并返回该函数的返回值。

请注意，该函数依赖于其他函数和头文件的定义，包括fko_ctx_t类型、fko_cli_options_t类型和 
fko_set_spa_message_type函数的定义。此外，函数还使用了结构体指针options的成员变量 
server_command、nat_local、nat_access_str和fw_timeout。
 
*/
static int
set_message_type(fko_ctx_t ctx, fko_cli_options_t *options)
{
    short message_type;

    if(options->server_command[0] != 0x0)
    {
        message_type = FKO_COMMAND_MSG;
    }
    else if(options->nat_local)
    {
        if (options->fw_timeout >= 0)
            message_type = FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG;
        else
            message_type = FKO_LOCAL_NAT_ACCESS_MSG;
    }
    else if(options->nat_access_str[0] != 0x0)
    {
        if (options->fw_timeout >= 0)
            message_type = FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG;
        else
            message_type = FKO_NAT_ACCESS_MSG;
    }
    else
    {
        if (options->fw_timeout >= 0)
            message_type = FKO_CLIENT_TIMEOUT_ACCESS_MSG;
        else
            message_type = FKO_ACCESS_MSG;
    }

    return fko_set_spa_message_type(ctx, message_type);
}

/* Prompt for and receive a user password.
*/
//提示并接收用户密码。
/*
    这段代码是一个函数get_keys，用于获取密钥和HMAC密钥。

首先，它会先清空key和hmac_key数组，然后通过一系列条件判断来确定密钥来源和长度。

    如果options结构体中的have_key字段为真，那么将options->key拷贝到key数组中，并获取密钥长度。
    如果options结构体中的have_base64_key字段为真，那么将对options->key_base64进行Base64解码，
    并将解码结果拷贝到key数组中，并获取密钥长度。
    如果options结构体中的get_key_file字段不为空，那么从文件中读取密钥。
    如果options结构体中的use_gpg字段为真，那么根据不同情况获取签名密钥。
    其他情况下，从用户输入中获取加密密钥。

接着，如果options结构体中的have_hmac_key字段为真，那么将options->hmac_key拷贝到hmac_key数组中，并获取HMAC密钥长度。
如果options结构体中的have_hmac_base64_key字段为真，
那么将对options->hmac_key_base64进行Base64解码，
并将解码结果拷贝到hmac_key数组中，并获取HMAC密钥长度。
如果options结构体中的use_hmac字段为真，那么根据不同情况获取HMAC密钥。

最后，如果使用了HMAC密钥，会检查密钥长度是否合法，并确保加密密钥和HMAC密钥不相同。
然后，设置SPA（Secure Packet Acceleration）的HMAC类型。

函数返回1表示成功获取密钥，返回0表示获取失败
*/
static int
get_keys(fko_ctx_t ctx, fko_cli_options_t *options,
    char *key, int *key_len, char *hmac_key, int *hmac_key_len)
{
#if !AFL_FUZZING
    char   *key_tmp = NULL, *hmac_key_tmp = NULL;
#endif
    int     use_hmac = 0, res = 0;

    memset(key, 0x0, MAX_KEY_LEN+1);
    memset(hmac_key, 0x0, MAX_KEY_LEN+1);

    if(options->have_key)
    {
        strlcpy(key, options->key, MAX_KEY_LEN+1);
        *key_len = strlen(key);
    }
    else if(options->have_base64_key)
    {
        *key_len = fko_base64_decode(options->key_base64,
                (unsigned char *) options->key);
        if(*key_len > 0 && *key_len < MAX_KEY_LEN)
        {
            memcpy(key, options->key, *key_len);
        }
        else
        {
            log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid key length: '%d', must be in [1,%d]",
                    *key_len, MAX_KEY_LEN);
            return 0;
        }
    }
    else
    {
        /* If --get-key file was specified grab the key/password from it.
        */
        if(options->get_key_file[0] != 0x0)
        {
            if(get_key_file(key, key_len, options->get_key_file, ctx, options) != 1)
            {
                return 0;
            }
        }
        else if(options->use_gpg)
        {
            if(options->use_gpg_agent)
                log_msg(LOG_VERBOSITY_NORMAL,
                    "[+] GPG mode set, signing passphrase acquired via gpg-agent");
            else if(options->gpg_no_signing_pw)
                log_msg(LOG_VERBOSITY_NORMAL,
                    "[+] GPG mode set, signing passphrase not required");
            else if(strlen(options->gpg_signer_key))
            {
#if AFL_FUZZING
                strlcpy(key, AFL_ENC_KEY, MAX_KEY_LEN+1);
#else
                key_tmp = getpasswd("Enter passphrase for signing: ", options->input_fd);
                if(key_tmp == NULL)
                {
                    log_msg(LOG_VERBOSITY_ERROR, "[*] getpasswd() key error.");
                    return 0;
                }
                strlcpy(key, key_tmp, MAX_KEY_LEN+1);
#endif
                *key_len = strlen(key);
            }
        }
        else
        {
#if AFL_FUZZING
            strlcpy(key, AFL_ENC_KEY, MAX_KEY_LEN+1);
#else
            key_tmp = getpasswd("Enter encryption key: ", options->input_fd);
            if(key_tmp == NULL)
            {
                log_msg(LOG_VERBOSITY_ERROR, "[*] getpasswd() key error.");
                return 0;
            }
            strlcpy(key, key_tmp, MAX_KEY_LEN+1);
#endif
            *key_len = strlen(key);
        }
    }

    if(options->have_hmac_key)
    {
        strlcpy(hmac_key, options->hmac_key, MAX_KEY_LEN+1);
        *hmac_key_len = strlen(hmac_key);
        use_hmac = 1;
    }
    else if(options->have_hmac_base64_key)
    {
        *hmac_key_len = fko_base64_decode(options->hmac_key_base64,
            (unsigned char *) options->hmac_key);
        if(*hmac_key_len > MAX_KEY_LEN || *hmac_key_len < 0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "[*] Invalid decoded key length: '%d', must be in [0,%d]",
                    *hmac_key_len, MAX_KEY_LEN);
            return 0;
        }
        memcpy(hmac_key, options->hmac_key, *hmac_key_len);
        use_hmac = 1;
    }
    else if (options->use_hmac)
    {
        /* If --get-key file was specified grab the key/password from it.
        */
        if(options->get_hmac_key_file[0] != 0x0)
        {
            if(get_key_file(hmac_key, hmac_key_len,
                options->get_hmac_key_file, ctx, options) != 1)
            {
                return 0;
            }
            use_hmac = 1;
        }
        else
        {
#if AFL_FUZZING
            strlcpy(hmac_key, AFL_HMAC_KEY, MAX_KEY_LEN+1);
#else
            hmac_key_tmp = getpasswd("Enter HMAC key: ", options->input_fd);
            if(hmac_key_tmp == NULL)
            {
                log_msg(LOG_VERBOSITY_ERROR, "[*] getpasswd() key error.");
                return 0;
            }
            strlcpy(hmac_key, hmac_key_tmp, MAX_KEY_LEN+1);
#endif
            *hmac_key_len = strlen(hmac_key);
            use_hmac = 1;
        }
    }

    if (use_hmac)
    {
        if(*hmac_key_len < 0 || *hmac_key_len > MAX_KEY_LEN)
        {
            log_msg(LOG_VERBOSITY_ERROR, "[*] Invalid HMAC key length: '%d', must be in [0,%d]",
                    *hmac_key_len, MAX_KEY_LEN);
            return 0;
        }

        /* Make sure the same key is not used for both encryption and the HMAC
        */
        if(*hmac_key_len == *key_len)
        {
            if(memcmp(hmac_key, key, *key_len) == 0)
            {
                log_msg(LOG_VERBOSITY_ERROR,
                    "[*] The encryption passphrase and HMAC key should not be identical, no SPA packet sent. Exiting.");
                return 0;
            }
        }

        res = fko_set_spa_hmac_type(ctx, options->hmac_type);
        if(res != FKO_SUCCESS)
        {
            errmsg("fko_set_spa_hmac_type", res);
            return 0;
        }
    }

    return 1;
}

/* Display an FKO error message.
*/
/*
这段代码定义了一个名为errmsg的函数，用于输出错误信息。

函数有两个参数：msg和err。msg是一个字符串，用来描述错误信息，err是一个整数，表示错误代码。

函数内部调用了log_msg函数来输出错误信息。使用log_msg函数，并传入LOG_VERBOSITY_ERROR作为日志级别，
以及格式化字符串作为日志内容。

格式化字符串中包含了MY_NAME，它表示程序的名称。然后依次输出msg、err和fko_errstr(err)的值。
其中，fko_errstr(err)是一个用于根据错误码获取错误描述的函数。

这个函数的作用是将错误信息格式化后输出到日志中。

*/
void
errmsg(const char *msg, const int err) {
    log_msg(LOG_VERBOSITY_ERROR, "%s: %s: Error %i - %s",
        MY_NAME, msg, err, fko_errstr(err));
}

/*
这段代码定义了一个名为zero_buf_wrapper的函数，用于将缓冲区中的数据清零。

函数有两个参数：buf和len，分别表示待清零的缓冲区指针和缓冲区长度。

首先，函数会进行输入参数的检查。如果buf为空指针或者len为0，则直接返回，不进行清零操作。

接下来，调用了zero_buf函数来将缓冲区中的数据清零。如果清零操作返回的错误码为FKO_ERROR_ZERO_OUT_DATA，
则说明清零操作失败，此时会输出相应的错误信息到日志中。

最后，函数返回，结束执行。

这个函数的作用是通过调用zero_buf函数来将缓冲区中的敏感数据清零，并在清零失败时输出错误信息到日志中。

*/
static void
zero_buf_wrapper(char *buf, int len)
{

    if(buf == NULL || len == 0)
        return;

    if(zero_buf(buf, len) == FKO_ERROR_ZERO_OUT_DATA)
        log_msg(LOG_VERBOSITY_ERROR,
                "[*] Could not zero out sensitive data buffer.");

    return;
}

/*
2023/7/20 10:41:09

这段代码是一个条件编译块，用于在编译时判断是否启用了libfiu库，并定义了一个名为enable_fault_injections的函数。

首先，通过检查预处理宏HAVE_LIBFIU来确定是否启用了libfiu库。如果启用了该库，则进入条件编译块。

在函数内部，首先定义了一个整数类型的变量rv并将其初始化为1。

接着，通过判断opts->fault_injection_tag的值是否为空字符串来确定是否设置了故障注入标签。
如果设置了标签，则输出相应的日志信息。

然后，调用fiu_init函数来初始化libfiu库。如果初始化失败，则输出警告日志，并将rv的值设为0。

接下来，调用fiu_enable函数来设置故障注入标签的开启状态。如果设置失败，则输出警告日志，并将rv的值设为0。

最后，函数返回rv，表示是否成功启用故障注入功能。

该函数的作用是在启用了libfiu库的情况下，根据配置中的故障注入标签来进行故障注入。
首先初始化libfiu库，然后根据标签开启相应的故障注入功能，并在设置失败时输出警告日志。
函数返回值表示是否成功启用了故障注入。

*/
#if HAVE_LIBFIU
static int
enable_fault_injections(fko_cli_options_t * const opts)
{
    int rv = 1;
    if(opts->fault_injection_tag[0] != 0x0)
    {
        if(opts->verbose)
            log_msg(LOG_VERBOSITY_NORMAL, "[+] Enable fault injection tag: %s",
                    opts->fault_injection_tag);
        if(fiu_init(0) != 0)
        {
            log_msg(LOG_VERBOSITY_WARNING, "[*] Unable to set fault injection tag: %s",
                    opts->fault_injection_tag);
            rv = 0;
        }
        if(fiu_enable(opts->fault_injection_tag, 1, NULL, 0) != 0)
        {
            log_msg(LOG_VERBOSITY_WARNING, "[*] Unable to set fault injection tag: %s",
                    opts->fault_injection_tag);
            rv = 0;
        }
    }
    return rv;
}
#endif

/* free up memory and exit
*/
/*
2023/7/20 10:42:33

这段代码定义了一个名为clean_exit的函数，用于在程序退出时进行清理工作。

在函数内部，首先通过条件编译块判断是否启用了libfiu库。
如果启用了该库，并且设置了故障注入标签，则调用fiu_disable函数来禁用该标签的故障注入功能。

接着，调用fko_destroy函数销毁传入的上下文对象ctx，如果返回值为FKO_ERROR_ZERO_OUT_DATA，
则输出错误日志表示无法将敏感数据缓冲区清零。

然后，调用free_configs函数来释放由opts指针指向的配置数据的内存。

接下来，调用zero_buf_wrapper函数将密钥缓冲区和HMAC密钥缓冲区清零。之后，将密钥长度和HMAC密钥长度都设置为0。

最后，使用exit函数退出程序，并传入指定的退出状态码exit_status。

该函数的作用是在程序退出时进行必要的清理工作。根据条件判断是否启用了libfiu库，
并根据配置中的故障注入标签禁用相应的故障注入功能。然后，销毁上下文对象、释放内存、清零敏感数据缓冲区，
最后退出程序并返回指定的退出状态码。

*/
static void
clean_exit(fko_ctx_t ctx, fko_cli_options_t *opts,
        char *key, int *key_len, char *hmac_key, int *hmac_key_len,
        unsigned int exit_status)
{
#if HAVE_LIBFIU
    if(opts->fault_injection_tag[0] != 0x0)
        fiu_disable(opts->fault_injection_tag);
#endif

    if(fko_destroy(ctx) == FKO_ERROR_ZERO_OUT_DATA)
        log_msg(LOG_VERBOSITY_ERROR,
                "[*] Could not zero out sensitive data buffer.");
    ctx = NULL;
    free_configs(opts);
    zero_buf_wrapper(key, *key_len);
    zero_buf_wrapper(hmac_key, *hmac_key_len);
    *key_len = 0;
    *hmac_key_len = 0;
    exit(exit_status);
}

/***EOF***/
