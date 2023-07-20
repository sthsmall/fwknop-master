/**
 * \file client/cmd_opts.h
 *
 * \brief Header file for fwknop command line options.
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
#ifndef CMD_OPTS_H
#define CMD_OPTS_H

/* Long options values (for those without a short option).
*/
/*

    FKO_DIGEST_NAME：摘要算法名称。
    ENCRYPTION_MODE：加密模式。
    NAT_LOCAL：本地网络地址转换（NAT）设置。
    NAT_PORT：NAT端口设置。
    NAT_RAND_PORT：随机NAT端口设置。
    NO_HOME_DIR：禁用家目录。
    NO_RC_FILE：禁用配置文件。
    TIME_OFFSET_MINUS：时间偏移负值。
    TIME_OFFSET_PLUS：时间偏移正值。
    SAVE_RC_STANZA：保存配置节。
    FORCE_SAVE_RC_STANZA：强制保存配置节。
    STANZA_LIST：配置节列表。
    NO_SAVE_ARGS：不保存参数。
    SHOW_LAST_ARGS：显示最后一次参数。
    RC_FILE_PATH：配置文件路径。
    RESOLVE_HTTP_ONLY：仅解析HTTP。
    RESOLVE_URL：解析URL。
    SERVER_RESOLVE_IPV4：服务器解析IPv4。
    USE_HMAC：使用HMAC。
    USE_WGET_USER_AGENT：使用Wget用户代理。
    SPA_ICMP_TYPE：SPA ICMP类型。
    SPA_ICMP_CODE：SPA ICMP代码。
    KEY_LEN：密钥长度。
    HMAC_DIGEST_TYPE：HMAC摘要类型。
    HMAC_KEY_LEN：HMAC密钥长度。
    GET_HMAC_KEY：获取HMAC密钥。
    KEY_RIJNDAEL：Rijndael密钥。
    KEY_RIJNDAEL_BASE64：Base64编码的Rijndael密钥。
    KEY_HMAC_BASE64：Base64编码的HMAC密钥。
    KEY_HMAC：HMAC密钥。
    FD_SET_STDIN：设置标准输入文件描述符。
    FD_SET_ALT：设置备用文件描述符。
    FAULT_INJECTION_TAG：故障注入标签。

*/
enum {
    FKO_DIGEST_NAME     = 0x100,
    ENCRYPTION_MODE,
    NAT_LOCAL,
    NAT_PORT,
    NAT_RAND_PORT,
    NO_HOME_DIR,
    NO_RC_FILE,
    TIME_OFFSET_MINUS,
    TIME_OFFSET_PLUS,
    SAVE_RC_STANZA,
    FORCE_SAVE_RC_STANZA,
    STANZA_LIST,
    NO_SAVE_ARGS,
    SHOW_LAST_ARGS,
    RC_FILE_PATH,
    RESOLVE_HTTP_ONLY,
    RESOLVE_URL,
    SERVER_RESOLVE_IPV4,
    USE_HMAC,
    USE_WGET_USER_AGENT,
    SPA_ICMP_TYPE,
    SPA_ICMP_CODE,
    KEY_LEN,
    HMAC_DIGEST_TYPE,
    HMAC_KEY_LEN,
    GET_HMAC_KEY,
    KEY_RIJNDAEL,
    KEY_RIJNDAEL_BASE64,
    KEY_HMAC_BASE64,
    KEY_HMAC,
    FD_SET_STDIN,
    FD_SET_ALT,
    FAULT_INJECTION_TAG,

    /*
    这段代码是在前面提到的枚举类型中添加了与GPG相关的常量。这些常量用于指定与GPG加密有关的设置和选项。

下面是对这些常量的简要说明：

    GPG_ENCRYPTION：GPG加密设置。
    GPG_RECIP_KEY：GPG接收者密钥。
    GPG_SIGNER_KEY：GPG签名者密钥。
    GPG_HOME_DIR：GPG主目录。
    GPG_EXE_PATH：GPG可执行文件路径。
    GPG_AGENT：GPG代理。
    GPG_ALLOW_NO_SIGNING_PW：允许无签名密码的GPG操作。
    NOOP：只是一个标记，表示枚举的结束。

通过使用这些常量，可以在程序中设置和配置与GPG加密相关的选项和参数。

    */
    /* Put GPG-related items below the following line */
    GPG_ENCRYPTION      = 0x200,
    GPG_RECIP_KEY,
    GPG_SIGNER_KEY,
    GPG_HOME_DIR,
    GPG_EXE_PATH,
    GPG_AGENT,
    GPG_ALLOW_NO_SIGNING_PW,
    NOOP /* Just to be a marker for the end */
};


/* Our getopt_long options string.
*/
//具体来说，这个字符串包含了多个字母和冒号，每个字母都代表一个命令行选项。冒号表示该选项需要接收一个参数。
//通过解析命令行参数时，可以使用这个字符串常量来指定可接受的选项和它们是否需要参数。
#define GETOPTS_OPTION_STRING "a:A:bB:C:D:E:f:gG:hH:kK:lm:M:n:N:p:P:Q:rRsS:Tu:U:vVw:"

/* Our program command-line options...
*/

/*
当我们编写一个需要处理命令行参数的程序时，可以使用cmd_opts数组来定义可接受的命令行选项及其相关信息。
下面是对每个元素的详细解释：

{"allow-ip", 1, NULL, 'a'}

    allow-ip：长选项名称，表示允许的IP地址。
    1：需要一个参数。
    NULL：没有标记位。
    'a'：短选项名称。

此结构体元素表示了一个命令行选项，用户可以通过--allow-ip <ip>或-a <ip>的方式指定IP地址。

其他的元素按照相同的格式进行解释，具体含义如下：

    "access"：长选项名称，表示访问控制。
    "save-packet-append"：长选项名称，表示附加保存数据包。
    "save-packet"：长选项名称，表示保存数据包。
    "save-rc-stanza"：长选项名称，表示保存RC部分。
    "force-stanza"：长选项名称，表示强制保存RC部分。
    "stanza-list"：长选项名称，表示任务列表。
    "no-save-args"：长选项名称，表示不保存参数。
    "server-cmd"：长选项名称，表示服务器命令。
    "digest-type"：长选项名称，表示摘要类型。
    "destination"：长选项名称，表示目标地址。
    "save-args-file"：长选项名称，表示保存参数文件。
    "encryption-mode"：长选项名称，表示加密模式。
    "fd"：长选项名称，表示文件描述符。
    "fw-timeout"：长选项名称，表示超时时间。
    "fault-injection-tag"：长选项名称，表示故障注入标签。
    "gpg-encryption"：长选项名称，表示GPG加密。
    "gpg-recipient-key"：长选项名称，表示GPG接收方密钥。
    "gpg-signer-key"：长选项名称，表示GPG签名者密钥。
    "gpg-home-dir"：长选项名称，表示GPG家目录。
    "gpg-exe"：长选项名称，表示GPG可执行文件路径。
    "gpg-agent"：长选项名称，表示GPG代理。
    "gpg-no-signing-pw"：长选项名称，表示不使用签名密码。
    "get-key"：长选项名称，表示获取密钥。
    "get-hmac-key"：长选项名称，表示获取HMAC密钥。
    "help"：长选项名称，表示帮助。
    "http-proxy"：长选项名称，表示HTTP代理。
    "key-gen"：长选项名称，表示生成密钥。
    "key-gen-file"：长选项名称，表示生成密钥文件。
    "key-rijndael"：长选项名称，表示Rijndael密钥。
    "key-base64-rijndael"：长选项名称，表示Base64编码的Rijndael密钥。
    "key-base64-hmac"：长选项名称，表示Base64编码的HMAC密钥。
    "key-hmac"：长选项名称，表示HMAC密钥。
    "key-len"：长选项名称，表示密钥长度。
    "hmac-key-len"：长选项名称，表示HMAC密钥长度。
    "hmac-digest-type"：长选项名称，表示HMAC摘要类型。
    "icmp-type"：长选项名称，表示ICMP类型。
    "icmp-code"：长选项名称，表示ICMP代码。
    "last-cmd"：长选项名称，表示上一个命令。
    "nat-access"：长选项名称，表示NAT访问。
    "named-config"：长选项名称，表示命名配置。
    "nat-local"：长选项名称，表示本地NAT。
    "nat-port"：长选项名称，表示NAT端口。
    "nat-rand-port"：长选项名称，表示随机NAT端口。
    "no-home-dir"：长选项名称，表示没有家目录。
    "no-rc-file"：长选项名称，表示没有RC文件。
    "server-port"：长选项名称，表示服务器端口。
    "server-proto"：长选项名称，表示服务器协议。
    "spoof-source"：长选项名称，表示伪造源IP。
    "spoof-src"：长选项名称，表示伪造源IP（同义词）。
    "rc-file"：长选项名称，表示RC文件路径。
    "rand-port"：长选项名称，表示随机端口。
    "resolve-ip-http"：长选项名称，表示解析IP地址的HTTP。
    "resolve-ip-https"：长选项名称，表示解析IP地址的HTTPS（同义词，默认是HTTPS）。
    "resolve-http-only"：长选项名称，表示仅解析HTTP。
    "resolve-url"：长选项名称，表示解析URL。
    "server-resolve-ipv4"：长选项名称，表示服务器解析IPv4。
    "show-last"：长选项名称，表示显示上次的参数。
    "source-ip"：长选项名称，表示源IP。
    "source-port"：长选项名称，表示源端口。
    "stdin"：长选项名称，表示标准输入。
    "test"：长选项名称，表示测试。
    "time-offset-plus"：长选项名称，表示时间偏移增加。
    "time-offset-minus"：长选项名称，表示时间偏移减少。
    "user-agent"：长选项名称，表示用户代理。
    "use-hmac"：长选项名称，表示使用HMAC。
    "use-wget-user-agent"：长选项名称，表示使用Wget用户代理。
    "spoof-user"：长选项名称，表示伪造用户。
    "verbose"：长选项名称，表示详细模式。
    "version"：长选项名称，表示版本。
    "wget-cmd"：长选项名称，表示Wget命令。

最后一个元素{0, 0, 0, 0}用于表示数组的结束，其中所有的字段都为0。

通过遍历cmd_opts数组，可以在程序中获取用户输入的命令行选项及其参数，并执行相应的操作。
例如，当用户输入--allow-ip 192.168.1.1时，程序可以解析出allow-ip选项，并将192.168.1.1作为该选项的参数进行处理。

这种方式可以帮助我们编写更严谨和易用的命令行工具，提供更多的选项和灵活性。 
*/
static struct option cmd_opts[] =
{
    {"allow-ip",            1, NULL, 'a'},
    {"access",              1, NULL, 'A'},
    {"save-packet-append",  0, NULL, 'b'},
    {"save-packet",         1, NULL, 'B'},
    {"save-rc-stanza",      0, NULL, SAVE_RC_STANZA},
    {"force-stanza",        0, NULL, FORCE_SAVE_RC_STANZA},
    {"stanza-list",         0, NULL, STANZA_LIST},
    {"no-save-args",        0, NULL, NO_SAVE_ARGS},
    {"server-cmd",          1, NULL, 'C'},
    {"digest-type",         1, NULL, FKO_DIGEST_NAME},
    {"destination",         1, NULL, 'D'},
    {"save-args-file",      1, NULL, 'E'},
    {"encryption-mode",     1, NULL, ENCRYPTION_MODE},
    {"fd",                  1, NULL, FD_SET_ALT},
    {"fw-timeout",          1, NULL, 'f'},
    {"fault-injection-tag", 1, NULL, FAULT_INJECTION_TAG },
    {"gpg-encryption",      0, NULL, 'g'},
    {"gpg-recipient-key",   1, NULL, GPG_RECIP_KEY },
    {"gpg-signer-key",      1, NULL, GPG_SIGNER_KEY },
    {"gpg-home-dir",        1, NULL, GPG_HOME_DIR },
    {"gpg-exe",             1, NULL, GPG_EXE_PATH },
    {"gpg-agent",           0, NULL, GPG_AGENT },
    {"gpg-no-signing-pw",   0, NULL, GPG_ALLOW_NO_SIGNING_PW },
    {"get-key",             1, NULL, 'G'},
    {"get-hmac-key",        1, NULL, GET_HMAC_KEY },
    {"help",                0, NULL, 'h'},
    {"http-proxy",          1, NULL, 'H'},
    {"key-gen",             0, NULL, 'k'},
    {"key-gen-file",        1, NULL, 'K'},
    {"key-rijndael",        1, NULL, KEY_RIJNDAEL },
    {"key-base64-rijndael", 1, NULL, KEY_RIJNDAEL_BASE64 },
    {"key-base64-hmac",     1, NULL, KEY_HMAC_BASE64 },
    {"key-hmac",            1, NULL, KEY_HMAC },
    {"key-len",             1, NULL, KEY_LEN},
    {"hmac-key-len",        1, NULL, HMAC_KEY_LEN},
    {"hmac-digest-type",    1, NULL, HMAC_DIGEST_TYPE},
    {"icmp-type",           1, NULL, SPA_ICMP_TYPE },
    {"icmp-code",           1, NULL, SPA_ICMP_CODE },
    {"last-cmd",            0, NULL, 'l'},
    {"nat-access",          1, NULL, 'N'},
    {"named-config",        1, NULL, 'n'},
    {"nat-local",           0, NULL, NAT_LOCAL},
    {"nat-port",            1, NULL, NAT_PORT},
    {"nat-rand-port",       0, NULL, NAT_RAND_PORT},
    {"no-home-dir",         0, NULL, NO_HOME_DIR},
    {"no-rc-file",          0, NULL, NO_RC_FILE},
    {"server-port",         1, NULL, 'p'},
    {"server-proto",        1, NULL, 'P'},
    {"spoof-source",        1, NULL, 'Q'},
    {"spoof-src",           1, NULL, 'Q'}, /* synonym */
    {"rc-file",             1, NULL, RC_FILE_PATH},
    {"rand-port",           0, NULL, 'r'},
    {"resolve-ip-http",     0, NULL, 'R'},
    {"resolve-ip-https",    0, NULL, 'R'}, /* synonym, default is HTTPS */
    {"resolve-http-only",   0, NULL, RESOLVE_HTTP_ONLY},
    {"resolve-url",         1, NULL, RESOLVE_URL},
    {"server-resolve-ipv4", 0, NULL, SERVER_RESOLVE_IPV4},
    {"show-last",           0, NULL, SHOW_LAST_ARGS},
    {"source-ip",           0, NULL, 's'},
    {"source-port",         1, NULL, 'S'},
    {"stdin",               0, NULL, FD_SET_STDIN},
    {"test",                0, NULL, 'T'},
    {"time-offset-plus",    1, NULL, TIME_OFFSET_PLUS},
    {"time-offset-minus",   1, NULL, TIME_OFFSET_MINUS},
    {"user-agent",          1, NULL, 'u'},
    {"use-hmac",            0, NULL, USE_HMAC},
    {"use-wget-user-agent", 0, NULL, USE_WGET_USER_AGENT},
    {"spoof-user",          1, NULL, 'U'},
    {"verbose",             0, NULL, 'v'},
    {"version",             0, NULL, 'V'},
    {"wget-cmd",            1, NULL, 'w'},
    {0, 0, 0, 0}
};

#endif /* CMD_OPTS_H */

/***EOF***/
