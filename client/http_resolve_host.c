/**
 * \file client/http_resolve_host.c
 *
 * \brief Routine for using an http request to obtain a client's IP
 *          address as seen from the outside world.
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
 *****************************************************************************
*/
#include "fwknop_common.h"
#include "utils.h"

#include <errno.h>

#ifdef WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #if HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
  #endif
  #include <netdb.h>
  #include <sys/wait.h>
#endif

#if AFL_FUZZING
  #define AFL_SET_RESOLVE_HOST "192.168.12.123" /* force to non-routable IP */
#endif


/*
这段代码定义了一个名为 url 的结构体。该结构体包含了三个成员变量：port、host 和 path。

port 是一个字符串数组，长度为 MAX_PORT_STR_LEN+1，用于存储端口号。host 是一个字符串数组，
长度为 MAX_URL_HOST_LEN+1，用于存储主机名或 IP 地址。path 是一个字符串数组，长度为 MAX_URL_PATH_LEN+1，用于存储路径信息。

这个结构体用于表示一个 URL 的各个组成部分，包括端口号、主机名和路径信息。
通过将这些信息存储在结构体中，可以方便地对 URL 进行处理和操作。
每个成员变量都有预定义的最大长度，以确保足够的空间来存储对应的信息。

*/
struct url
{
    char    port[MAX_PORT_STR_LEN+1];
    char    host[MAX_URL_HOST_LEN+1];
    char    path[MAX_URL_PATH_LEN+1];
};

/*
2023/7/20 15:29:56

这段代码是一个函数try_url，它用于尝试解析 URL 的外部 IP 地址。函数的主要步骤如下：

    初始化变量和数据结构。
    构建 HTTP 请求，并发送给指定的 URL。
    接收并处理从服务器返回的 HTTP 响应。
    解析响应中的 IP 地址，并验证其格式和值的合法性。
    如果解析成功，将解析到的 IP 地址存储在 options->allow_ip_str 中，并返回1。
    如果解析失败，返回-1。

需要注意的是，该函数依赖于一些外部的库和定义，例如<sys/types.h>、<sys/socket.h>等。
此外，函数中还包含了一些错误处理和日志记录的代码。


*/
static int
try_url(struct url *url, fko_cli_options_t *options)
{
    int     sock=-1, sock_success=0, res, error, http_buf_len, i;
    int     bytes_read = 0, position = 0;
    int     o1, o2, o3, o4;
    struct  addrinfo *result=NULL, *rp, hints;
    char    http_buf[HTTP_MAX_REQUEST_LEN]       = {0};
    char    http_response[HTTP_MAX_RESPONSE_LEN] = {0};
    char   *ndx;

#ifdef WIN32
    WSADATA wsa_data;

    /* Winsock needs to be initialized...
    */
    res = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( res != 0 )
    {
        log_msg(LOG_VERBOSITY_ERROR, "Winsock initialization error %d", res );
        return(-1);
    }
#endif

    /* Build our HTTP request to resolve the external IP (this is similar to
     * to contacting whatismyip.org, but using a different URL).
    */
    snprintf(http_buf, HTTP_MAX_REQUEST_LEN,
        "GET %s HTTP/1.1\r\nUser-Agent: %s\r\nAccept: */*\r\n"
        "Host: %s\r\nConnection: close\r\n\r\n",
        url->path,
        options->http_user_agent,
        url->host
    );

    http_buf_len = strlen(http_buf);

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_family   = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

#if AFL_FUZZING
    /* Make sure to not generate any resolution requests when compiled
     * for AFL fuzzing cycles
    */
    strlcpy(options->allow_ip_str, AFL_SET_RESOLVE_HOST,
            sizeof(options->allow_ip_str));
    log_msg(LOG_VERBOSITY_INFO,
                "\n[+] AFL fuzzing cycle, force IP resolution to: %s",
                options->allow_ip_str);

    return(1);
#endif

    error = getaddrinfo(url->host, url->port, &hints, &result);
    if (error != 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "error in getaddrinfo: %s", gai_strerror(error));
        return(-1);
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sock < 0)
            continue;

        if ((error = (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)))
        {
            sock_success = 1;
            break;  /* made it */
        }
        else /* close the open socket if there was a connect error */
        {
#ifdef WIN32
            closesocket(sock);
#else
            close(sock);
#endif
        }

    }
    if(result != NULL)
        freeaddrinfo(result);

    if (! sock_success)
    {
        log_msg(LOG_VERBOSITY_ERROR, "resolve_ip_http: Could not create socket: ", strerror(errno));
        return(-1);
    }

    log_msg(LOG_VERBOSITY_DEBUG, "\nHTTP request: %s", http_buf);

    res = send(sock, http_buf, http_buf_len, 0);

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "resolve_ip_http: write error: ", strerror(errno));
    }
    else if(res != http_buf_len)
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, http_buf_len
        );
    }

    do
    {
        memset(http_buf, 0x0, sizeof(http_buf));
        bytes_read = recv(sock, http_buf, sizeof(http_buf), 0);
        if ( bytes_read > 0 ) {
            if(position + bytes_read >= HTTP_MAX_RESPONSE_LEN)
                break;
            memcpy(&http_response[position], http_buf, bytes_read);
            position += bytes_read;
        }
    }
    while ( bytes_read > 0 );

    http_response[HTTP_MAX_RESPONSE_LEN-1] = '\0';

#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif

    log_msg(LOG_VERBOSITY_DEBUG, "\nHTTP response: %s", http_response);

    /* Move to the end of the HTTP header and to the start of the content.
    */
    ndx = strstr(http_response, "\r\n\r\n");
    if(ndx == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "Did not find the end of HTTP header.");
        return(-1);
    }
    ndx += 4;

    /* Walk along the content to try to find the end of the IP address.
     * Note: We are expecting the content to be just an IP address
     *       (possibly followed by whitespace or other not-digit value).
     */
    for(i=0; i<MAX_IPV4_STR_LEN; i++) {
        if(! isdigit((int)(unsigned char)*(ndx+i)) && *(ndx+i) != '.')
            break;
    }

    /* Terminate at the first non-digit and non-dot.
    */
    *(ndx+i) = '\0';

    /* Now that we have what we think is an IP address string.  We make
     * sure the format and values are sane.
     */
    if((sscanf(ndx, "%u.%u.%u.%u", &o1, &o2, &o3, &o4)) == 4
            && o1 >= 0 && o1 <= 255
            && o2 >= 0 && o2 <= 255
            && o3 >= 0 && o3 <= 255
            && o4 >= 0 && o4 <= 255)
    {
        strlcpy(options->allow_ip_str, ndx, sizeof(options->allow_ip_str));

        log_msg(LOG_VERBOSITY_INFO,
                    "\n[+] Resolved external IP (via http://%s%s) as: %s",
                    url->host,
                    url->path,
                    options->allow_ip_str);

        return(1);
    }
    else
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "[-] From http://%s%s\n    Invalid IP (%s) in HTTP response:\n\n%s",
            url->host, url->path, ndx, http_response);
        return(-1);
    }
}

/*
2023/7/20 15:33:04

这段代码是一个函数parse_url，用于解析传入的 URL 字符串，并提取出其中的主机名、端口号和路径信息。函数的主要步骤如下：

    首先判断 URL 字符串是否以 "https://" 或 "http://" 开头，如果是，则跳过该部分。
    检查是否指定了端口号（通过冒号进行分隔），如果指定了，则提取出端口号，并将其存储在 url->port 中。
    如果URL字符串以 "/" 结尾，则删除末尾的斜杠。
    查找 URL 字符串中的第一个 "/"，确定主机名和路径的长度。
    将主机名和路径分别拷贝到 url->host 和 url->path 中，并确保长度不超过预定义的最大值。
    如果没有指定路径，则将默认路径设为 "/".

函数使用了一些辅助函数和宏定义，例如strncasecmp、strchr、strtol_wrapper等。
需要注意的是，函数中的一些边界检查和错误处理的代码依赖于外部的定义和库。
因此，在实际使用时，可能需要根据实际情况进行适当的修改和补充。
*/
static int
parse_url(char *res_url, struct url* url)
{
    char *s_ndx, *e_ndx;
    int  tlen, tlen_offset, port, is_err;

    /* Strip off https:// or http:// portion if necessary
    */
    if(strncasecmp(res_url, "https://", 8) == 0)
        s_ndx = res_url + 8;
    else if(strncasecmp(res_url, "http://", 7) == 0)
        s_ndx = res_url + 7;
    else
        s_ndx = res_url;

    /* Look for a colon in case an alternate port was specified.
    */
    e_ndx = strchr(s_ndx, ':');
    if(e_ndx != NULL)
    {
        port = strtol_wrapper(e_ndx+1, 1, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
        if(is_err != FKO_SUCCESS)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                "[*] resolve-url port value is invalid, must be in [%d-%d]",
                1, MAX_PORT);
            return(-1);
        }

        snprintf(url->port, sizeof(url->port)-1, "%u", port);

        /* Get the offset we need to skip the port portion when we
         * extract the hostname part.
        */
        tlen_offset = strlen(url->port)+1;
    }
    else
    {
        strlcpy(url->port, "80", sizeof(url->port));
        tlen_offset = 0;
    }

    /* Get rid of any trailing slash
    */
    if(res_url[strlen(res_url)-1] == '/')
        res_url[strlen(res_url)-1] = '\0';

    e_ndx = strchr(s_ndx, '/');
    if(e_ndx == NULL)
        tlen = strlen(s_ndx)+1;
    else
        tlen = (e_ndx-s_ndx)+1;

    tlen -= tlen_offset;

    if(tlen > MAX_URL_HOST_LEN)
    {
        log_msg(LOG_VERBOSITY_ERROR, "resolve-url hostname portion is too large.");
        return(-1);
    }
    strlcpy(url->host, s_ndx, tlen);

    if(e_ndx != NULL)
    {
        if(strlen(e_ndx) > MAX_URL_PATH_LEN)
        {
            log_msg(LOG_VERBOSITY_ERROR, "resolve-url path portion is too large.");
            return(-1);
        }

        strlcpy(url->path, e_ndx, sizeof(url->path));
    }
    else
    {
        /* default to "GET /" if there isn't a more specific URL
        */
        strlcpy(url->path, "/", sizeof(url->path));
    }

    return(0);
}

int
resolve_ip_https(fko_cli_options_t *options)
{
    int     o1, o2, o3, o4, got_resp=0, i=0;
    char   *ndx, resp[MAX_IPV4_STR_LEN+1] = {0};
    struct  url url; /* for validation only */
    char    wget_ssl_cmd[MAX_URL_PATH_LEN] = {0};  /* for verbose logging only */

#if HAVE_EXECVP
    char   *wget_argv[MAX_CMDLINE_ARGS]; /* for execvp() */
    int     wget_argc=0;
    int     pipe_fd[2];
    pid_t   pid=0;
    FILE   *output;
    int     status, es = 0;
#else
    FILE *wget;
#endif

#if HAVE_EXECVP
    memset(wget_argv, 0x0, sizeof(wget_argv));
#endif
    memset(&url, 0x0, sizeof(url));

    if(options->wget_bin != NULL)
    {
        strlcpy(wget_ssl_cmd, options->wget_bin, sizeof(wget_ssl_cmd));
    }
    else
    {
#ifdef WGET_EXE
        strlcpy(wget_ssl_cmd, WGET_EXE, sizeof(wget_ssl_cmd));
#else
        log_msg(LOG_VERBOSITY_ERROR,
                "[*] Use --wget-cmd <path> to specify path to the wget command.");
        return(-1);
#endif
    }

    /* See whether we're supposed to change the default wget user agent
    */
    if(! options->use_wget_user_agent)
    {
        strlcat(wget_ssl_cmd, " -U ", sizeof(wget_ssl_cmd));
        strlcat(wget_ssl_cmd, options->http_user_agent, sizeof(wget_ssl_cmd));
    }

    /* We collect the IP from wget's stdout
    */
    strlcat(wget_ssl_cmd,
            " --secure-protocol=auto --quiet -O - ", sizeof(wget_ssl_cmd));

    if(options->resolve_url != NULL)
    {
        if(strncasecmp(options->resolve_url, "https", 5) != 0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "[-] Warning: IP resolution URL '%s' should begin with 'https://' in -R mode.",
                    options->resolve_url);
        }

        if(parse_url(options->resolve_url, &url) < 0)
        {
            log_msg(LOG_VERBOSITY_ERROR, "Error parsing resolve-url");
            return(-1);
        }
        /* tack on the original URL to the wget command
        */
        strlcat(wget_ssl_cmd, options->resolve_url, sizeof(wget_ssl_cmd));
    }
    else
    {
        /* tack on the default URL to the wget command
        */
        strlcat(wget_ssl_cmd, WGET_RESOLVE_URL_SSL, sizeof(wget_ssl_cmd));
    }

#if AFL_FUZZING
    /* Make sure to not generate any resolution requests when compiled
     * for AFL fuzzing cycles
    */
    strlcpy(options->allow_ip_str, AFL_SET_RESOLVE_HOST,
            sizeof(options->allow_ip_str));
    log_msg(LOG_VERBOSITY_INFO,
                "\n[+] AFL fuzzing cycle, force IP resolution to: %s",
                options->allow_ip_str);

    return(1);
#endif

#if HAVE_EXECVP
    if(strtoargv(wget_ssl_cmd, wget_argv, &wget_argc) != 1)
    {
        log_msg(LOG_VERBOSITY_ERROR, "Error converting wget cmd str to argv");
        return(-1);
    }

    /* We drive wget to resolve the external IP via SSL. This may not
     * work on all platforms, but is a better strategy for now than
     * requiring that fwknop link against an SSL library.
    */
    if(pipe(pipe_fd) < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] pipe() error");
        free_argv(wget_argv, &wget_argc);
        return -1;
    }

    pid = fork();
    if (pid == 0)
    {
        close(pipe_fd[0]);
        dup2(pipe_fd[1], STDOUT_FILENO);
        dup2(pipe_fd[1], STDERR_FILENO);
        es = execvp(wget_argv[0], wget_argv);

        if(es == -1)
            log_msg(LOG_VERBOSITY_ERROR,
                    "[*] resolve_ip_https(): execvp() failed: %s",
                    strerror(errno));

        /* We only make it here if there was a problem with execvp(),
         * so exit() here either way
        */
        exit(es);
    }
    else if(pid == -1)
    {
        log_msg(LOG_VERBOSITY_INFO, "[*] Could not fork() for wget.");
        free_argv(wget_argv, &wget_argc);
        return -1;
    }

    /* Only the parent process makes it here
    */
    close(pipe_fd[1]);
    if ((output = fdopen(pipe_fd[0], "r")) != NULL)
    {
        if(fgets(resp, sizeof(resp), output) != NULL)
        {
            got_resp = 1;
        }
        fclose(output);
    }
    else
    {
        log_msg(LOG_VERBOSITY_INFO,
                "[*] Could not fdopen() pipe output file descriptor.");
        free_argv(wget_argv, &wget_argc);
        return -1;
    }

    waitpid(pid, &status, 0);

    free_argv(wget_argv, &wget_argc);

#else /* fall back to popen() */
    wget = popen(wget_ssl_cmd, "r");
    if(wget == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] Could not run cmd: %s",
                wget_ssl_cmd);
        return -1;
    }
    /* Expecting one line of wget output that contains the resolved IP.
     * */
    if ((fgets(resp, sizeof(resp), wget)) != NULL)
    {
        got_resp = 1;
    }
    pclose(wget);
#endif

    if(got_resp)
    {
        ndx = resp;
        for(i=0; i<MAX_IPV4_STR_LEN; i++) {
            if(! isdigit((int)(unsigned char)*(ndx+i)) && *(ndx+i) != '.')
                break;
        }
        *(ndx+i) = '\0';

        if((sscanf(ndx, "%u.%u.%u.%u", &o1, &o2, &o3, &o4)) == 4
                && o1 >= 0 && o1 <= 255
                && o2 >= 0 && o2 <= 255
                && o3 >= 0 && o3 <= 255
                && o4 >= 0 && o4 <= 255)
        {
            strlcpy(options->allow_ip_str, ndx, sizeof(options->allow_ip_str));

            log_msg(LOG_VERBOSITY_INFO,
                        "\n[+] Resolved external IP (via '%s') as: %s",
                        wget_ssl_cmd, options->allow_ip_str);
            return 1;
        }
    }
    log_msg(LOG_VERBOSITY_ERROR,
        "[-] Could not resolve IP via: '%s'", wget_ssl_cmd);
    return -1;
}
//解析http
/*
这是一个C语言函数，用于通过HTTPS解析IP地址。函数接受一个名为options的结构体指针作为参数，并返回一个整数。

函数中定义了一些变量，包括o1, o2, o3, o4用于存储IP地址的四个部分，got_resp表示是否成功获取到响应，i用作循环计数器，
resp用于存储wget的输出结果，url用于验证URL的有效性，wget_ssl_cmd用于存储wget命令。

函数首先检查是否已经指定了wget_bin路径，如果指定了则将其赋值给wget_ssl_cmd变量，如果没有指定则使用默认路径。
然后根据use_wget_user_agent标志决定是否更改wget的默认User-Agent。之后拼接命令行参数和URL到wget_ssl_cmd。

接下来根据编译选项判断是否处于AFL Fuzzing模式，如果是，则直接返回预设的IP地址。

然后根据编译选项选择使用execvp()或popen()函数执行wget命令，并从输出中读取解析得到的IP地址。

最后将解析得到的IP地址存储到options->allow_ip_str变量中，并返回相应的结果。

注意：这段代码是一个片段，可能会缺少一些必要的头文件和其他依赖项。

*/
int
resolve_ip_http(fko_cli_options_t *options)
{
    int     res;
    struct  url url;

    memset(&url, 0, sizeof(url));

    if(options->resolve_url != NULL)
    {
        /* we only enter this function when the user forces non-HTTPS
         * IP resolution
        */
        if(strncasecmp(options->resolve_url, "https", 5) == 0)
        {
            log_msg(LOG_VERBOSITY_ERROR,
                    "[*] https is not supported for --resolve-http-only.");
            return(-1);
        }

        if(parse_url(options->resolve_url, &url) < 0)
        {
            log_msg(LOG_VERBOSITY_ERROR, "Error parsing resolve-url");
            return(-1);
        }

        res = try_url(&url, options);

    } else {
        strlcpy(url.port, "80", sizeof(url.port));
        strlcpy(url.host, HTTP_RESOLVE_HOST, sizeof(url.host));
        strlcpy(url.path, HTTP_RESOLVE_URL, sizeof(url.path));

        res = try_url(&url, options);
        if(res != 1)
        {
            /* try the backup url (just switches the host to cipherdyne.com)
            */
            strlcpy(url.host, HTTP_BACKUP_RESOLVE_HOST, sizeof(url.host));

#ifndef WIN32
            sleep(2);
#endif
            res = try_url(&url, options);
        }
    }
    return(res);
}

/***EOF***/
