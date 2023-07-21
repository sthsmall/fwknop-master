/**
 * \file client/spa_comm.c
 *
 * \brief Network-related functions for the fwknop client
 */


#include "spa_comm.h"
#include "utils.h"
/*
2023/7/20 15:40:08

这是一个名为dump_transmit_options的静态函数，用于打印传输选项信息。

函数接受一个类型为fko_cli_options_t的指针options作为参数。

函数中首先定义了一个名为proto_str的字符数组，大小为PROTOCOL_BUFSIZE，并初始化为全零。

接下来调用了proto_inttostr函数，将options->spa_proto转换为字符串保存到proto_str中。

然后使用log_msg函数打印了一条信息，日志级别为LOG_VERBOSITY_INFO，内容为"Generating SPA packet:"。

接着使用log_msg函数再次打印了一条信息，日志级别为LOG_VERBOSITY_INFO，
内容为"            protocol: %s"，其中%s会被proto_str替换。

如果options->spa_src_port不为0，则使用log_msg函数打印源端口信息；
否则打印一个默认的源端口信息"         source port: <OS assigned>"。

然后使用log_msg函数打印目标端口信息和IP/主机信息，日志级别都为LOG_VERBOSITY_INFO。

最后函数结束，没有返回值。

需要注意的是，函数中使用了LOG_VERBOSITY_INFO作为日志级别，在日志输出时会根据全局变量log_ctx.verbosity的值进行判断是否输出。

*/
static void
dump_transmit_options(const fko_cli_options_t *options)
{
    char proto_str[PROTOCOL_BUFSIZE] = {0};   /* Protocol string */

    proto_inttostr(options->spa_proto, proto_str, sizeof(proto_str));

    log_msg(LOG_VERBOSITY_INFO, "Generating SPA packet:");
    log_msg(LOG_VERBOSITY_INFO, "            protocol: %s", proto_str);

    if (options->spa_src_port)
        log_msg(LOG_VERBOSITY_INFO, "         source port: %d", options->spa_src_port);
    else
        log_msg(LOG_VERBOSITY_INFO, "         source port: <OS assigned>");

    log_msg(LOG_VERBOSITY_INFO, "    destination port: %d", options->spa_dst_port);
    log_msg(LOG_VERBOSITY_INFO, "             IP/host: %s", options->spa_server_str);

    return;
}

/* Function to generate a header checksum.
*/
/*
这是一个名为chksum的静态函数，用于计算校验和。

函数接受一个类型为unsigned short的指针buf和一个类型为int的参数nbytes作为输入。

函数中首先定义了两个变量：sum表示校验和，初始化为0；oddbyte表示奇数个字节。

接下来使用一个循环，当nbytes大于1时，将buf所指向的值加到sum上，并将buf向后移动2个字节，nbytes减去2。

如果nbytes等于1，则将buf所指向的值赋值给oddbyte，并将oddbyte加到sum上。这样处理是为了处理字节数为奇数的情况。

然后对sum执行一系列位运算，将高16位与低16位相加，并将结果再次与高16位相加。这是为了将可能产生的溢出结果加到校验和上。

最后，通过对sum取反得到最终的校验和值，并将其强制转换为unsigned short类型后返回。

该函数用于计算校验和，可用于网络通信等场景中确保数据的完整性。


*/
static unsigned short
chksum(unsigned short *buf, int nbytes)
{
    unsigned int   sum;
    unsigned short oddbyte;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *buf++;
        nbytes -= 2;
    }

    if (nbytes == 1)
    {
        oddbyte = 0;
        *((unsigned short *) &oddbyte) = *(unsigned short *) buf;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short) ~sum;
}

/* Send the SPA data via UDP packet.
*/
<<<<<<< HEAD
<<<<<<< HEAD
/*
这是一个名为send_spa_packet_tcp_or_udp的函数，用于发送SPA数据包。

该函数接受三个参数：spa_data表示要发送的SPA数据包内容，sd_len表示数据包的长度，options是一个结构体，包含了一些配置选项。

函数中首先对options->test进行了判断，如果设置了测试模式，则直接返回结果res。

然后通过调用memset函数将hints结构体清零，并设置hints.ai_family为AF_INET，即仅允许IPv4。

根据options->spa_proto的值，判断是使用UDP还是TCP协议进行发送。
如果是UDP，则将hints.ai_socktype设置为SOCK_DGRAM，hints.ai_protocol设置为IPPROTO_UDP；
如果是TCP，则将hints.ai_socktype设置为SOCK_STREAM，hints.ai_protocol设置为IPPROTO_TCP。

接下来通过snprintf函数将端口号转换为字符串，并存储在port_str中。

判断是否处于AFL模糊测试状态，如果是，则返回结果res。

接着调用getaddrinfo函数获取目标主机的地址信息，并将结果保存在result中。

然后通过循环遍历result链表中的每个地址信息，尝试建立套接字连接。当找到一个可用的地址时，将其作为目标地址，并跳出循环。

如果在循环结束后未找到可用的地址，释放result并返回错误。

然后创建套接字，并尝试连接目标地址。如果连接成功，则设置sock_success为1，并跳出循环。否则关闭套接字。

在循环结束后释放result。

如果没有成功创建套接字，则返回错误。

然后使用send函数发送SPA数据包，并将返回值保存在res中。

如果发送失败，则输出错误信息。

最后关闭套接字，并返回结果res。


*/
=======
//发送spa
>>>>>>> f09b0292cd2656cd80e5e6c7c601b8725d8fd234
=======
//发送spa
>>>>>>> f09b0292cd2656cd80e5e6c7c601b8725d8fd234

//该函数是发送的不是原始的udp或者tcp的数据包
static int
send_spa_packet_tcp_or_udp(const char *spa_data, const int sd_len,
    const fko_cli_options_t *options)
{
    int     sock=-1, sock_success=0, res=0, error;
    struct  addrinfo *result=NULL, *rp, hints;
    char    port_str[MAX_PORT_STR_LEN+1] = {0};

    if (options->test)          //这里会判断是否开启了test，开启了就会直接打印日志，终止函数，这样主函数中的test代码就会执行
    {
        log_msg(LOG_VERBOSITY_NORMAL,
            "test mode enabled, SPA packet not actually sent.");
        return res;
    }

    memset(&hints, 0, sizeof(struct addrinfo));//用于将一块内存区域的值设置为指定的字节值。

    hints.ai_family   = AF_INET; /* Allow IPv4 only */
   
    //如果是UDP，设置udp相关的
    /*
    这段代码是根据给定的条件设置hints结构体中与套接字类型和协议相关的字段，以便在使用UDP协议发送SPA数据包时使用。

    根据代码片段提供的信息，当options->spa_proto等于FKO_PROTO_UDP时，即当SPA协议为UDP时，会执行以下操作：

    将hints结构体中的ai_socktype字段设置为SOCK_DGRAM，表示使用数据报套接字类型（UDP）。

    将hints结构体中的ai_protocol字段设置为IPPROTO_UDP，表示要使用UDP协议。

    通过这样的设置，后续在创建套接字并进行网络通信时，可以根据hints的值选择正确的套接字类型和协议，
    确保SPA数据包通过UDP协议进行发送。

    需要注意的是，这段代码片段只是设置了相关的hints字段，并没有展示完整的套接字创建和网络通信的过程。
    完整的代码可能会在后续的步骤中使用hints来创建套接字、进行绑定、发送数据等操作。

    
    */
    if (options->spa_proto == FKO_PROTO_UDP)
    {
        /* Send the SPA data packet via an single UDP packet - this is the
         * most common usage.
        */
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }
    else
    {
        /* Send the SPA data packet via an established TCP connection.
        */
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
    }

    //在提供的代码中，snprintf函数被用于将整数值options->spa_dst_port转换为字符串形式，
    //并将结果存储到port_str中。该函数保证不会超过MAX_PORT_STR_LEN限定的字符串长度。
    //通过该函数就可以获得string类型的目标端口号
    snprintf(port_str, MAX_PORT_STR_LEN+1, "%d", options->spa_dst_port);

#if AFL_FUZZING
    /* Make sure to never send SPA packets under AFL fuzzing cycles
    */
    log_msg(LOG_VERBOSITY_NORMAL,
        "AFL fuzzing enabled, SPA packet not actually sent.");
    return res;
#endif
    /*
        这段代码使用getaddrinfo函数根据给定的服务器地址和端口号获取与之对应的网络地址信息。

        getaddrinfo是一个C语言中的库函数，用于将主机名（或IP地址）和服务名（或端口号）
        转换为适用于网络通信的地址结构。
    */
    error = getaddrinfo(options->spa_server_str, port_str, &hints, &result);

    if (error != 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "error in getaddrinfo: %s", gai_strerror(error));
        return -1;
    }
    /*
    for循环：

        这段代码是一个循环，用于遍历result链表中的地址信息结构体，并尝试创建套接字并进行连接操作。代码逻辑如下：

    遍历result链表中的每个地址信息结构体（rp = result; rp != NULL; rp = rp->ai_next）。
    如果设置了--server-resolve-ipv4选项，判断地址族不是IPv4的情况，跳过当前循环，继续下一次循环。
    使用socket函数创建套接字，并将返回的套接字描述符保存在sock变量中。如果创建失败（sock < 0），则继续下一次循环。
    使用connect函数尝试连接到指定地址（rp->ai_addr）和端口（rp->ai_addrlen）。如果连接成功（返回值不为-1），
    设置sock_success为1，跳出循环。
    如果连接失败，则关闭套接字，并继续下一次循环。
    循环结束后，释放地址信息结构体占用的资源（通过调用freeaddrinfo函数）。
    如果sock_success为0，表示没有成功创建套接字或连接，打印错误消息，并返回-1。
    如果成功创建套接字且连接成功，则使用send函数发送数据到服务器。
    如果发送数据失败（res < 0），打印错误消息。
    如果发送的字节数与数据长度不一致（res != sd_len），打印警告消息。

    这段代码的作用是根据给定的地址信息，创建套接字并尝试连接服务器，并发送数据。其中，result是一个addrinfo结构体链表，
    保存了一些网络相关的信息，例如主机名、端口号等。具体的操作需要根据实际需求和后续代码进行相应调整。

    
    */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        /* Apply --server-resolve-ipv4 criteria
        */
        if(options->spa_server_resolve_ipv4)
        {
            //只会循环IPv4的协议族
            if(rp->ai_family != AF_INET)
            {
                log_msg(LOG_VERBOSITY_DEBUG, "Non-IPv4 resolution");
                continue;
            }
        }

        sock = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
        if (sock < 0)
            continue;

        /*
        为UDP套接字调用connect函数的好处是：

        简化发送数据的过程：通过调用send函数，可以直接将数据发送给已连接的目标地址，而无需每次发送数据时都指定目标地址。
        进行错误检查：如果连接失败，可以及时得知连接错误，并采取相应的处理措施。
        如果不设置连接的话，需要使用sendto函数，并且要指定目标IP

        */
        /*注意这里只要连接成功，就会退出循环
        而且不管是tcp或者是udp都会去连接
        这里的协议可以是 TCP（传输控制协议）或 UDP（用户数据报协议），取决于在创建 addrinfo 结构体时设置的 ai_socktype 字段。

        如果 ai_socktype 设置为 SOCK_STREAM，则 connect 函数将尝试使用 TCP 协议建立连接。
        如果 ai_socktype 设置为 SOCK_DGRAM，则 connect 函数将尝试使用 UDP 协议建立连接。

        在调用 connect 函数之前，通常会通过 getaddrinfo 函数获取地址信息，并在其中设置 ai_socktype 字段以指定所需的套接字类型。
        根据设置的套接字类型，connect 函数将使用相应的协议来建立连接。

       */
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
    //循环结束，释放空间
    if(result != NULL)
        freeaddrinfo(result);

    if (! sock_success) {
        log_msg(LOG_VERBOSITY_ERROR,
                "send_spa_packet_tcp_or_udp: Could not create socket: %s",
                strerror(errno));
        return -1;
    }
    //发送数据
    //这里可能是tcp也可能是udp，具体的形式，要看上面设置的协议，统一使用send函数就可以发送
    res = send(sock, spa_data, sd_len, 0);

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_tcp_or_udp: write error: ", strerror(errno));
    }
    else if(res != sd_len)
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, sd_len
        );
    }

#ifdef WIN32
    closesocket(sock);
#else
    //最后释放socket
    close(sock);
#endif

    return(res);
}

/* Send the SPA data via raw TCP packet.
*/
//发送原始TCP数据包
/*
2023/7/20 15:46:43

当发送原始TCP数据包时，我们需要使用原始套接字（raw socket）来构造和发送数据包。原始套接字允许我们直接访问底层的网络协议栈，
并且可以自定义IP头部和TCP头部的值。

代码中的函数send_spa_packet_tcp_raw实现了发送原始TCP数据包的功能。下面逐行进行解释：

    #ifdef WIN32 和 #else：这是一个条件编译的指令，因为该代码在Windows平台上尚未支持，
    所以在Windows上会直接返回-1并输出错误信息。

    创建一些必要的变量，如套接字，数据包缓冲区等。

    if (options->test)：如果选项中开启了测试模式，则函数会直接返回，不会实际发送数据包。

    sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);：创建一个原始套接字。使用socket函数，
    传入PF_INET表示IPv4，SOCK_RAW表示原始套接字类型，IPPROTO_RAW表示原始套接字的协议为原始IP协议。

    memcpy((pkt_data + hdrlen), spa_data, sd_len);：将SPA数据拷贝到数据包的相应位置。

    构造IP头部：
        iph->ihl = 5;：IP首部长度（Header Length），单位是32位字（4字节）。通常为5，表示20字节。
        iph->version = 4;：IP协议版本号。本代码中使用IPv4。
        iph->tos = 0;：服务类型（Type of Service），用于指定不同的数据传输优先级和服务质量。
        iph->tot_len = hdrlen + sd_len;：IP数据包的总长度，包括IP首部和数据部分。
        iph->id = random() & 0xffff;：标识符，唯一地标识单个数据报。
        iph->frag_off = 0;：分片偏移。在IP分片时使用。
        iph->ttl = RAW_SPA_TTL;：生存时间（Time to Live），指定数据包在网络中的生存时间（跳数限制）。
        iph->protocol = IPPROTO_TCP;：指定上层协议为TCP。
        iph->check = 0;：校验和。在发送前需要计算校验和。
        iph->saddr = saddr->sin_addr.s_addr;：源IP地址。
        iph->daddr = daddr->sin_addr.s_addr;：目标IP地址。

    构造TCP头部：
        tcph->source = saddr->sin_port;：源端口号。
        tcph->dest = daddr->sin_port;：目标端口号。
        tcph->seq = htonl(1);：序列号，用于标识数据流中的每个字节。
        tcph->ack_seq = 0;：确认序列号，用于标识已经收到的数据字节。
        tcph->doff = 5;：TCP首部长度，单位是32位字（4字节）。通常为5，表示20字节。
        tcph->res1 = 0;：保留字段。
        tcph->fin, tcph->syn, tcph->rst, tcph->psh, tcph->ack, tcph->urg：TCP标志位，
        用于控制连接的建立、终止和数据传输等。
        tcph->res2 = 0;：保留字段。
        tcph->window = htons(32767);：窗口大小，表示发送方的可接收窗口大小。
        tcph->check = 0;：校验和。在发送前需要计算校验和。
        tcph->urg_ptr = 0;：紧急指针。

    iph->check = chksum((unsigned short *)pkt_data, iph->tot_len);：计算IP头部的校验和。

    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, so_val, sizeof(one)) < 0)：使用setsockopt函数，
    设置套接字选项IP_HDRINCL。这个选项告诉内核，数据包中已经包含了IP头部，所以内核不会再插入自己的IP头部。

    res = sendto (sock, pkt_data, iph->tot_len, 0, (struct sockaddr *)daddr, sizeof(*daddr));：
    使用sendto函数，将数据包发送到目标地址。

    根据发送的结果，进行相应的处理和日志记录。

    关闭套接字，释放资源。

最后，函数返回发送的字节数。

这段代码主要是在底层构造了IP头部和TCP头部，然后通过原始套接字发送数据包。
它使得我们可以更加灵活地构造自定义的TCP数据包，并直接发送到网络中。
*/
static int
send_spa_packet_tcp_raw(const char *spa_data, const int sd_len,
    const struct sockaddr_in *saddr, const struct sockaddr_in *daddr,
    const fko_cli_options_t *options)
{
#ifdef WIN32
    log_msg(LOG_VERBOSITY_ERROR,
        "send_spa_packet_tcp_raw: raw packets are not yet supported.");
    return(-1);
#else
    int  sock, res = 0;
    char pkt_data[2048] = {0}; /* Should be enough for our purposes */

    struct iphdr  *iph  = (struct iphdr *) pkt_data;
    struct tcphdr *tcph = (struct tcphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct tcphdr);

    /* Values for setsockopt.
    */
    int         one     = 1;
    const int  *so_val  = &one;

    if (options->test)
    {
        log_msg(LOG_VERBOSITY_NORMAL,
            "test mode enabled, SPA packet not actually sent.");
        return res;
    }

    sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_tcp_raw: create socket: ", strerror(errno));
        return(sock);
    }

    /* Put the spa data in place.
    */
    memcpy((pkt_data + hdrlen), spa_data, sd_len);

    /* Construct our own header by filling in the ip/tcp header values,
     * starting with the IP header values.
    */
    iph->ihl        = 5;
    iph->version    = 4;
    iph->tos        = 0;
    /* Total size is header plus payload */
    iph->tot_len    = hdrlen + sd_len;
    /* The value here does not matter */
    srandom(time(NULL) ^ getuid() ^ (getgid() << 16) ^ getpid());
    iph->id         = random() & 0xffff;
    iph->frag_off   = 0;
    iph->ttl        = RAW_SPA_TTL;
    iph->protocol   = IPPROTO_TCP;
    iph->check      = 0;
    iph->saddr      = saddr->sin_addr.s_addr;
    iph->daddr      = daddr->sin_addr.s_addr;

    /* Now the TCP header values.
    */
    tcph->source    = saddr->sin_port;
    tcph->dest      = daddr->sin_port;
    tcph->seq       = htonl(1);
    tcph->ack_seq   = 0;
    tcph->doff      = 5;
    tcph->res1      = 0;
    /* TCP flags */
    tcph->fin       = 0;
    tcph->syn       = 1;
    tcph->rst       = 0;
    tcph->psh       = 0;
    tcph->ack       = 0;
    tcph->urg       = 0;

    tcph->res2      = 0;
    tcph->window    = htons(32767);
    tcph->check     = 0;
    tcph->urg_ptr   = 0;

    /* Now we can compute our checksum.
    */
   //计算校验和
    iph->check = chksum((unsigned short *)pkt_data, iph->tot_len);

    /* Make sure the kernel knows the header is included in the data so it
     * doesn't try to insert its own header into the packet.
    */
   //保证内核知道头部包含在数据中，这样它就不会尝试将自己的头部插入数据包中
   //IP_HDRINCL选项可以让内核绕过协议栈，直接将数据包发送到网络上


    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, so_val, sizeof(one)) < 0)
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_tcp_raw: setsockopt HDRINCL: ", strerror(errno));

    res = sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr));

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_tcp_raw: sendto error: ", strerror(errno));
    }
    else if(res != sd_len + hdrlen) /* account for the header ?*/
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, sd_len
        );
    }

    close(sock);

    return(res);

#endif /* !WIN32 */
}

/* Send the SPA data via raw UDP packet.
*/
//发送原始UDP数据包
/*
这段代码是一个函数send_spa_packet_udp_raw的实现，用于发送原始的UDP数据包。
函数的功能是构建IP头部和UDP头部，并发送带有指定数据的UDP数据包。

代码主要逻辑如下：

    首先，函数检查是否在Windows平台上运行。如果是，则输出一个错误信息并返回-1。

    在非Windows平台上，函数创建一个原始套接字(socket)，使用PF_INET协议族和SOCK_RAW类型。
    这样可以直接操作IP层和传输层的头部。

    将SPA数据复制到pkt_data缓冲区中，位于IP头部和UDP头部之后。

    填充IP头部的各个字段，例如版本号、总长度、源IP地址、目标IP地址等。

    填充UDP头部的各个字段，例如源端口号、目标端口号等。

    计算IP头部的校验和。

    设置套接字选项，使得内核知道IP头部已经包含在数据中，不会尝试插入自己的头部。

    使用sendto函数将数据包发送给目标地址。

    检查发送结果，如果发送失败则输出错误信息。

    关闭套接字，释放资源。

    这个发送的是原始的UDP数据包
*/
static int
send_spa_packet_udp_raw(const char *spa_data, const int sd_len,
    const struct sockaddr_in *saddr, const struct sockaddr_in *daddr,
    const fko_cli_options_t *options)
{
#ifdef WIN32
    log_msg(LOG_VERBOSITY_ERROR,
        "send_spa_packet_udp_raw: raw packets are not yet supported.");
    return(-1);
#else
    int  sock, res = 0;
    char pkt_data[2048] = {0}; /* Should be enough for our purposes */

    struct iphdr  *iph  = (struct iphdr *) pkt_data;
    struct udphdr *udph = (struct udphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct udphdr);

    /* Values for setsockopt.
    */
    int         one     = 1;
    const int  *so_val  = &one;

    if (options->test)
    {
        log_msg(LOG_VERBOSITY_NORMAL,
            "test mode enabled, SPA packet not actually sent.");
        return res;
    }

    sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_udp_raw: create socket: ", strerror(errno));
        return(sock);
    }

    /* Put the spa data in place.
    */
    memcpy((pkt_data + hdrlen), spa_data, sd_len);

    /* Construct our own header by filling in the ip/udp header values,
     * starting with the IP header values.
    */
    iph->ihl        = 5;
    iph->version    = 4;
    iph->tos        = 0;
    /* Total size is header plus payload */
    iph->tot_len    = hdrlen + sd_len;
    /* The value here does not matter */
    srandom(time(NULL) ^ getuid() ^ (getgid() << 16) ^ getpid());
    iph->id         = random() & 0xffff;
    iph->frag_off   = 0;
    iph->ttl        = RAW_SPA_TTL;
    iph->protocol   = IPPROTO_UDP;
    iph->check      = 0;
    iph->saddr      = saddr->sin_addr.s_addr;
    iph->daddr      = daddr->sin_addr.s_addr;

    /* Now the UDP header values.
    */
    udph->source    = saddr->sin_port;
    udph->dest      = daddr->sin_port;
    udph->check     = 0;
    udph->len       = htons(sd_len + sizeof(struct udphdr));

    /* Now we can compute our checksum.
    */
    iph->check = chksum((unsigned short *)pkt_data, iph->tot_len);

    /* Make sure the kernel knows the header is included in the data so it
     * doesn't try to insert its own header into the packet.
    */
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, so_val, sizeof(one)) < 0)
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_udp_raw: setsockopt HDRINCL: ", strerror(errno));

    res = sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr));

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_udp_raw: sendto error: ", strerror(errno));
    }
    else if(res != sd_len + hdrlen) /* account for the header ?*/
    {
        log_msg(LOG_VERBOSITY_WARNING,
            "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, sd_len
        );
    }

    close(sock);

    return(res);

#endif /* !WIN32 */
}

/* Send the SPA data via ICMP packet.
*/
//发送ICMP数据包
/*

这段代码是用于通过ICMP协议发送SPA数据包的函数。下面是代码的执行流程：

    首先，检查当前的操作系统是否为Windows，如果是，则打印错误信息并返回-1，因为Windows暂时不支持原始套接字操作。
    创建一个原始套接字，使用 socket 函数来创建。设置套接字的协议为IPPROTO_RAW，这样可以直接操作IP层的数据。
    如果 options->test 为真，则表示测试模式启用，不实际发送SPA数据包。此时，打印相应的日志信息并返回0。
    将SPA数据拷贝到 pkt_data 缓冲区的正确位置。
    填充IP头部的各个字段，例如版本号、服务类型、总长度、标识符、生存时间等。
    填充ICMP头部的各个字段，例如类型、代码、校验和等。如果ICMP类型为ICMP_ECHO（即Ping请求）且代码为0，还需要设置ICMP的标识符和序列号。
    计算IP头部和ICMP头部的校验和。
    使用 setsockopt 函数设置套接字选项，将IP报文头部包含在数据中，以避免内核自动填充IP头部。
    调用 sendto 函数发送数据包。
    检查发送结果。如果发送失败，则打印错误信息。如果发送成功但发送的字节数与SPA数据长度不一致，则打印警告信息。
    关闭套接字。
    返回发送结果。

这段代码的作用是使用ICMP协议发送SPA数据包。它创建一个原始套接字，并填充IP头部和ICMP头部的字段，然后发送数据包。


*/
static int
send_spa_packet_icmp(const char *spa_data, const int sd_len,
    const struct sockaddr_in *saddr, const struct sockaddr_in *daddr,
    const fko_cli_options_t *options)
{
#ifdef WIN32
    log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_icmp: raw packets are not yet supported.");
    return(-1);
#else
    int res = 0, sock;
    char pkt_data[2048] = {0};

    struct iphdr  *iph    = (struct iphdr *) pkt_data;
    struct icmphdr *icmph = (struct icmphdr *) (pkt_data + sizeof (struct iphdr));

    int hdrlen = sizeof(struct iphdr) + sizeof(struct icmphdr);

    /* Values for setsockopt.
    */
    int         one     = 1;
    const int  *so_val  = &one;

    if (options->test)
    {
        log_msg(LOG_VERBOSITY_NORMAL,
            "test mode enabled, SPA packet not actually sent.");
        return res;
    }

    sock = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sock < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_icmp: create socket: ", strerror(errno));
        return(sock);
    }

    /* Put the spa data in place.
    */
    memcpy((pkt_data + hdrlen), spa_data, sd_len);

    /* Construct our own header by filling in the ip/icmp header values,
     * starting with the IP header values.
    */
    iph->ihl        = 5;
    iph->version    = 4;
    iph->tos        = 0;
    /* Total size is header plus payload */
    iph->tot_len    = hdrlen + sd_len;
    /* The value here does not matter */
    srandom(time(NULL) ^ getuid() ^ (getgid() << 16) ^ getpid());
    iph->id         = random() & 0xffff;
    iph->frag_off   = 0;
    iph->ttl        = RAW_SPA_TTL;
    iph->protocol   = IPPROTO_ICMP;
    iph->check      = 0;
    iph->saddr      = saddr->sin_addr.s_addr;
    iph->daddr      = daddr->sin_addr.s_addr;

    /* Now the ICMP header values.
    */
    icmph->type     = options->spa_icmp_type;
    icmph->code     = options->spa_icmp_code;
    icmph->checksum = 0;

    if(icmph->type == ICMP_ECHO && icmph->code == 0)
    {
        icmph->un.echo.id       = htons(random() & 0xffff);
        icmph->un.echo.sequence = htons(1);
    }

    /* Now we can compute our checksum.
    */
    iph->check = chksum((unsigned short *)pkt_data, iph->tot_len);
    icmph->checksum = chksum((unsigned short *)icmph, sizeof(struct icmphdr) + sd_len);

    /* Make sure the kernel knows the header is included in the data so it
     * doesn't try to insert its own header into the packet.
    */
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, so_val, sizeof(one)) < 0)
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_icmp: setsockopt HDRINCL: ", strerror(errno));

    res = sendto (sock, pkt_data, iph->tot_len, 0,
        (struct sockaddr *)daddr, sizeof(*daddr));

    if(res < 0)
    {
        log_msg(LOG_VERBOSITY_ERROR, "send_spa_packet_icmp: sendto error: ", strerror(errno));
    }
    else if(res != sd_len + hdrlen) /* account for icmp header */
    {
        log_msg(LOG_VERBOSITY_WARNING, "[#] Warning: bytes sent (%i) not spa data length (%i).",
            res, sd_len);
    }

    close(sock);

    return(res);

#endif /* !WIN32 */
}

/* Send the SPA data packet via an HTTP request
*/
/*

    首先，函数开始时定义了一些变量。http_buf是用来存放HTTP请求内容的字符数组，初始化为全0。spa_data_copy是用来保存拷贝的SPA数据的指针，初始时为空。
    接下来，通过调用malloc函数在堆上分配了一块大小为sd_len+1的内存用于存放拷贝的SPA数据。如果分配失败，则打印错误信息并返回-1。
    使用memcpy函数将原始的SPA数据拷贝到spa_data_copy所指向的内存块中，并在最后添加终止符。这样做是为了修改spa_data_copy中的数据，而不影响到原始的SPA数据。
    遍历spa_data_copy中的每个字符，将其中的"+"替换为"-"，将"/"替换为"_"。这是因为在HTTP请求中，这些字符需要进行转义。
    判断options->http_proxy是否为空，以确定是否需要发送SPA数据包通过HTTP代理。如果为空，则表示不使用代理。
    此时，使用snprintf函数将HTTP请求的内容格式化到http_buf中。
    格式化的内容包括请求行、请求头部和空行。其中，spa_data_copy表示的是请求的资源路径，options->http_user_agent表示浏览器的User-Agent信息，
    options->spa_server_str表示主机名或IP地址。
    如果options->http_proxy不为空，表示需要通过HTTP代理发送SPA数据包。首先判断代理地址是否以"http://"开头，如果是，则将其去掉。
    然后，查找代理地址中是否有":"，若有则分离出代理的主机名或IP地址和端口号，并且将代理的主机名或IP地址赋值给options->spa_server_str。
    最后，使用snprintf函数将HTTP请求的内容格式化到http_buf中。其中的格式化内容与上述情况类似，只是请求行中的资源路径前面加上了代理的主机名或IP地址。
    释放spa_data_copy指向的内存块。
    如果options->test为真，则表示测试模式启用，不实际发送SPA数据包。此时，打印HTTP请求内容，然后返回0。
    否则，调用send_spa_packet_tcp_or_udp函数将HTTP请求内容发送出去，并返回发送结果。

    这段代码的作用是根据配置选项，通过HTTP协议发送SPA数据包。如果不使用HTTP代理，则直接将SPA数据包封装成HTTP请求发送出去；
    如果使用HTTP代理，则将SPA数据包封装成HTTP请求，并指定代理服务器。

*/
static int
send_spa_packet_http(const char *spa_data, const int sd_len,
    fko_cli_options_t *options)
{
    char http_buf[HTTP_MAX_REQUEST_LEN] = {0}, *spa_data_copy = NULL;
    char *ndx = options->http_proxy;
    int  i, proxy_port = 0, is_err;

    spa_data_copy = malloc(sd_len+1);
    if (spa_data_copy == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "[*] Fatal, could not allocate memory.");
        return -1;
    }
    memcpy(spa_data_copy, spa_data, sd_len+1);

    /* Change "+" to "-", and "/" to "_" for HTTP requests (the server
     * side will translate these back before decrypting)
    */
    for (i=0; i < sd_len; i++) {
        if (spa_data_copy[i] == '+') {
            spa_data_copy[i] = '-';
        }
        else if (spa_data_copy[i] == '/') {
            spa_data_copy[i] = '_';
        }
    }

    if(options->http_proxy[0] == 0x0)
    {
        snprintf(http_buf, HTTP_MAX_REQUEST_LEN,
            "GET /%s HTTP/1.1\r\nUser-Agent: %s\r\nAccept: */*\r\n"
            "Host: %s\r\nConnection: close\r\n\r\n",
            spa_data_copy,
            options->http_user_agent,
            options->spa_server_str  /* hostname or IP */
        );
    }
    else /* we are sending the SPA packet through an HTTP proxy */
    {
        /* Extract the hostname if it was specified as a URL. Actually,
         * we just move the start of the hostname to the beginning of the
         * original string.
        */
        if(strncasecmp(ndx, "http://", 7) == 0)
            memmove(ndx, ndx+7, strlen(ndx)+1);

        /* If there is a colon assume the proxy hostname or IP is on the left
         * and the proxy port is on the right. So we make the : a \0 and
         * extract the port value.
        */
        ndx = strchr(options->http_proxy, ':');
        if(ndx)
        {
            *ndx = '\0';
            proxy_port = strtol_wrapper(ndx+1, 1, MAX_PORT, NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_VERBOSITY_ERROR,
                    "[-] proxy port value is invalid, must be in [%d-%d]",
                    1, MAX_PORT);
                free(spa_data_copy);
                return -1;
            }
        }

        /* If we have a valid port value, use it.
        */
        if(proxy_port)
            options->spa_dst_port = proxy_port;

        snprintf(http_buf, HTTP_MAX_REQUEST_LEN,
            "GET http://%s/%s HTTP/1.1\r\nUser-Agent: %s\r\nAccept: */*\r\n"
            "Host: %s\r\nConnection: close\r\n\r\n",
            options->spa_server_str,
            spa_data_copy,
            options->http_user_agent,
            options->http_proxy  /* hostname or IP */
        );
        strlcpy(options->spa_server_str, options->http_proxy,
                sizeof(options->spa_server_str));
    }
    free(spa_data_copy);

    if (options->test)
    {
        log_msg(LOG_VERBOSITY_INFO, "%s", http_buf);

        log_msg(LOG_VERBOSITY_NORMAL,
            "Test mode enabled, SPA packet not actually sent.");
        return 0;
    }

    /* In AFL fuzzing mode, the following function will not send
     * the SPA packet.
    */
    return send_spa_packet_tcp_or_udp(http_buf, strlen(http_buf), options);
}

/* Function used to send the SPA data.
*/
//用于发送spa数据的函数
/*
这段代码是一个名为send_spa_packet的函数，用于发送SPA数据包。
该函数接受两个参数：一个是fko_ctx_t类型的上下文对象ctx，另一个是fko_cli_options_t类型的选项指针options。

函数内部定义了一些变量，包括整型变量res和sd_len，字符型指针spa_data，以及struct sockaddr_in类型的saddr和daddr结构体变量等。

函数首先调用fko_get_spa_data函数获取SPA数据，并将结果保存在spa_data中。
如果获取失败，则打印错误信息并返回-1。

接下来，函数根据options->spa_proto的值判断使用哪种协议发送SPA数据包。
如果是TCP或UDP协议，则调用send_spa_packet_tcp_or_udp函数发送数据包；
如果是HTTP协议，则调用send_spa_packet_http函数发送数据包；
如果是TCP_RAW、UDP_RAW或ICMP协议，则设置源地址和目的地址，并根据协议类型调用相应的发送函数。

最后，函数根据发送结果返回相应的值。

需要注意的是，这段代码可能存在一些特殊情况的处理逻辑，比如在AFL模糊测试环境下不发送SPA数据包等。


*/
//使用该函数可以封装前面的几种协议的函数
int
send_spa_packet(fko_ctx_t ctx, fko_cli_options_t *options)
{
    int                 res, sd_len;
    char               *spa_data;
    struct sockaddr_in  saddr, daddr;
    //字符串用于包含主机名的ip地址
    char                ip_str[INET_ADDRSTRLEN] = {0};  /* String used to contain the ip address of an hostname */ 
    //用于设置hints以解析主机名的结构
    struct addrinfo     hints;                          /* Structure used to set hints to resolve hostname */
#ifdef WIN32
    WSADATA wsa_data;
#endif

    /* Initialize the hint buffer */
    //初始化hints
    memset(&hints, 0 , sizeof(hints));

    /* Get our spa data here.
    */
    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "send_spa_packet: Error #%i from fko_get_spa_data: %s",
            res, fko_errstr(res)
        );
        return(-1);
    }

    sd_len = strlen(spa_data);

#ifdef WIN32
    /* Winsock needs to be initialized...
    */
    res = WSAStartup( MAKEWORD(1,1), &wsa_data );
    if( res != 0 )
    {
        log_msg(LOG_VERBOSITY_ERROR, "Winsock initialization error %d", res );
        return(-1);
    }
#endif

    errno = 0;
    
    dump_transmit_options(options);

    if (options->spa_proto == FKO_PROTO_TCP || options->spa_proto == FKO_PROTO_UDP)
    {
        res = send_spa_packet_tcp_or_udp(spa_data, sd_len, options);
    }
    else if (options->spa_proto == FKO_PROTO_HTTP)
    {
        res = send_spa_packet_http(spa_data, sd_len, options);
    }
    else if (options->spa_proto == FKO_PROTO_TCP_RAW
            || options->spa_proto == FKO_PROTO_UDP_RAW
            || options->spa_proto == FKO_PROTO_ICMP)
    {
        memset(&saddr, 0, sizeof(saddr));
        memset(&daddr, 0, sizeof(daddr));

        saddr.sin_family = AF_INET;
        daddr.sin_family = AF_INET;

        /* Set source address and port
        */
        if (options->spa_src_port)
            saddr.sin_port = htons(options->spa_src_port);
        else
            saddr.sin_port = INADDR_ANY;

        if (options->spoof_ip_src_str[0] != 0x00) {
            saddr.sin_addr.s_addr = inet_addr(options->spoof_ip_src_str);
        } else
            saddr.sin_addr.s_addr = INADDR_ANY;  /* default */

        if (saddr.sin_addr.s_addr == -1)
        {
            log_msg(LOG_VERBOSITY_ERROR, "Could not set source IP.");
            return -1;
        }

        /* Set destination port
        */
        daddr.sin_port = htons(options->spa_dst_port);

        /* Set destination address. We use the default protocol to resolve
         * the ip address */
        hints.ai_family = AF_INET;

#if AFL_FUZZING
        /* Make sure to never send SPA packets under AFL fuzzing cycles
        */
        log_msg(LOG_VERBOSITY_NORMAL,
            "AFL fuzzing enabled, SPA packet not actually sent.");
        return res;
#endif

        if (resolve_dst_addr(options->spa_server_str,
                    &hints, ip_str, sizeof(ip_str), options) != 0)
        {
            log_msg(LOG_VERBOSITY_ERROR, "[*] Unable to resolve %s as an ip address",
                    options->spa_server_str);
            return -1;
        }
        else;

        daddr.sin_addr.s_addr = inet_addr(ip_str);

        if (options->spa_proto == FKO_PROTO_TCP_RAW)
        {
            res = send_spa_packet_tcp_raw(spa_data, sd_len, &saddr, &daddr, options);
        }
        else if (options->spa_proto == FKO_PROTO_UDP_RAW)
        {
            res = send_spa_packet_udp_raw(spa_data, sd_len, &saddr, &daddr, options);
        }
        else
        {
            res = send_spa_packet_icmp(spa_data, sd_len, &saddr, &daddr, options);
        }
    }
    else
    {
        /* --DSS XXX: What to we really want to do here? */
        log_msg(LOG_VERBOSITY_ERROR, "%i is not a valid or supported protocol.",
            options->spa_proto);
        res = -1;
    }

    return res;
}

/* Function to write SPA packet data to the filesystem
*/
//将SPA数据写入文件
/*
2023/7/20 16:28:35

这段代码是一个名为write_spa_packet_data的函数，用于将SPA数据写入文件。该函数接受两个参数：
一个是fko_ctx_t类型的上下文对象ctx，另一个是const fko_cli_options_t类型的选项指针options。

函数内部定义了一些变量，包括文件指针fp和字符型指针spa_data以及整型变量res。

函数首先调用fko_get_spa_data函数获取SPA数据，并将结果保存在spa_data中。如果获取失败，则打印错误信息并返回-1。

接下来，根据options->save_packet_file_append的值判断是以追加模式还是覆盖模式打开文件。
如果是追加模式，则以追加方式打开文件；如果是覆盖模式，则先删除已存在的文件再以写入方式打开文件。

然后，函数判断文件指针是否为空，如果为空，则打印错误信息并返回-1。

之后，函数使用fprintf函数将SPA数据写入文件。

最后，关闭文件并返回0表示成功。

需要注意的是，这段代码没有对文件操作进行异常处理，比如文件无法打开或写入失败等情况。建议在实际使用中添加适当的异常处理机制。

*/
int write_spa_packet_data(fko_ctx_t ctx, const fko_cli_options_t *options)
{
    FILE   *fp;
    char   *spa_data;
    int     res;

    res = fko_get_spa_data(ctx, &spa_data);

    if(res != FKO_SUCCESS)
    {
        log_msg(LOG_VERBOSITY_ERROR,
            "write_spa_packet_data: Error #%i from fko_get_spa_data: %s",
            res, fko_errstr(res)
        );

        return(-1);
    }

    if (options->save_packet_file_append)
    {
        fp = fopen(options->save_packet_file, "a");
    }
    else
    {
        unlink(options->save_packet_file);
        fp = fopen(options->save_packet_file, "w");
    }

    if(fp == NULL)
    {
        log_msg(LOG_VERBOSITY_ERROR, "write_spa_packet_data: ", strerror(errno));
        return(-1);
    }

    fprintf(fp, "%s\n",
        (spa_data == NULL) ? "<NULL>" : spa_data);

    fclose(fp);

    return(0);
}

/***EOF***/
