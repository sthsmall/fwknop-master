/**
 * \file lib/fko_context.h
 *
 * \brief fko context definition.
 */

/*
 *  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
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
#ifndef FKO_CONTEXT_H
#define FKO_CONTEXT_H 1

#include "fko_common.h"

#if HAVE_LIBGPGME
  #include <gpgme.h>
#endif

#if HAVE_LIBGPGME || DOXYGEN

/**
 *
 * \struct fko_gpg_sig
 *
 * \brief Structure to hold a list of the gpg signature information we are interested in.
 */
struct fko_gpg_sig {
    struct fko_gpg_sig *next; /**< link to next member */
    gpgme_sigsum_t      summary;
    gpgme_error_t       status;
    gpgme_validity_t    validity;
    char               *fpr;
};

typedef struct fko_gpg_sig *fko_gpg_sig_t;
#endif /* HAVE_LIBGPGME */

/**
 *
 * \struct fko_context
 *
 * \brief The pieces we need to make an FKO SPA data packet.
 */
/*
这段代码定义了一个名为fko_context的结构体，该结构体用于存储FWKNOP（FireWall KNock OPerator）中的上下文信息。FWKNOP是一个用于网络安全的工具，允许用户在受保护的主机上通过发送加密的"knock"消息来打开防火墙规则以获得访问权限。下面逐个解释结构体中各个参数的作用：

rand_val: 随机值，用于生成安全令牌的一部分。

username: 用户名，用于生成安全令牌的一部分。

timestamp: 时间戳，用于生成安全令牌的一部分。

message_type: 消息类型，表示message字段的内容类型。

message: 用户自定义的消息数据。

nat_access: NAT（Network Address Translation）访问字符串，用于处理NAT穿透。

server_auth: 服务器认证信息。

client_timeout: 客户端超时时间，表示一次请求的有效期。

digest_type: 摘要类型，用于消息摘要的算法类型。

encryption_type: 加密类型，表示消息的加密算法类型。

encryption_mode: 加密模式，表示加密算法的模式（例如，ECB，CBC等）。

hmac_type: HMAC（Hash-based Message Authentication Code）类型，用于消息认证码的算法类型。

version: 版本信息。

digest: 消息摘要，用于数据完整性验证。

digest_len: 消息摘要的长度。

raw_digest: 原始加密/编码数据的摘要，用于防止重放攻击。

raw_digest_type: 原始加密/编码数据的摘要类型。

raw_digest_len: 原始加密/编码数据的摘要长度。

encoded_msg: 编码后的消息数据。

encoded_msg_len: 编码后的消息数据长度。

encrypted_msg: 加密后的消息数据。

encrypted_msg_len: 加密后的消息数据长度。

msg_hmac: 消息认证码。

msg_hmac_len: 消息认证码的长度。

added_salted_str: 标记是否添加了盐值字符串。

added_gpg_prefix: 标记是否添加了GPG（GNU Privacy Guard）前缀。

state: 状态信息，表示当前上下文的状态。

initval: 初始化值。

gpg_exe: GPG执行程序路径。

gpg_recipient: GPG接收者（用于加密和解密）。

gpg_signer: GPG签名者（用于签名和验证）。

gpg_home_dir: GPG的主目录。

have_gpgme_context: 是否有GPGME（GnuPG Made Easy）上下文。

gpg_ctx: GPGME上下文。

recipient_key: GPG接收者密钥。

signer_key: GPG签名者密钥。

verify_gpg_sigs: 是否验证GPG签名。

ignore_gpg_sig_error: 是否忽略GPG签名错误。

gpg_sigs: GPG签名信息。

gpg_err: GPG错误信息。
*/
struct fko_context {
    /** \name FKO SPA user-definable message data */

    /*@{*/
    char           *rand_val;
    char           *username; 
    time_t          timestamp;
    short           message_type;
    char           *message;
    char           *nat_access;
    char           *server_auth;
    unsigned int    client_timeout;
    /*@}*/
    /** \name FKO SPA user-settable message encoding types */
    /*@{*/
    short  digest_type;
    short  encryption_type;
    int    encryption_mode;
    short  hmac_type;
    /*@}*/
    /** \name Computed or predefined data */
    /*@{*/
    char           *version;
    char           *digest;
    int             digest_len;
    /*@}*/
    /** \name Digest of raw encrypted/base64 data
     * This is used for replay attack detection
    */
    /*@{*/
    char           *raw_digest;
    short           raw_digest_type;
    int             raw_digest_len;
    /*@}*/
    /** \name Computed processed data (encodings, etc.) */
    /*@{*/
    char           *encoded_msg;
    int             encoded_msg_len;
    char           *encrypted_msg;
    int             encrypted_msg_len;
    char           *msg_hmac;
    int             msg_hmac_len;
    int             added_salted_str;
    int             added_gpg_prefix;
    /*@}*/
    /** \name State info */
    /*@{*/
    unsigned int    state;
    unsigned char   initval;
    /*@}*/
#if HAVE_LIBGPGME
    /** \name For gpgme support */
    /*@{*/
    char           *gpg_exe;
    char           *gpg_recipient;
    char           *gpg_signer;
    char           *gpg_home_dir;

    unsigned char   have_gpgme_context;

    gpgme_ctx_t     gpg_ctx;
    gpgme_key_t     recipient_key;
    gpgme_key_t     signer_key;

    unsigned char   verify_gpg_sigs;
    unsigned char   ignore_gpg_sig_error;

    fko_gpg_sig_t   gpg_sigs;

    gpgme_error_t   gpg_err;
    /*@}*/
#endif /* HAVE_LIBGPGME */
};

#endif /* FKO_CONTEXT_H */

/***EOF***/
