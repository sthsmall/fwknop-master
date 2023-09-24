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
 * \brief The pieces we need to make an FKO SPA data packet我们制作FKO SPA数据包所需的组成部分.
 */
struct fko_context {
    /** \name FKO SPA user-definable message data */

    /*@{*/
    char           *rand_val; //随机值
    char           *username; //用户名
    time_t          timestamp; //时间戳
    short           message_type; //消息类型，表示message字段的内容类型。
    char           *message; //用户自定义的消息数据。
    char           *nat_access; //NAT（Network Address Translation）访问字符串，用于处理NAT穿透。
    char           *server_auth; //服务器认证信息
    unsigned int    client_timeout; //客户端超时时间，表示一次请求的有效期
    /*@}*/
    /** \name FKO SPA user-settable message encoding types */
    /*@{*/
    short  digest_type; //摘要类型，用于消息摘要的算法类型。
    short  encryption_type; //加密类型，表示消息的加密算法类型。
    int    encryption_mode; //加密模式，表示加密算法的模式（例如，ECB，CBC等）
    short  hmac_type; //HMAC（Hash-based Message Authentication Code）类型，用于消息认证码的算法类型
    /*@}*/
    /** \name Computed or predefined data */
    /*@{*/
    char           *version; //版本信息
    char           *digest; //消息摘要，用于数据完整性验证
    int             digest_len; //消息摘要的长度
    /*@}*/
    /** \name Digest of raw encrypted/base64 data
     * This is used for replay attack detection
    */
    /*@{*/
    char           *raw_digest; //原始加密/编码数据的摘要，用于防止重放攻击
    short           raw_digest_type; //原始加密/编码数据的摘要类型
    int             raw_digest_len; //原始加密/编码数据的摘要长度
    /*@}*/
    /** \name Computed processed data (encodings, etc.) */
    /*@{*/
    char           *encoded_msg; //编码后的消息数据
    int             encoded_msg_len; //编码后的消息数据长度
    char           *encrypted_msg; //加密后的消息数据
    int             encrypted_msg_len; //加密后的消息数据长度
    char           *msg_hmac; //消息认证码
    int             msg_hmac_len; //消息认证码的长度
    int             added_salted_str; //标记是否添加了盐值字符串
    int             added_gpg_prefix; //标记是否添加了GPG（GNU Privacy Guard）前缀
    /*@}*/
    /** \name State info */
    /*@{*/
    unsigned int    state; //状态信息，表示当前上下文的状态。
    unsigned char   initval; //初始化值。
    /*@}*/
#if HAVE_LIBGPGME
    /** \name For gpgme support */
    /*@{*/
    char           *gpg_exe; //GPG执行程序路径
    char           *gpg_recipient; //GPG接收者（用于加密和解密）
    char           *gpg_signer; //GPG签名者（用于签名和验证）
    char           *gpg_home_dir; //GPG的主目录

    unsigned char   have_gpgme_context; //是否有GPGME（GnuPG Made Easy）上下文

    gpgme_ctx_t     gpg_ctx; //GPGME上下文
    gpgme_key_t     recipient_key; //GPG接收者密钥
    gpgme_key_t     signer_key; //GPG签名者密钥

    unsigned char   verify_gpg_sigs; //是否验证GPG签名
    unsigned char   ignore_gpg_sig_error; //是否忽略GPG签名错误

    fko_gpg_sig_t   gpg_sigs; //GPG签名信息

    gpgme_error_t   gpg_err; //GPG错误信息
    /*@}*/
#endif /* HAVE_LIBGPGME */
};

#endif /* FKO_CONTEXT_H */

/***EOF***/
