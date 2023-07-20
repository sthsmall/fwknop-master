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
��δ��붨����һ����Ϊfko_context�Ľṹ�壬�ýṹ�����ڴ洢FWKNOP��FireWall KNock OPerator���е���������Ϣ��FWKNOP��һ���������簲ȫ�Ĺ��ߣ������û����ܱ�����������ͨ�����ͼ��ܵ�"knock"��Ϣ���򿪷���ǽ�����Ի�÷���Ȩ�ޡ�����������ͽṹ���и������������ã�

rand_val: ���ֵ���������ɰ�ȫ���Ƶ�һ���֡�

username: �û������������ɰ�ȫ���Ƶ�һ���֡�

timestamp: ʱ������������ɰ�ȫ���Ƶ�һ���֡�

message_type: ��Ϣ���ͣ���ʾmessage�ֶε��������͡�

message: �û��Զ������Ϣ���ݡ�

nat_access: NAT��Network Address Translation�������ַ��������ڴ���NAT��͸��

server_auth: ��������֤��Ϣ��

client_timeout: �ͻ��˳�ʱʱ�䣬��ʾһ���������Ч�ڡ�

digest_type: ժҪ���ͣ�������ϢժҪ���㷨���͡�

encryption_type: �������ͣ���ʾ��Ϣ�ļ����㷨���͡�

encryption_mode: ����ģʽ����ʾ�����㷨��ģʽ�����磬ECB��CBC�ȣ���

hmac_type: HMAC��Hash-based Message Authentication Code�����ͣ�������Ϣ��֤����㷨���͡�

version: �汾��Ϣ��

digest: ��ϢժҪ������������������֤��

digest_len: ��ϢժҪ�ĳ��ȡ�

raw_digest: ԭʼ����/�������ݵ�ժҪ�����ڷ�ֹ�طŹ�����

raw_digest_type: ԭʼ����/�������ݵ�ժҪ���͡�

raw_digest_len: ԭʼ����/�������ݵ�ժҪ���ȡ�

encoded_msg: ��������Ϣ���ݡ�

encoded_msg_len: ��������Ϣ���ݳ��ȡ�

encrypted_msg: ���ܺ����Ϣ���ݡ�

encrypted_msg_len: ���ܺ����Ϣ���ݳ��ȡ�

msg_hmac: ��Ϣ��֤�롣

msg_hmac_len: ��Ϣ��֤��ĳ��ȡ�

added_salted_str: ����Ƿ��������ֵ�ַ�����

added_gpg_prefix: ����Ƿ������GPG��GNU Privacy Guard��ǰ׺��

state: ״̬��Ϣ����ʾ��ǰ�����ĵ�״̬��

initval: ��ʼ��ֵ��

gpg_exe: GPGִ�г���·����

gpg_recipient: GPG�����ߣ����ڼ��ܺͽ��ܣ���

gpg_signer: GPGǩ���ߣ�����ǩ������֤����

gpg_home_dir: GPG����Ŀ¼��

have_gpgme_context: �Ƿ���GPGME��GnuPG Made Easy�������ġ�

gpg_ctx: GPGME�����ġ�

recipient_key: GPG��������Կ��

signer_key: GPGǩ������Կ��

verify_gpg_sigs: �Ƿ���֤GPGǩ����

ignore_gpg_sig_error: �Ƿ����GPGǩ������

gpg_sigs: GPGǩ����Ϣ��

gpg_err: GPG������Ϣ��
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
