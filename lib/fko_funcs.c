/**
 * \file lib/fko_funcs.c
 *
 * \brief General utility functions for libfko
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
#include "fko_common.h"
#include "fko.h"
#include "cipher_funcs.h"
#include "base64.h"
#include "digest.h"

/* Initialize an fko context.
*/
//初始化一个新的fko文本
/*
这段代码是一个函数 fko_new 的实现，用于创建并初始化一个 fko_ctx_t 上下文结构体对象。

首先，定义了一个局部变量 ctx 并初始化为 NULL。

接着，调用 calloc 函数分配了一块内存，用于存储 ctx 结构体对象，并将其初始化为全零。
如果内存分配失败，则返回错误码 FKO_ERROR_MEMORY_ALLOCATION。

然后，设定了一些默认值和状态，设置了上下文的初始状态为 FKO_CTX_INITIALIZED。

之后，使用 strdup 函数复制了一个字符串常量 FKO_PROTOCOL_VERSION 到 ver 变量中，并将其赋值给上下文对象的 version 成员变量。
如果内存分配失败，则销毁上下文对象并返回错误码 FKO_ERROR_MEMORY_ALLOCATION。

接下来，调用 fko_set_rand_value 函数设置上下文对象的随机值。如果设置失败，则销毁上下文对象并返回对应的错误码。

然后，调用 fko_set_username、fko_set_timestamp、fko_set_spa_digest_type 等函数依次设置上下文对象的用户名、
时间戳、默认摘要类型、默认消息类型以及默认加密类型等。

最后，设置了一些特定条件下的操作，如开启 GPG 签名验证等。

最终，将创建并初始化完成的上下文对象通过指针 r_ctx 返回。

函数执行成功时返回 FKO_SUCCESS，否则根据具体错误情况返回相应的错误码。

*/
int
fko_new(fko_ctx_t *r_ctx)
{
    fko_ctx_t   ctx = NULL;
    int         res;
    char       *ver;

#if HAVE_LIBFIU
    fiu_return_on("fko_new_calloc", FKO_ERROR_MEMORY_ALLOCATION);
#endif

    ctx = calloc(1, sizeof *ctx); //分配内存并初始化
    if(ctx == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Set default values and state.
     *
     * Note: We initialize the context early so that the fko_set_xxx
     *       functions can operate properly. If there are any problems during
     *       initialization, then fko_destroy() is called which will clean up
     *       the context.
     * 提前初始化以便fko_set_xxx函数能成功运行，如果在初始化遇到了错误，调用fko_destroy函数销毁
    */
    ctx->initval = FKO_CTX_INITIALIZED;

    /* Set the version string.
    */
    ver = strdup(FKO_PROTOCOL_VERSION);
    if(ver == NULL)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }
    ctx->version = ver;

    /* Rand value.
    */
    res = fko_set_rand_value(ctx, NULL);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Username.
    */
    res = fko_set_username(ctx, NULL);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Timestamp.
    */
    res = fko_set_timestamp(ctx, 0);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Default Digest Type.
    */
    res = fko_set_spa_digest_type(ctx, FKO_DEFAULT_DIGEST);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Default Message Type.
    */
    res = fko_set_spa_message_type(ctx, FKO_DEFAULT_MSG_TYPE);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Default Encryption Type.
    */
    res = fko_set_spa_encryption_type(ctx, FKO_DEFAULT_ENCRYPTION);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Default is Rijndael in CBC mode
    */
    res = fko_set_spa_encryption_mode(ctx, FKO_DEFAULT_ENC_MODE);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

#if HAVE_LIBGPGME
    /* Set gpg signature verify on.
    */
    ctx->verify_gpg_sigs = 1;

#endif /* HAVE_LIBGPGME */

    FKO_SET_CTX_INITIALIZED(ctx);

    *r_ctx = ctx;

    return(FKO_SUCCESS);
}

/* Initialize an fko context with external (encrypted/encoded) data.
 * This is used to create a context with the purpose of decoding
 * and parsing the provided data into the context data.
*/
/*
详细请查看声明，因为太多不能快捷显示
*/
int
fko_new_with_data(fko_ctx_t *r_ctx, const char * const enc_msg,
    const char * const dec_key, const int dec_key_len,
    int encryption_mode, const char * const hmac_key,
    const int hmac_key_len, const int hmac_type)
{
    fko_ctx_t   ctx = NULL;
    int         res = FKO_SUCCESS; /* Are we optimistic or what? */
    int         enc_msg_len;

#if HAVE_LIBFIU
    fiu_return_on("fko_new_with_data_msg",
            FKO_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING);
#endif

    if(enc_msg == NULL)
        return(FKO_ERROR_INVALID_DATA_FUNCS_NEW_ENCMSG_MISSING);

#if HAVE_LIBFIU
    fiu_return_on("fko_new_with_data_keylen",
            FKO_ERROR_INVALID_KEY_LEN);
#endif

    if(dec_key_len < 0 || hmac_key_len < 0)
        return(FKO_ERROR_INVALID_KEY_LEN);

    ctx = calloc(1, sizeof *ctx);
    if(ctx == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    enc_msg_len = strnlen(enc_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(enc_msg_len))
    {
        free(ctx);
        return(FKO_ERROR_INVALID_DATA_FUNCS_NEW_MSGLEN_VALIDFAIL);
    }

    /* First, add the data to the context.
    */
    ctx->encrypted_msg     = strdup(enc_msg);
    ctx->encrypted_msg_len = enc_msg_len;

    if(ctx->encrypted_msg == NULL)
    {
        free(ctx);
        return(FKO_ERROR_MEMORY_ALLOCATION);
    }

    /* Default Encryption Mode (Rijndael in CBC mode)
    */
    ctx->initval = FKO_CTX_INITIALIZED;
    res = fko_set_spa_encryption_mode(ctx, encryption_mode);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* HMAC digest type
    */
    res = fko_set_spa_hmac_type(ctx, hmac_type);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Check HMAC if the access stanza had an HMAC key
    */
    if(hmac_key_len > 0 && hmac_key != NULL)
        res = fko_verify_hmac(ctx, hmac_key, hmac_key_len);
    if(res != FKO_SUCCESS)
    {
        fko_destroy(ctx);
        ctx = NULL;
        return res;
    }

    /* Consider it initialized here.
    */
    FKO_SET_CTX_INITIALIZED(ctx);

    /* If a decryption key is provided, go ahead and decrypt and decode.
    */
    if(dec_key != NULL)
    {
        res = fko_decrypt_spa_data(ctx, dec_key, dec_key_len);

        if(res != FKO_SUCCESS)
        {
            fko_destroy(ctx);
            ctx = NULL;
            *r_ctx = NULL; /* Make sure the caller ctx is null just in case */
            return(res);
        }
    }

#if HAVE_LIBGPGME
    /* Set gpg signature verify on.
    */
    ctx->verify_gpg_sigs = 1;

#endif /* HAVE_LIBGPGME */

    *r_ctx = ctx;

    return(res);
}

/* Destroy a context and free its resources
 * 销毁一个上下文并释放其资源
*/
int
fko_destroy(fko_ctx_t ctx)
{
    int zero_free_rv = FKO_SUCCESS;

#if HAVE_LIBGPGME
    fko_gpg_sig_t   gsig, tgsig;
#endif

    if(!CTX_INITIALIZED(ctx))
        return(zero_free_rv);

    if(ctx->rand_val != NULL)
        free(ctx->rand_val);

    if(ctx->username != NULL)
        free(ctx->username);

    if(ctx->version != NULL)
        free(ctx->version);

    if(ctx->message != NULL)
        free(ctx->message);

    if(ctx->nat_access != NULL)
        free(ctx->nat_access);

    if(ctx->server_auth != NULL)
        free(ctx->server_auth);

    if(ctx->digest != NULL)
        if(zero_free(ctx->digest, ctx->digest_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->raw_digest != NULL)
        if(zero_free(ctx->raw_digest, ctx->raw_digest_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->encoded_msg != NULL)
        if(zero_free(ctx->encoded_msg, ctx->encoded_msg_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->encrypted_msg != NULL)
        if(zero_free(ctx->encrypted_msg, ctx->encrypted_msg_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

    if(ctx->msg_hmac != NULL)
        if(zero_free(ctx->msg_hmac, ctx->msg_hmac_len) != FKO_SUCCESS)
            zero_free_rv = FKO_ERROR_ZERO_OUT_DATA;

#if HAVE_LIBGPGME
    if(ctx->gpg_exe != NULL)
        free(ctx->gpg_exe);

    if(ctx->gpg_home_dir != NULL)
        free(ctx->gpg_home_dir);

    if(ctx->gpg_recipient != NULL)
        free(ctx->gpg_recipient);

    if(ctx->gpg_signer != NULL)
        free(ctx->gpg_signer);

    if(ctx->recipient_key != NULL)
        gpgme_key_unref(ctx->recipient_key);

    if(ctx->signer_key != NULL)
        gpgme_key_unref(ctx->signer_key);

    if(ctx->gpg_ctx != NULL)
        gpgme_release(ctx->gpg_ctx);

    gsig = ctx->gpg_sigs;
    while(gsig != NULL)
    {
        if(gsig->fpr != NULL)
            free(gsig->fpr);

        tgsig = gsig;
        gsig = gsig->next;

        free(tgsig);
    }

#endif /* HAVE_LIBGPGME */

    memset(ctx, 0x0, sizeof(*ctx));

    free(ctx);

    return(zero_free_rv);
}

/* Generate Rijndael and HMAC keys from /dev/random and base64
 * encode them
*/
/*
这段代码是一个实现密钥生成的函数。它接收一些参数，包括 key_base64、key_len、hmac_key_base64、hmac_key_len 和 hmac_type，并返回一个整数。

在函数中，首先声明了用于存储密钥和HMAC 密钥的变量 key 和 hmac_key，它们分别是 RIJNDAEL_MAX_KEYSIZE 和 SHA512_BLOCK_LEN 字节大小的无符号字符数组。
然后，对传入的密钥长度和HMAC 密钥长度进行处理，如果它们等于默认值 FKO_DEFAULT_KEY_LEN，则将其替换为相应的长度。
接下来，根据 hmac_type 的不同取值，确定了 HMAC 密钥的长度。

然后会对密钥长度和HMAC 密钥长度进行有效性验证，确保它们在有效范围内。如果验证失败，则返回相应的错误代码。

之后，调用 get_random_data 函数生成随机的密钥和HMAC 密钥。生成的密钥和HMAC 密钥会被编码成 Base64 格式，
并存储到相应的输出参数 key_base64 和 hmac_key_base64 中。

最后，函数返回 FKO_SUCCESS 表示密钥生成成功。

总结来说，这段代码实现了生成密钥和HMAC 密钥，并将其以 Base64 编码格式返回的功能。
*/
int
fko_key_gen(char * const key_base64, const int key_len,
        char * const hmac_key_base64, const int hmac_key_len,
        const int hmac_type)
{
    unsigned char key[RIJNDAEL_MAX_KEYSIZE];
    unsigned char hmac_key[SHA512_BLOCK_LEN];
    int klen      = key_len;
    int hmac_klen = hmac_key_len;
    int b64_len   = 0;

    if(key_len == FKO_DEFAULT_KEY_LEN)
        klen = RIJNDAEL_MAX_KEYSIZE;

    if(hmac_key_len == FKO_DEFAULT_KEY_LEN)
    {
        if(hmac_type == FKO_DEFAULT_HMAC_MODE
                || hmac_type == FKO_HMAC_SHA256)
            hmac_klen = SHA256_BLOCK_LEN;
        else if(hmac_type == FKO_HMAC_MD5)
            hmac_klen = MD5_DIGEST_LEN;
        else if(hmac_type == FKO_HMAC_SHA1)
            hmac_klen = SHA1_DIGEST_LEN;
        else if(hmac_type == FKO_HMAC_SHA384)
            hmac_klen = SHA384_BLOCK_LEN;
        else if(hmac_type == FKO_HMAC_SHA512)
            hmac_klen = SHA512_BLOCK_LEN;
    }

    if((klen < 1) || (klen > RIJNDAEL_MAX_KEYSIZE))
        return(FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEYLEN_VALIDFAIL);

    if((hmac_klen < 1) || (hmac_klen > SHA512_BLOCK_LEN))
        return(FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMACLEN_VALIDFAIL);

    get_random_data(key, klen);
    get_random_data(hmac_key, hmac_klen);

    b64_len = b64_encode(key, key_base64, klen);
    if(b64_len < klen)
        return(FKO_ERROR_INVALID_DATA_FUNCS_GEN_KEY_ENCODEFAIL);

    b64_len = b64_encode(hmac_key, hmac_key_base64, hmac_klen);
    if(b64_len < hmac_klen)
        return(FKO_ERROR_INVALID_DATA_FUNCS_GEN_HMAC_ENCODEFAIL);

    return(FKO_SUCCESS);
}

/* Provide an FKO wrapper around base64 encode/decode functions
*/


*/
int
fko_base64_encode(unsigned char * const in, char * const out, int in_len)
{
    return b64_encode(in, out, in_len);
}

int
fko_base64_decode(const char * const in, unsigned char *out)
{
    return b64_decode(in, out);
}

/* Return the fko version
*/
// fko_get_version: 用于获取fko的版本号
int
fko_get_version(fko_ctx_t ctx, char **version)
{

#if HAVE_LIBFIU
    fiu_return_on("fko_get_version_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(version == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_version_val", FKO_ERROR_INVALID_DATA);
#endif

    *version = ctx->version;

    return(FKO_SUCCESS);
}

/* Final update and encoding of data in the context.
 * This does require all requisite fields be properly
 * set.
*/

/*
这段代码是一个名为 fko_spa_data_final 的函数，它用于最终处理 SPA（Secure Password Authentication）数据。
该函数接受一个 fko_ctx_t 类型的上下文参数 ctx，以及两个加密密钥参数 enc_key 和 hmac_key，
以及对应的密钥长度参数 enc_key_len 和 hmac_key_len。函数返回一个整数。

在函数中，首先通过条件编译判断上下文是否已初始化。如果未初始化，则返回错误代码 FKO_ERROR_CTX_NOT_INITIALIZED。

然后，检查传入的加密密钥长度是否小于 0，如果是，则返回错误代码 FKO_ERROR_INVALID_KEY_LEN。

接着，调用 fko_encrypt_spa_data 函数对 SPA 数据进行加密。加密成功后，检查上下文中的哈希类型是否为已知类型。
如果哈希类型不为未知类型，则执行以下操作：

    检查传入的哈希密钥长度是否小于 0，如果是，则返回错误代码 FKO_ERROR_INVALID_KEY_LEN。
    检查哈希密钥是否为空指针，如果是，则返回错误代码 FKO_ERROR_INVALID_KEY_LEN。
    调用 fko_set_spa_hmac 函数设置 SPA 数据的哈希值。
    如果设置哈希值成功，则将哈希值追加到已经进行过 Base64 编码和去除尾部 '=' 字符的加密数据中。
    更新上下文中的加密数据和加密数据长度。

最后，函数返回加密和哈希操作的结果。

综上所述，这段代码实现了最终处理 SPA 数据的功能，包括对数据进行加密和追加哈希值。
代码中还包含了对错误情况的处理和对上下文状态的检查。

*/
int
fko_spa_data_final(fko_ctx_t ctx,
    const char * const enc_key, const int enc_key_len,
    const char * const hmac_key, const int hmac_key_len)
{
    char   *tbuf;
    int     res = 0, data_with_hmac_len = 0;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(enc_key_len < 0)
        return(FKO_ERROR_INVALID_KEY_LEN);

    res = fko_encrypt_spa_data(ctx, enc_key, enc_key_len);

    /* Now calculate hmac if so configured
    */
   //如果设置了要使用HMAC
    if (res == FKO_SUCCESS && ctx->hmac_type != FKO_HMAC_UNKNOWN)
    {
        if(hmac_key_len < 0)
            return(FKO_ERROR_INVALID_KEY_LEN);

        if(hmac_key == NULL)
            return(FKO_ERROR_INVALID_KEY_LEN);

        //将encrypt_msg生成消息摘要
        res = fko_set_spa_hmac(ctx, hmac_key, hmac_key_len);

        if (res == FKO_SUCCESS)
        {
            /* Now that we have the hmac, append it to the
             * encrypted data (which has already been base64-encoded
             * and the trailing '=' chars stripped off).
            */
            data_with_hmac_len
                = ctx->encrypted_msg_len+1+ctx->msg_hmac_len+1;

            tbuf = realloc(ctx->encrypted_msg, data_with_hmac_len);
            if (tbuf == NULL)
                return(FKO_ERROR_MEMORY_ALLOCATION);

            //将tbuf设置成encrypted_msg+msg_hmac的形式
            strlcat(tbuf, ctx->msg_hmac, data_with_hmac_len);

            ctx->encrypted_msg     = tbuf;
            ctx->encrypted_msg_len = data_with_hmac_len;
        }
    }

    return res;
}

/* Return the fko SPA encrypted data.
*/
/*
在这个函数中，上下文 ctx 的作用是存储与 SPA 数据相关的信息和状态。该上下文参数 ctx 是一个 fko_ctx_t 类型的结构体，在函数调用之前需要先初始化。

上下文对象 ctx 存储了一些关键的数据，包括加密后的 SPA 数据、加密类型等。它的作用是提供函数执行所需的信息和状态，以便正确地处理 SPA 数据。

在函数中，上下文被用于以下几个方面：

    检查上下文是否已初始化：通过检查上下文的初始化状态，可以确保函数在处理 SPA 数据之前，
    上下文对象已经经过正确的初始化。如果上下文未初始化，则函数会返回错误代码。

    获取加密数据：函数通过访问上下文对象中的 encrypted_msg 成员来获取加密数据。
    这个成员存储了加密后的 SPA 数据，函数将其赋值给 spa_data 返回给调用者。

    检查加密类型：根据上下文中的 encryption_type 成员，判断加密类型是 Rijndael 还是 GnuPG。
    根据不同类型的加密规则，调整返回的 SPA 数据指针的位置。

总之，上下文在这个函数中的作用是提供必要的数据和状态，以便函数能够正确地处理和返回 SPA 数据。
它承载了与 SPA 数据相关的信息，帮助函数在正确的上下文环境中执行操作。

该函数并没有加密数据，而是通过上下文来获取加密的SPA，并通过该函数返回加密的SPA
*/
int
fko_get_spa_data(fko_ctx_t ctx, char **spa_data)
{

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_data_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(spa_data == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_data_val", FKO_ERROR_INVALID_DATA);
#endif

    /* We expect to have encrypted data to process.  If not, we bail.
    */
   //我们期望有加密数据来处理。如果没有，我们就放弃了。
    if(ctx->encrypted_msg == NULL || ! is_valid_encoded_msg_len(
                strnlen(ctx->encrypted_msg, MAX_SPA_ENCODED_MSG_SIZE)))
        return(FKO_ERROR_MISSING_ENCODED_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_data_encoded", FKO_ERROR_MISSING_ENCODED_DATA);
#endif

    *spa_data = ctx->encrypted_msg;

    /* Notice we omit the first 10 bytes if Rijndael encryption is
     * used (to eliminate the consistent 'Salted__' string), and
     * in GnuPG mode we eliminate the consistent 'hQ' base64 encoded
     * prefix
    */
   //注意，如果使用Rijndael加密，我们省略了前10个字节（以消除一致的“Salted__”字符串），
    //在GnuPG模式下，我们消除了一致的“hQ”base64编码前缀
    if(ctx->encryption_type == FKO_ENCRYPTION_RIJNDAEL)
        *spa_data += B64_RIJNDAEL_SALT_STR_LEN;
    else if(ctx->encryption_type == FKO_ENCRYPTION_GPG)
        *spa_data += B64_GPG_PREFIX_STR_LEN;

    return(FKO_SUCCESS);
}

/* Set the fko SPA encrypted data.
*/
/*
这段代码是一个名为 fko_set_spa_data 的函数，用于设置 SPA（Secure Password Authentication）数据。
函数接受一个 fko_ctx_t 类型的上下文参数 ctx 和一个指向常量字符的指针 enc_msg 参数，用于传入加密后的 SPA 数据。函数返回一个整数。

在函数中，首先通过条件编译判断上下文是否已初始化。如果未初始化，则返回错误代码 FKO_ERROR_CTX_NOT_INITIALIZED。

然后，检查传入的 enc_msg 是否为空指针，如果是，则返回错误代码 FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL。

接着，通过 strnlen 函数获取 enc_msg 的长度，并将其赋值给 enc_msg_len 变量。

然后，调用 is_valid_encoded_msg_len 函数验证 enc_msg_len 是否符合规定的有效长度。如果长度不合法，
则返回错误代码 FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL。

接下来，检查上下文中的 encrypted_msg 是否已存在，如果存在，则释放之前分配的内存。

然后，将 enc_msg 中的数据拷贝到上下文的 encrypted_msg 成员中，并将其长度赋值给 encrypted_msg_len。

最后，如果内存分配失败，则返回错误代码 FKO_ERROR_MEMORY_ALLOCATION，否则返回成功代码 FKO_SUCCESS。

综上所述，这段代码实现了设置加密后的 SPA 数据的功能，包括检查上下文状态、验证输入参数、拷贝数据到上下文中。
如果一切正常，函数会成功设置 SPA 数据并返回成功代码。


*/
int
fko_set_spa_data(fko_ctx_t ctx, const char * const enc_msg)
{
    int         enc_msg_len;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    if(enc_msg == NULL)
        return(FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    enc_msg_len = strnlen(enc_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(enc_msg_len))
        return(FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    if(ctx->encrypted_msg != NULL)
        free(ctx->encrypted_msg);

    /* First, add the data to the context.
    */
    ctx->encrypted_msg = strdup(enc_msg);
    ctx->encrypted_msg_len = enc_msg_len;

    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

#if AFL_FUZZING
/* provide a way to set the encrypted data directly without base64 encoding.
 * This allows direct AFL fuzzing against decryption routines.
*/
int
fko_afl_set_spa_data(fko_ctx_t ctx, const char * const enc_msg, const int enc_msg_len)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    if(enc_msg == NULL)
        return(FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    if(! is_valid_encoded_msg_len(enc_msg_len))
        return(FKO_ERROR_INVALID_DATA_FUNCS_SET_MSGLEN_VALIDFAIL);

    if(ctx->encrypted_msg != NULL)
        free(ctx->encrypted_msg);

    /* Copy the raw encrypted data into the context
    */
    ctx->encrypted_msg = calloc(1, enc_msg_len);
    if(ctx->encrypted_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    memcpy(ctx->encrypted_msg, enc_msg, enc_msg_len);

    ctx->encrypted_msg_len = enc_msg_len;

    return(FKO_SUCCESS);
}
#endif

/***EOF***/
