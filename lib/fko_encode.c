/**
 * \file lib/fko_encode.c
 *
 * \brief Encodes some pieces of the spa data then puts together all of
 *          the necessary pieces to gether to create the single encoded
 *          message string.
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
#include "base64.h"
#include "digest.h"

/* Take a given string, base64-encode it and append it to the given
 * buffer.
*/
static int
append_b64(char* tbuf, char *str)
{
    int   len = strnlen(str, MAX_SPA_ENCODED_MSG_SIZE);
    char *bs;

#if HAVE_LIBFIU
    fiu_return_on("append_b64_toobig",
            FKO_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG);
#endif

    if(len >= MAX_SPA_ENCODED_MSG_SIZE)
        return(FKO_ERROR_INVALID_DATA_ENCODE_MESSAGE_TOOBIG);

#if HAVE_LIBFIU
    fiu_return_on("append_b64_calloc", FKO_ERROR_MEMORY_ALLOCATION);
#endif

    bs = calloc(1, ((len/3)*4)+8);
    if(bs == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    b64_encode((unsigned char*)str, bs, len);

    /* --DSS XXX: make sure to check here if later decoding
     *            becomes a problem.
    */
    strip_b64_eq(bs);

    strlcat(tbuf, bs, FKO_ENCODE_TMP_BUF_SIZE);

    free(bs);

    return(FKO_SUCCESS);
}

/* Set the SPA encryption type.
*/
int
fko_encode_spa_data(fko_ctx_t ctx)
{
    int     res, offset = 0;
    char   *tbuf;

#if HAVE_LIBFIU
    fiu_return_on("fko_encode_spa_data_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    /* Check prerequisites.
     * --DSS XXX:  Needs review.  Also, we could make this more robust (or
     *             (at leaset expand the error reporting for the missing
     *             data).
    */
#if HAVE_LIBFIU
    fiu_return_on("fko_encode_spa_data_valid", FKO_ERROR_INCOMPLETE_SPA_DATA);
#endif
    if(  validate_username(ctx->username) != FKO_SUCCESS
      || ctx->version  == NULL || strnlen(ctx->version, MAX_SPA_VERSION_SIZE)  == 0
      || ctx->message  == NULL || strnlen(ctx->message, MAX_SPA_MESSAGE_SIZE)  == 0)
    {
        return(FKO_ERROR_INCOMPLETE_SPA_DATA);
    }

    if(ctx->message_type == FKO_NAT_ACCESS_MSG)
    {
        if(ctx->nat_access == NULL || strnlen(ctx->nat_access, MAX_SPA_MESSAGE_SIZE) == 0)
            return(FKO_ERROR_INCOMPLETE_SPA_DATA);
    }

#if HAVE_LIBFIU
    fiu_return_on("fko_encode_spa_data_calloc", FKO_ERROR_MEMORY_ALLOCATION);
#endif
    /* Allocate our initial tmp buffer.
    */
    tbuf = calloc(1, FKO_ENCODE_TMP_BUF_SIZE);
    if(tbuf == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* Put it together a piece at a time, starting with the rand val.
    */
    strlcpy(tbuf, ctx->rand_val, FKO_ENCODE_TMP_BUF_SIZE);

    /* Add the base64-encoded username.
    */
    strlcat(tbuf, ":", FKO_ENCODE_TMP_BUF_SIZE);
    if((res = append_b64(tbuf, ctx->username)) != FKO_SUCCESS)
    {
        free(tbuf);
        return(res);
    }

    /* Add the timestamp.
    */
    offset = strlen(tbuf);
    snprintf(((char*)tbuf+offset), FKO_ENCODE_TMP_BUF_SIZE - offset,
            ":%u:", (unsigned int) ctx->timestamp);

    /* Add the version string.
    */
    strlcat(tbuf, ctx->version, FKO_ENCODE_TMP_BUF_SIZE);

    /* Before we add the message type value, we will once again
     * check for whether or not a client_timeout was specified
     * since the message_type was set.  If this is the case, then
     * we want to adjust the message_type first.  The easy way
     * to do this is simply call fko_set_spa_client_timeout and set
     * it to its current value.  This will force a re-check and
     * possible reset of the message type.
     *
    */
    fko_set_spa_client_timeout(ctx, ctx->client_timeout);

    /* Add the message type value.
    */
    offset = strlen(tbuf);
    snprintf(((char*)tbuf+offset), FKO_ENCODE_TMP_BUF_SIZE - offset,
            ":%i:", ctx->message_type);

    /* Add the base64-encoded SPA message.
    */
    if((res = append_b64(tbuf, ctx->message)) != FKO_SUCCESS)
    {
        free(tbuf);
        return(res);
    }

    /* If a nat_access message was given, add it to the SPA
     * message.
    */
    if(ctx->nat_access != NULL)
    {
        strlcat(tbuf, ":", FKO_ENCODE_TMP_BUF_SIZE);
        if((res = append_b64(tbuf, ctx->nat_access)) != FKO_SUCCESS)
        {
            free(tbuf);
            return(res);
        }
    }

    /* If we have a server_auth field set.  Add it here.
     *
    */
    if(ctx->server_auth != NULL)
    {
        strlcat(tbuf, ":", FKO_ENCODE_TMP_BUF_SIZE);
        if((res = append_b64(tbuf, ctx->server_auth)) != FKO_SUCCESS)
        {
            free(tbuf);
            return(res);
        }
    }

    /* If a client timeout is specified and we are not dealing with a
     * SPA command message, add the timeout here.
    */
    if(ctx->client_timeout > 0 && ctx->message_type != FKO_COMMAND_MSG)
    {
        offset = strlen(tbuf);
        snprintf(((char*)tbuf+offset), FKO_ENCODE_TMP_BUF_SIZE - offset,
                ":%i", ctx->client_timeout);
    }

    /* If encoded_msg is not null, then we assume it needs to
     * be freed before re-assignment.
    */
    if(ctx->encoded_msg != NULL)
        free(ctx->encoded_msg);

    /* Copy our encoded data into the context.
    */
    ctx->encoded_msg = strdup(tbuf);
    free(tbuf);

    if(ctx->encoded_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    ctx->encoded_msg_len = strnlen(ctx->encoded_msg, MAX_SPA_ENCODED_MSG_SIZE);

    if(! is_valid_encoded_msg_len(ctx->encoded_msg_len))
        return(FKO_ERROR_INVALID_DATA_ENCODE_MSGLEN_VALIDFAIL);

    /* At this point we can compute the digest for this SPA data.
    */
    if((res = fko_set_spa_digest(ctx)) != FKO_SUCCESS)
        return(res);

    /* Here we can clear the modified flags on the SPA data fields.
    */
    FKO_CLEAR_SPA_DATA_MODIFIED(ctx);

    return(FKO_SUCCESS);
}

/* Return the fko SPA encrypted data.
*/
int
fko_get_encoded_data(fko_ctx_t ctx, char **enc_msg)
{
    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(enc_msg == NULL)
        return(FKO_ERROR_INVALID_DATA);

    *enc_msg = ctx->encoded_msg;

    return(FKO_SUCCESS);
}

/* Set the fko SPA encoded data (this is a convenience
 * function mostly used for tests that involve fuzzing).
*/
#if FUZZING_INTERFACES
int
fko_set_encoded_data(fko_ctx_t ctx,
        const char * const encoded_msg, const int msg_len,
        const int require_digest, const int digest_type)
{
    char *tbuf   = NULL;
    int          res = FKO_SUCCESS, mlen;

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(encoded_msg == NULL)
        return(FKO_ERROR_INVALID_DATA);

    ctx->encoded_msg = strdup(encoded_msg);

    ctx->state |= FKO_DATA_MODIFIED;

    if(ctx->encoded_msg == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    /* allow arbitrary length (i.e. let the decode routines validate
     * SPA message length).
    */
    ctx->encoded_msg_len = msg_len;

    if(require_digest)
    {
        fko_set_spa_digest_type(ctx, digest_type);
        if((res = fko_set_spa_digest(ctx)) != FKO_SUCCESS)
        {
            return res;
        }

        /* append the digest to the encoded message buffer
        */
        mlen = ctx->encoded_msg_len + ctx->digest_len + 2;
        tbuf = calloc(1, mlen);
        if(tbuf == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        /* memcpy since the provided encoded buffer might
         * have an embedded NULL?
        */
        mlen = snprintf(tbuf, mlen, "%s:%s", ctx->encoded_msg, ctx->digest);

        if(ctx->encoded_msg != NULL)
            free(ctx->encoded_msg);

        ctx->encoded_msg = strdup(tbuf);
        free(tbuf);

        if(ctx->encoded_msg == NULL)
            return(FKO_ERROR_MEMORY_ALLOCATION);

        ctx->encoded_msg_len = mlen;
    }

    FKO_CLEAR_SPA_DATA_MODIFIED(ctx);

    return(FKO_SUCCESS);
}
#endif

/***EOF***/
