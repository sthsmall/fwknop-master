/**
 * \file lib/fko_server_auth.c
 *
 * \brief Set/Get the spa server auth data.
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

/* Set the SPA Server Auth data
*/
int
fko_set_spa_server_auth(fko_ctx_t ctx, const char * const msg)
{
    /****************************************
     *   --DSS This is not supported yet
     ****************************************
    */
    //return(FKO_ERROR_UNSUPPORTED_FEATURE);

#if HAVE_LIBFIU
    fiu_return_on("fko_set_spa_server_auth_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Context must be initialized.
    */
    if(!CTX_INITIALIZED(ctx))
        return FKO_ERROR_CTX_NOT_INITIALIZED;

    /* Gotta have a valid string.
    */
    if(msg == NULL || strnlen(msg, MAX_SPA_SERVER_AUTH_SIZE) == 0)
        return(FKO_ERROR_INVALID_DATA_SRVAUTH_MISSING);

    /* --DSS XXX: Bail out for now.  But consider just
     *            truncating in the future...
    */
    if(strnlen(msg, MAX_SPA_SERVER_AUTH_SIZE) == MAX_SPA_SERVER_AUTH_SIZE)
        return(FKO_ERROR_DATA_TOO_LARGE);

    /* --DSS TODO: ???
     * Do we want to add message type and format checking here
     * or continue to leave it to the implementor?
    */

    /**/

    /* Just in case this is a subsequent call to this function.  We
     * do not want to be leaking memory.
    */
    if(ctx->server_auth != NULL)
        free(ctx->server_auth);

    ctx->server_auth = strdup(msg);

    ctx->state |= FKO_DATA_MODIFIED;

    if(ctx->server_auth == NULL)
        return(FKO_ERROR_MEMORY_ALLOCATION);

    return(FKO_SUCCESS);
}

/* Return the SPA message data.
*/
int
fko_get_spa_server_auth(fko_ctx_t ctx, char **server_auth)
{

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_server_auth_init", FKO_ERROR_CTX_NOT_INITIALIZED);
#endif

    /* Must be initialized
    */
    if(!CTX_INITIALIZED(ctx))
        return(FKO_ERROR_CTX_NOT_INITIALIZED);

    if(server_auth == NULL)
        return(FKO_ERROR_INVALID_DATA);

#if HAVE_LIBFIU
    fiu_return_on("fko_get_spa_server_auth_val", FKO_ERROR_INVALID_DATA);
#endif

    *server_auth = ctx->server_auth;

    return(FKO_SUCCESS);
}

/***EOF***/
