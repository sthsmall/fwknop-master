/**
 * \file server/replay_cache.h
 *
 * \brief Header file for fwknopd replay_cache.c functions.
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
#ifndef REPLAY_CACHE_H
#define REPLAY_CACHE_H

#include "fwknopd_common.h"
#include "fko.h"

typedef struct digest_cache_info {
    unsigned int    src_ip;
    unsigned int    dst_ip;
    unsigned short  src_port;
    unsigned short  dst_port;
    unsigned char   proto;
    time_t          created;
    char           *digest;
#if ! USE_FILE_CACHE
    time_t          first_replay;
    time_t          last_replay;
    int             replay_count;
#endif
} digest_cache_info_t;

#if USE_FILE_CACHE
struct digest_cache_list {
    digest_cache_info_t cache_info;
    struct digest_cache_list *next;
};
#endif

/* Prototypes
*/
int replay_cache_init(fko_srv_options_t *opts);
int is_replay(fko_srv_options_t *opts, char *digest);
int add_replay(fko_srv_options_t *opts, char *digest);
#ifdef USE_FILE_CACHE
void free_replay_list(fko_srv_options_t *opts);
#endif

#endif  /* REPLAY_CACHE_H */
