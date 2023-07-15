/**
 * \file client/spa_comm.h
 *
 * \brief Header file for fwknop client test program.
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
#ifndef SPA_COMM_H
#define SPA_COMM_H

#include "fwknop_common.h"
#include "netinet_common.h"

/* Function Prototypes
*/
int send_spa_packet(fko_ctx_t ctx, fko_cli_options_t *options);
int write_spa_packet_data(fko_ctx_t ctx, const fko_cli_options_t *options);

#endif  /* SPA_COMM_H */
