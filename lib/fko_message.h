/**
 * \file lib/fko_message.h
 *
 * \brief Provide validation functions for SPA messages
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

#ifndef FKO_MESSAGE_H
#define FKO_MESSAGE_H 1

/* SPA message format validation functions.
*/
int validate_cmd_msg(const char *msg);
int validate_access_msg(const char *msg);
int validate_nat_access_msg(const char *msg);
int validate_proto_port_spec(const char *msg);

#endif /* FKO_MESSAGE_H */

/***EOF***/
