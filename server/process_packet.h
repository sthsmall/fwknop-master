/**
 * \file server/process_packet.h
 *
 * \brief Header file for process_packet and other fwknopd code.
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
#ifndef PROCESS_PACKET_H
#define PROCESS_PACKET_H

#if USE_LIBPCAP
  #include <pcap.h>
  #define PACKET_HEADER_META const struct pcap_pkthdr *packet_header
  #define PROCESS_PKT_ARGS_TYPE unsigned char
#else
  #define PACKET_HEADER_META unsigned short pkt_len
  #define PROCESS_PKT_ARGS_TYPE fko_srv_options_t
#endif

#define IPV4_VER_MASK   0x15
#define MIN_IPV4_WORDS  0x05

/* For items not defined by this system
  对于该系统未定义的项目
*/
#ifndef ETHER_CRC_LEN
  #define ETHER_CRC_LEN 4
#endif
#ifndef ETHER_HDR_LEN
  #define ETHER_HDR_LEN 14
#endif

/* Prototypes
*/
void process_packet(PROCESS_PKT_ARGS_TYPE *opts, PACKET_HEADER_META,
					const unsigned char *packet);

#endif  /* PROCESS_PACKET_H */
