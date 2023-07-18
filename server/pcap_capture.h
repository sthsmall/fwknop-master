/**
 * \file server/pcap_capture.h
 *
 * \brief Header file for pcap_capture.c.
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
#ifndef PCAP_CAPTURE_H
#define PCAP_CAPTURE_H

/* How many consecutive pcap capture errors will we allow
 * before giving up and bailing out.
 * 在放弃并退出之前，我们允许连续的 pcap 抓包错误次数。 
*/
#define MAX_PCAP_ERRORS_BEFORE_BAIL 100

/* We normally want pcap in non-blockinbg mode, but this seems to be
 * broken on FreeBSD 7 (at least my test host), so we'll set the default
 * mode to on unless it is a FreeBSD system. --DSS XXX: What we really need
 * to do is figure out what the difference is and address it correctly.
 * 通常我们希望 pcap 处于非阻塞模式，但在 FreeBSD 7 上（至少在我的测试主机上）似乎存在问题，
 * 因此我们将默认将模式设置为打开（开启），除非它是一个 FreeBSD 系统。
 * -- DSS XXX：我们真正需要做的是找出其中的差异并进行正确处理。
 * 
*/
#if defined(__FreeBSD__) || defined(__APPLE__)
    #define DEF_PCAP_NONBLOCK 0
#else
    #define DEF_PCAP_NONBLOCK 1
#endif

/* Prototypes
*/
int pcap_capture(fko_srv_options_t *opts);

#endif  /* PCAP_CAPTURE_H */
