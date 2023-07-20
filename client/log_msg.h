/**
 * \file    client/log_msg.h
 *
 * \brief   Header file for log_msg.c
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
 */

#ifndef LOG_MSG_H
#define LOG_MSG_H
/*
这段代码定义了一个枚举类型，用于表示不同的日志级别。枚举类型是一种特殊的整数类型，它为一组相关的常量提供了有意义的名称。

在这段代码中，定义了以下枚举常量：

    LOG_FIRST_VERBOSITY：用于指定日志级别的起始值，值为0。
    LOG_VERBOSITY_ERROR：表示错误日志级别，值为0。
    LOG_VERBOSITY_WARNING：表示警告日志级别，值为1。
    LOG_VERBOSITY_NORMAL：表示普通日志级别，值为2。
    LOG_VERBOSITY_INFO：表示信息日志级别，值为3。
    LOG_VERBOSITY_DEBUG：表示调试日志级别，值为4。
    LOG_LAST_VERBOSITY：用于指定日志级别的结束值，值为5。

这些枚举常量可以在代码中用作日志级别的标识，提高代码的可读性和可维护性。

*/
enum
{
    LOG_FIRST_VERBOSITY = 0,
    LOG_VERBOSITY_ERROR = 0,    /*!< Constant to define a ERROR message */
    LOG_VERBOSITY_WARNING,      /*!< Constant to define a WARNING message */
    LOG_VERBOSITY_NORMAL,       /*!< Constant to define a NORMAL message */
    LOG_VERBOSITY_INFO,         /*!< Constant to define a INFO message */
    LOG_VERBOSITY_DEBUG,        /*!< Constant to define a DEBUG message */
    LOG_LAST_VERBOSITY
};

#define LOG_DEFAULT_VERBOSITY   LOG_VERBOSITY_NORMAL    /*!< Default verbosity to use */

void log_new(void);
void log_free(void);
void log_set_verbosity(int level);
void log_msg(int verbosity_level, char *msg, ...);

#endif /* LOG_MSG_H */

/***EOF***/
