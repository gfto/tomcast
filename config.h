/*
 * mptsd configuration header file
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 */
#ifndef CONFIG_H
#define CONFIG_H

#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "libfuncs/libfuncs.h"

struct config {
	char				*ident;
	char				*pidfile;

	int					syslog_active;
	char				*logident;
	char				*loghost;
	int					logport;

	struct sockaddr_in	server;
	char				*server_addr;
	int					server_port;
	int					server_socket;
	pthread_t			server_thread;

	char				*channels_file;

	LIST				*chanconf;
	LIST				*restreamer;

	pthread_mutex_t		channels_lock;
};

#endif
