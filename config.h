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

typedef enum { udp_sock, tcp_sock } channel_source;

typedef struct {
	channel_source sproto;
	char *proto;
	char *host;
	char *path;
	unsigned int port;
} CHANSRC;

#define MAX_CHANNEL_SOURCES 8

typedef struct {
	char *name;
	char *source; /* Full source url */
	char *sources[MAX_CHANNEL_SOURCES];
	uint8_t num_src;
	uint8_t curr_src;
	char *dest_host;
	int dest_port;
} CHANNEL;

typedef struct {
	char  *name;
	CHANNEL *channel;
	int sock;				/* Server socket */
	struct sockaddr_in src_sockname;
	int clientsock;			/* The udp socket */
	struct sockaddr_in dst_sockname;
	int reconnect:1,		/* Set to 1 to force proxy reconnect */
	    connected:1,		/* It's set to 1 when proxy is connected and serving clients */
	    dienow:1,			/* Stop serving clients and exit now */
	    freechannel:1;		/* Free channel data on object free (this is used in chanconf) */
	int cookie;				/* Used in chanconf to determine if the restreamer is alrady checked */
	pthread_t thread;
	pthread_rwlock_t lock;
	time_t conn_ts;
	uint64_t read_bytes;
	char status[64];
} RESTREAMER;


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

extern void do_reconnect();
extern void do_reconf();
extern struct config *get_config(void);

#endif
