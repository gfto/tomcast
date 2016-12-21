/*
 * tomcast
 * Copyright (C) 2010-2013 Unix Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License (COPYING file) for more details.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <signal.h>
#include <fcntl.h>
#include <regex.h>
#include <netdb.h> // for uint32_t

#include "libfuncs/libfuncs.h"
#include "config.h"

#include "web_server.h"

#define DNS_RESOLVER_TIMEOUT 5000

#define FDGETLINE_TIMEOUT 500
#define FDGETLINE_RETRIES 30

#define FDREAD_TIMEOUT 1500
#define FDREAD_RETRIES 7

#define FDWRITE_TIMEOUT 1500
#define FDWRITE_RETRIES 7

/* How much to wait for connection to be established with channel source (miliseconds) */
#define PROXY_CONNECT_TIMEOUT 1000

/* Seconds to sleep between retries (miliseconds) */
#define PROXY_RETRY_TIMEOUT 1000

#define TRANSPORT_PACKET_SIZE 188
#define TRANSPORT_EXTEDED_PACKET_SIZE 192
#define TRANSPORT_PACKETS_PER_NETWORK_PACKET 7
#define TRANSPORT_SYNC_BYTE 0x47

#define FRAME_PACKET_SIZE (TRANSPORT_PACKET_SIZE * TRANSPORT_PACKETS_PER_NETWORK_PACKET)

#ifndef FREE
	#define FREE(x) if(x) { free(x); x=NULL; }
#endif

#ifndef POLLRDHUP
	#define POLLRDHUP 0
#endif

char *server_sig = "tomcast";
char *server_ver = "1.30";
char *copyright  = "Copyright (C) 2010-2016 Unix Solutions Ltd.";

static struct config config;

channel_source get_sproto(char *url) {
	return strncmp(url, "http", 4)==0 ? tcp_sock : udp_sock;
}

CHANSRC *init_chansrc(char *url) {
	regex_t re;
	regmatch_t res[5];
	regcomp(&re, "^([a-z]+)://([^:/?]+):?([0-9]*)/?(.*)", REG_EXTENDED);
	if (regexec(&re,url,5,res,0)==0) {
		char *data = strdup(url);
		char *proto, *host, *port, *path;
		int iport;
		proto= data+res[1].rm_so; data[res[1].rm_eo]=0;
		host = data+res[2].rm_so; data[res[2].rm_eo]=0;
		port = data+res[3].rm_so; data[res[3].rm_eo]=0;
		path = data+res[4].rm_so; data[res[4].rm_eo]=0;
		iport = atoi(port);
		/* Setup */
		CHANSRC *src = calloc(1, sizeof(CHANSRC));
		src->proto = strdup(proto);
		src->sproto= get_sproto(url);
		src->host  = strdup(host);
		src->port  = iport ? iport : 80;
		src->path  = strdup(path);
		FREE(data);
		regfree(&re);
		return src;
	}
	regfree(&re);
	return NULL;
}

void free_chansrc(CHANSRC *url) {
	if (url) {
		FREE(url->proto);
		FREE(url->host);
		FREE(url->path);
		FREE(url);
	}
};

int is_valid_url(char *url) {
	regex_t re;
	regmatch_t res[5];
	int ret;
	regcomp(&re, "^([a-z]+)://([^:/?]+):?([0-9]*)/?(.*)", REG_EXTENDED);
	ret = regexec(&re,url,5,res,0);
	regfree(&re);
	return ret == 0;
}

void add_channel_source(CHANNEL *c, char *src) {
	if (c->num_src >= MAX_CHANNEL_SOURCES-1)
		return;
	c->sources[c->num_src] = strdup(src);
	if (c->num_src == 0) /* Set default source to first one */
		c->source = c->sources[c->num_src];
	c->num_src++;
}

void next_channel_source(CHANNEL *c) {
	if (c->num_src <= 1)
		return;
	// uint8_t old_src = c->curr_src;
	c->curr_src++;
	if (c->curr_src >= MAX_CHANNEL_SOURCES-1 || c->sources[c->curr_src] == NULL)
		c->curr_src = 0;
	c->source = c->sources[c->curr_src];
	// LOGf("CHAN : Switch source | Channel: %s OldSrc: %d %s NewSrc: %d %s\n", c->name, old_src, c->sources[old_src], c->curr_src, c->source);
}

void set_channel_source(CHANNEL *c, uint8_t src_id) {
	if (src_id >= MAX_CHANNEL_SOURCES-1 || c->sources[src_id] == NULL)
		return;
	// uint8_t old_src = c->curr_src;
	c->curr_src = src_id;
	c->source = c->sources[c->curr_src];
	// LOGf("CHAN : Set source    | Channel: %s OldSrc: %d %s NewSrc: %d %s\n", c->name, old_src, c->sources[old_src], c->curr_src, c->source);
}

CHANNEL * new_channel(char *name, char *source, char *dest, int port) {
	CHANNEL *c = calloc(1, sizeof(CHANNEL));
	c->name = strdup(name);
	c->dest_host = strdup(dest);
	c->dest_port = port;
	add_channel_source(c, source);
	return c;
}

void free_channel(CHANNEL *c) {
	int i;
	for (i=c->num_src-1; i>=0; i--) {
		FREE(c->sources[i]);
	}
	FREE(c->name);
	FREE(c->dest_host);
	c->source = NULL;
	FREE(c);
}

void free_channel_p(void *c) {
	free_channel(c);
}

int send_reset_opt = 0;
int multicast_ttl = 1;
struct in_addr output_intf = { .s_addr = INADDR_ANY };

int connect_multicast(struct sockaddr_in send_to) {
	int sendsock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sendsock < 0) {
		LOGf("socket(SOCK_DGRAM): %s\n", strerror(errno));
		return -1;
	}
	int on = 1;
	setsockopt(sendsock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	// subscribe to multicast group
	// LOGf("Using ttl %d\n", multicast_ttl);
	if (IN_MULTICAST(ntohl(send_to.sin_addr.s_addr))) {
		if (setsockopt(sendsock, IPPROTO_IP, IP_MULTICAST_TTL, &multicast_ttl, sizeof(multicast_ttl)) < 0) {
			LOGf("setsockopt(IP_MUTICAST_TTL): %s\n", strerror(errno));
			close(sendsock);
			return -1;
		}
		if (setsockopt(sendsock, IPPROTO_IP, IP_MULTICAST_IF, &output_intf, sizeof(output_intf)) < 0) {
			LOGf("setsockopt(IP_MUTICAST_IF, %s): %s\n", strerror(errno), inet_ntoa(output_intf));
			close(sendsock);
			return -1;
		}
	}

	int writebuflen = FRAME_PACKET_SIZE * 1000;
	if (setsockopt(sendsock, SOL_SOCKET, SO_SNDBUF, (const char *)&writebuflen, sizeof(writebuflen)) < 0)
		log_perror("setsockopt(): setsockopt(SO_SNDBUF)", errno);

	// call connect to get errors
	if (connect(sendsock, (struct sockaddr *)&send_to, sizeof send_to)) {
		LOGf("udp_connect() error: %s\n", strerror(errno));
		close(sendsock);
		return -1;
	}
	return sendsock;
}

void proxy_set_status(RESTREAMER *r, const char *proxy_status) {
	pthread_rwlock_wrlock(&r->lock);
	snprintf(r->status, sizeof(r->status), "%s", proxy_status);
	pthread_rwlock_unlock(&r->lock);
}

void connect_destination(RESTREAMER *r) {
	CHANNEL *c = r->channel;
	if (r->clientsock >= 0)
		shutdown_fd(&(r->clientsock));
	r->clientsock = connect_multicast(r->dst_sockname);
	LOGf("CONN : Connected dst_fd: %i | Chan: %s Dest: udp://%s:%d\n", r->clientsock, c->name, c->dest_host, c->dest_port);
}

RESTREAMER * new_restreamer(const char *name, CHANNEL *channel) {
	int active = 1;
	struct sockaddr_in sockname;
	int dret = async_resolve_host(channel->dest_host, channel->dest_port, &sockname, DNS_RESOLVER_TIMEOUT, &active);
	if (dret != 0) {
		if (dret == 1)
			LOGf("ERR  : Can't resolve host | Chan: %s Dest: udp://%s:%d\n", channel->name, channel->dest_host, channel->dest_port);
		if (dret == 2)
			LOGf("ERR  : DNS timeout        | Chan: %s Dest: udp://%s:%d\n", channel->name, channel->dest_host, channel->dest_port);
		return NULL;
	}
	RESTREAMER *r = calloc(1, sizeof(RESTREAMER));
	r->name = strdup(name);
	r->sock = -1;
	r->channel = channel;
	r->clientsock = -1;
	r->dst_sockname = sockname;
	pthread_rwlock_init(&r->lock, NULL);
	connect_destination(r);
	return r;
}

void free_restreamer(RESTREAMER *r) {
	if (r->sock > -1)
		shutdown_fd(&(r->sock));
	if (r->freechannel)
		free_channel(r->channel);
	FREE(r->name);
	FREE(r);
}

char TS_NULL_FRAME[FRAME_PACKET_SIZE];

regex_t http_response;

void proxy_log(RESTREAMER *r, char *msg, char *info) {
	LOGf("%s: %sChan: %s Src: %s Dst: udp://%s:%d SrcIP: %s SrcFD: %i DstFD: %i\n",
		msg,
		info,
		r->channel->name,
		r->channel->source,
		r->channel->dest_host,
		r->channel->dest_port,
		inet_ntoa(r->src_sockname.sin_addr),
		r->sock,
		r->clientsock
	);
}

int load_channels_config(struct config *cfg) {
	regex_t re;
	regmatch_t res[5];
	char line[1024];
	int fd;
	int num_channels = 0;

	if (pthread_mutex_trylock(&cfg->channels_lock) != 0)
		return -1;

	fd = open(cfg->channels_file, O_RDONLY);

	if (fd != -1) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		unsigned int randstate = tv.tv_usec;
		int cookie = rand_r(&randstate);

		regcomp(&re, "^([A-Za-z0-9]+)\t+([0-9.]+):([0-9]+)\t+(.*)", REG_EXTENDED);
		LIST *old_chanconf;
		LIST *new_chanconf = list_new("chanconf");
		while (fdgetline(fd,line,sizeof(line)) > 0) {
			chomp(line);
			if (regexec(&re,line,5,res,0)==0) {
				char *name, *dest_host, *dest_port, *source;
				char *org = strdup(line);
				name      = org+res[1].rm_so; org[res[1].rm_eo]=0;
				dest_host = org+res[2].rm_so; org[res[2].rm_eo]=0;
				dest_port = org+res[3].rm_so; org[res[3].rm_eo]=0;
				source    = org+res[4].rm_so; org[res[4].rm_eo]=0;

				if (!is_valid_url(source)) {
					LOGf("CONF : Invalid url: %s\n", source);
					FREE(org);
					goto report_error;
				}
				/* Search for already added channel */
				LNODE *l, *tmp;
				CHANNEL *chan = NULL;
				list_for_each_reverse(new_chanconf, l, tmp) {
					if (strcmp(name, ((CHANNEL *)l->data)->name)==0) {
						chan = l->data;
						break;
					}
				}
				if (!chan) {
					list_add(new_chanconf, new_channel(name, source, dest_host, atoi(dest_port)));
					num_channels++;
				} else {
					add_channel_source(chan, source);
				}
				FREE(org);
			} else {
report_error:
				if (strlen(line) > 2 && line[0] != '#') {
					LOGf("CONF : Invalid config line: %s\n", line);
				}
			}
		}
		regfree(&re);
		shutdown_fd(&fd);
		/* Save current chanconf */
		old_chanconf = cfg->chanconf;
		/* Switch chanconf */
		cfg->chanconf = new_chanconf;
		/* Rewrite restreamer channels */
		LNODE *lc, *lr, *lctmp, *lrtmp;
		CHANNEL *chan;
		list_lock(cfg->restreamer);	// Unlocked after second list_for_each(restreamer)

		list_lock(cfg->chanconf);
		list_for_each(cfg->chanconf, lc, lctmp) {
			chan = lc->data;
			list_for_each(cfg->restreamer, lr, lrtmp) {
				if (strcmp(chan->name, ((RESTREAMER *)lr->data)->name)==0) {
					RESTREAMER *restr = lr->data;
					/* Mark the restreamer as valid */
					restr->cookie = cookie;
					/* Check if current source exists in new channel configuration */
					int i, src_found = -1;
					char *old_source = restr->channel->source;
					for (i=0; i<chan->num_src; i++) {
						if (strcmp(old_source, chan->sources[i]) == 0) {
							src_found = i;
						}
					}
					if (src_found > -1) {
						/* New configuration contains existing source, just update the reference */
						set_channel_source(chan, src_found);
						restr->channel = chan;
					} else {
						/* New configuration *DO NOT* contain existing source. Force reconnect */
						LOGf("PROXY: Source changed | Channel: %s srv_fd: %d Old:%s New:%s\n", chan->name, restr->sock, restr->channel->source, chan->source);
						/* The order is important! */
						set_channel_source(chan, chan->num_src-1); /* Set source to last one. On reconnect next source will be used. */
						restr->channel = chan;
						restr->reconnect = 1;
					}
					break;
				}
			}
		}
		list_unlock(cfg->chanconf);

		/* Kill restreamers that serve channels that no longer exist */
		list_for_each(cfg->restreamer, lr, lrtmp) {
			RESTREAMER *r = lr->data;
			/* This restreamer should no longer serve clients */
			if (r->cookie != cookie) {
				proxy_log(r, "CLEAR", "Channel removed ");
				/* Replace channel reference with real object and instruct free_restreamer to free it */
				r->channel = new_channel(r->channel->name, r->channel->source, r->channel->dest_host, r->channel->dest_port);
				r->freechannel = 1;
				r->dienow = 1;
			}
		}
		list_unlock(cfg->restreamer);

		/* Free old_chanconf */
		list_free(&old_chanconf, free_channel_p, NULL);
	} else {
		num_channels = -1;
	}
	pthread_mutex_unlock(&cfg->channels_lock);
	if (num_channels == -1)
		LOGf("CONF : Error loading channels!\n");
	else
		LOGf("CONF : %d channels loaded\n", num_channels);
	return num_channels;
}

void proxy_close(RESTREAMER *r) {
	proxy_log(r, "STOP ","");
	// If there are no clients left, no "Timeout" messages will be logged
	list_del_entry(config.restreamer, r);
	free_restreamer(r);
}

/*
	On the last try, send no-signal to clients and exit
	otherwise wait a little bit before trying again
*/
#define DO_RECONNECT do \
{ \
	free_chansrc(src); \
	if (retries == 0) { \
		return -1; \
	} else { \
		if (errno != EHOSTUNREACH) /* When host is unreachable there is already a delay of ~4 secs per try so no sleep is needed */ \
			usleep(PROXY_RETRY_TIMEOUT * 1000); \
		return 1; \
	} \
} while(0)

#define FATAL_ERROR do \
{ \
	free_chansrc(src); \
	return -1; \
} while (0)

/*
	Returns:
		-1 = exit thread
		 1 = retry
		 0 = connected ok
*/
int connect_source(RESTREAMER *r, int retries, int readbuflen, int *http_code) {
	CHANSRC *src = init_chansrc(r->channel->source);
	if (!src) {
		LOGf("ERR  : Can't parse channel source | Channel: %s Source: %s\n", r->channel->name, r->channel->source);
		FATAL_ERROR;
	}
	r->connected = 0;
	r->reconnect = 0;

	int active = 1;
	int dret = async_resolve_host(src->host, src->port, &(r->src_sockname), DNS_RESOLVER_TIMEOUT, &active);
	if (dret != 0) {
		if (dret == 1) {
			proxy_log(r, "ERR  ","Can't resolve src host");
			proxy_set_status(r, "ERROR: Can not resolve source host");
		}
		if (dret == 2) {
			proxy_log(r, "ERR  ","Timeout resolving src host");
			proxy_set_status(r, "ERROR: Dns resolve timeout");
		}
		DO_RECONNECT;
	}

	char buf[1024];
	*http_code = 0;
	if (src->sproto == tcp_sock) {
		r->sock = socket(PF_INET, SOCK_STREAM, 0);
		if (r->sock < 0) {
			log_perror("play(): Could not create SOCK_STREAM socket.", errno);
			FATAL_ERROR;
		}
		proxy_log(r, "NEW  ","");
		if (do_connect(r->sock, (struct sockaddr *)&(r->src_sockname), sizeof(r->src_sockname), PROXY_CONNECT_TIMEOUT) < 0) {
			LOGf("ERR  : Error connecting to %s srv_fd: %i err: %s\n", r->channel->source, r->sock, strerror(errno));
			proxy_set_status(r, "ERROR: Can not connect to source");
			DO_RECONNECT;
		}

		snprintf(buf,sizeof(buf)-1, "GET /%s HTTP/1.0\r\nHost: %s:%u\r\nX-Smart-Client: yes\r\nUser-Agent: %s %s (%s)\r\n\r\n",
		         src->path, src->host, src->port, server_sig, server_ver, config.ident);
		buf[sizeof(buf)-1] = 0;
		fdwrite(r->sock, buf, strlen(buf));

		char xresponse[128];
		memset(xresponse, 0, sizeof(xresponse));
		memset(buf, 0, sizeof(buf));
		regmatch_t res[4];
		while (fdgetline(r->sock,buf,sizeof(buf)-1)) {
			if (buf[0] == '\n' || buf[0] == '\r')
				break;
			if (strstr(buf,"HTTP/1.") != NULL) {
				if (regexec(&http_response,buf,3,res,0) != REG_NOMATCH) {
					char codestr[4];
					if ((unsigned long)(res[1].rm_eo - res[1].rm_so) < sizeof(xresponse)) {
						strncpy(xresponse, &buf[res[1].rm_so], res[1].rm_eo-res[1].rm_so);
						xresponse[res[1].rm_eo-res[1].rm_so] = '\0';
						chomp(xresponse);
						strncpy(codestr, &buf[res[2].rm_so], res[2].rm_eo-res[2].rm_so);
						codestr[3] = 0;
						*http_code = atoi(codestr);
					}
				}
			}
			if (*http_code == 504) { // Extract extra error code
				if (strstr(buf, "X-ErrorCode: ") != NULL) {
					*http_code = atoi(buf+13);
					break;
				}
			}
		}
		if (*http_code == 0) { // No valid HTTP response, retry
			LOGf("DEBUG: Server returned not valid HTTP code | srv_fd: %i\n", r->sock);
			proxy_set_status(r, "ERROR: Source returned invalid HTTP code");
			DO_RECONNECT;
		}
		if (*http_code == 504) { // No signal, exit
			LOGf("ERR  : Get no-signal for %s from %s on srv_fd: %i\n", r->channel->name, r->channel->source, r->sock);
			proxy_set_status(r, "ERROR: Source returned no-signal");
			FATAL_ERROR;
		}
		if (*http_code > 300) { // Unhandled or error codes, exit
			LOGf("ERR  : Get code %i for %s from %s on srv_fd: %i exiting.\n", *http_code, r->channel->name, r->channel->source, r->sock);
			proxy_set_status(r, "ERROR: Source returned unhandled error code");
			FATAL_ERROR;
		}
		// connected ok, continue
	} else {
		if (!IN_MULTICAST(ntohl(r->src_sockname.sin_addr.s_addr))) {
			LOGf("ERR  : %s is not multicast address\n", r->channel->source);
			FATAL_ERROR;
		}
		struct ip_mreq mreq;
		struct sockaddr_in receiving_from;

		r->sock = socket(PF_INET, SOCK_DGRAM, 0);
		if (r->sock < 0) {
			log_perror("play(): Could not create SOCK_DGRAM socket.", errno);
			FATAL_ERROR;
		}
		LOGf("CONN : Listening on multicast socket %s srv_fd: %i retries left: %i\n", r->channel->source, r->sock, retries);
		int on = 1;
		setsockopt(r->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		// subscribe to multicast group
		memcpy(&mreq.imr_multiaddr, &(r->src_sockname.sin_addr), sizeof(struct in_addr));
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		if (setsockopt(r->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
			LOGf("ERR  : Failed to add IP membership on %s srv_fd: %i\n", r->channel->source, r->sock);
			FATAL_ERROR;
		}
		// bind to the socket so data can be read
		memset(&receiving_from, 0, sizeof(receiving_from));
		receiving_from.sin_family = AF_INET;
		receiving_from.sin_addr   = r->src_sockname.sin_addr;
		receiving_from.sin_port   = htons(src->port);
		if (bind(r->sock, (struct sockaddr *) &receiving_from, sizeof(receiving_from)) < 0) {
			LOGf("ERR  : Failed to bind to %s srv_fd: %i\n", r->channel->source, r->sock);
			FATAL_ERROR;
		}
	}

	if (setsockopt(r->sock, SOL_SOCKET, SO_RCVBUF, (const char *)&readbuflen, sizeof(readbuflen)) < 0)
		log_perror("play(): setsockopt(SO_RCVBUF)", errno);

	proxy_set_status(r, "Connected");
	r->connected = 1;

	free_chansrc(src);
	return 0;
}

int check_restreamer_state(RESTREAMER *r) {
	if (r->dienow) {
		// LOGf("PROXY: Forced disconnect on srv_fd: %i | Channel: %s Source: %s\n", r->sock, r->channel->name, r->channel->source);
		proxy_set_status(r, "Dying");
		return 2;
	}
	if (r->reconnect) {
		LOGf("PROXY: Forced reconnect on srv_fd: %i | Channel: %s Source: %s\n", r->sock, r->channel->name, r->channel->source);
		proxy_set_status(r, "Forced reconnect");
		return 1;
	}
	return 0;
}

#define MAX_ZERO_READS 3

/*         Start: 3 seconds on connect */
/* In connection: Max UDP timeout == 3 seconds (read) + 2 seconds (connect) == 5 seconds */
#define UDP_READ_RETRIES 3
#define UDP_READ_TIMEOUT 1000

/*         Start: 1/4 seconds on connect */
/* In connection: Max TCP timeout == 5 seconds (read) + 2 seconds (connect)             == 7 seconds */
/* In connection: Max TCP timeout == 5 seconds (read) + 8 seconds (connect, host unrch) == 13 seconds */
#define TCP_READ_RETRIES 5
#define TCP_READ_TIMEOUT 1000

/*
	Returns:
		0 = synced ok
		1 = not synced, reconnect
*/
int mpeg_sync(RESTREAMER *r, int proxysock, char *channel, channel_source source_proto) {
	time_t sync_start = time(NULL);
	unsigned int sync_packets = 0;
	unsigned int read_bytes = 0;
	char syncframe[188];

	int _timeout = TCP_READ_TIMEOUT;
	int _retries = TCP_READ_RETRIES;
	if (source_proto == udp_sock) {
		_timeout = UDP_READ_TIMEOUT;
		_retries = UDP_READ_RETRIES;
	}
	do {
resync:
		if (fdread_ex(proxysock, syncframe, 1, _timeout, _retries, 1) != 1) {
			LOGf("DEBUG: mpeg_sync fdread() timeout | Channel: %s\n", channel);
			proxy_set_status(r, "ERROR: fdread() timeout while syncing mpeg");
			return 1; // reconnect
		}
		// LOGf("DEBUG:     Read 0x%02x Offset %u Sync: %u\n", (uint8_t)syncframe[0], read_bytes, sync_packets);
		read_bytes++;
		if (syncframe[0] == 0x47) {
			ssize_t rdsz = fdread_ex(proxysock, syncframe, 188-1, _timeout, _retries, 1);
			if (rdsz != 188-1) {
				LOGf("DEBUG: mpeg_sync fdread() timeout | Channel: %s\n", channel);
				proxy_set_status(r, "ERROR: fdread() timeout while syncing mpeg");
				return 1; // reconnect
			}
			read_bytes += 188-1;
			if (++sync_packets == 7) // sync 7 packets
				break;
			goto resync;
		} else {
			sync_packets = 0;
		}
		if (read_bytes > FRAME_PACKET_SIZE) { // Can't sync in 1316 bytes
			LOGf("DEBUG: Can't sync after %d bytes | Channel: %s\n", FRAME_PACKET_SIZE, channel);
			proxy_set_status(r, "ERROR: Can not sync mpeg");
			return 1; // reconnect
		}
		if (sync_start+2 <= time(NULL)) { // Do not sync in two seconds
			LOGf("DEBUG: Timeout while syncing (read %u bytes) | Channel: %s\n", read_bytes, channel);
			proxy_set_status(r, "ERROR: Timeout while syncing mpeg");
			return 1; // reconnect
		}
	} while (1);
	pthread_rwlock_wrlock(&r->lock);
	r->conn_ts = time(NULL);
	r->read_bytes = read_bytes;
	pthread_rwlock_unlock(&r->lock);
	LOGf("SYNC : TS synced after %u bytes | Channel: %s\n", read_bytes-FRAME_PACKET_SIZE, channel);
	proxy_set_status(r, "Working");
	return 0;
}

char reset[FRAME_PACKET_SIZE] = {
  0x47,0x40,0x00,0x10,0x00,0x00,0xB0,0x09,0x27,0x10,0xC1,0x00,
  0x00,0x3C,0xDD,0xFF,0xB8,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x47,0x40,0x00,0x11,
  0x00,0x00,0xB0,0x0D,0x27,0x10,0xC3,0x00,0x00,0x4E,0x20,0xE0,
  0x64,0xD8,0x46,0x8F,0xCB,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0x47,0x40,0x11,0x12,0x00,0x42,0xF0,0x0C,
  0x27,0x10,0xC1,0x00,0x00,0x9C,0x40,0xFF,0x1F,0xA4,0x9D,0xBA,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0x47,0x40,0x11,0x13,0x00,0x42,0xF0,0x0C,0x27,0x10,0xC3,0x00,
  0x00,0x9C,0x40,0xFF,0x29,0xF4,0x87,0x4A,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x47,0x40,0x64,0x14,
  0x00,0x02,0xB0,0x0D,0x4E,0x20,0xC1,0x00,0x00,0xE0,0x6E,0xF0,
  0x00,0x30,0xB6,0x9F,0x1A,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0x47,0x40,0x64,0x15,0x00,0x02,0xB0,0x0D,
  0x4E,0x20,0xC3,0x00,0x00,0xE0,0x78,0xF0,0x00,0xB7,0x41,0x6C,
  0x5A,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0x47,0x1F,0xFF,0x10,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

void * proxy_ts_stream(void *self) {
	RESTREAMER *r = self;
	char buf[FRAME_PACKET_SIZE];

	signal(SIGPIPE, SIG_IGN);

	int http_code = 0;
	while (1) {
		r->conn_ts = 0;
		r->read_bytes = 0;

		int result = connect_source(self, 1, FRAME_PACKET_SIZE * 1000, &http_code);
		if (result > 0)
			goto RECONNECT;

		channel_source sproto = get_sproto(r->channel->source);

		int mpgsync = mpeg_sync(r, r->sock, r->channel->name, sproto);
		if (mpgsync == 1) // Timeout
			goto RECONNECT;

		ssize_t readen, written;
		int max_zero_reads = MAX_ZERO_READS;
		int send_reset = send_reset_opt;
		for (;;) {
			switch (check_restreamer_state(r)) {
				case 1: goto RECONNECT;		// r->reconnect is on
				case 2: goto QUIT;			// r->dienow is on
			}
			if (sproto == tcp_sock) {
				readen = fdread_ex(r->sock, buf, FRAME_PACKET_SIZE, TCP_READ_TIMEOUT, TCP_READ_RETRIES, 1);
			} else {
				readen = fdread_ex(r->sock, buf, FRAME_PACKET_SIZE, UDP_READ_TIMEOUT, UDP_READ_RETRIES, 0);
			}
			if (readen < 0)
				goto RECONNECT;
			if (readen == 0) { // ho, hum, wtf is going on here?
				LOGf("PROXY: zero read on srv_fd: %i | Channel: %s Source: %s\n", r->sock, r->channel->name, r->channel->source);
				if (--max_zero_reads == 0) {
					LOGf("PROXY: %d zero reads on srv_fd: %i | Channel: %s Source: %s\n", MAX_ZERO_READS, r->sock, r->channel->name, r->channel->source);
					proxy_set_status(r, "ERROR: Too many zero reads");
					break;
				}
				continue;
			}

			max_zero_reads = MAX_ZERO_READS;

			// Fill short frame with NULL packets
			if (readen < FRAME_PACKET_SIZE) {
				//LOGf("DEBUG: Short read (%d) on retreamer srv_fd: %i | Channel: %s\n", readen, sock, chan->name);
				memcpy(buf+readen, TS_NULL_FRAME+readen, FRAME_PACKET_SIZE - readen);
			}
			pthread_rwlock_wrlock(&r->lock);
			r->read_bytes += readen;
			pthread_rwlock_unlock(&r->lock);

			if (send_reset) {
				send_reset = 0;
				fdwrite(r->clientsock, reset, FRAME_PACKET_SIZE);
			}
			written = fdwrite(r->clientsock, buf, FRAME_PACKET_SIZE);
			if (written == -1) {
				LOGf("PROXY: Error writing to dst_fd: %i on srv_fd: %i | Channel: %s Source: %s\n", r->clientsock, r->sock, r->channel->name, r->channel->source);
				connect_destination(r);
			}
		}
		LOGf("DEBUG: fdread timeout restreamer srv_fd: %i | Channel: %s\n", r->sock, r->channel->name);
		proxy_set_status(r, "ERROR: Read timeout");
RECONNECT:
		pthread_rwlock_wrlock(&r->lock);
		r->conn_ts = 0;
		pthread_rwlock_unlock(&r->lock);
		LOGf("DEBUG: reconnect srv_fd: %i | Channel: %s\n", r->sock, r->channel->name);
		proxy_set_status(r, "Reconnecting");
		shutdown_fd(&(r->sock));
		next_channel_source(r->channel);
		continue;
QUIT:
		LOGf("DEBUG: quit srv_fd: %i | Channel: %s\n", r->sock, r->channel->name);
		break;
	}
	proxy_close(r);
	return 0;
}

static int copyright_shown = 0;
void show_usage(int ident_only) {
	if (!copyright_shown) {
		printf("%s %s\n", server_sig, server_ver);
		puts(copyright);
		puts("");
		copyright_shown = 1;
	}
	if (ident_only)
		return;
	puts("Usage: tomcast -c config_file");
	puts("");
	puts("\t-c file\t\tChannels configuration file");
	puts("\t-i ident\tServer ident. Must be formated as PROVIDER/SERVER");
	puts("\t-d pidfile\tDaemonize and write daemon pid into pidfile");
	puts("\t-t ttl\t\tSet multicast ttl (default: 1)");
	puts("\t-o ip\t\tOutput interface address (default: 0.0.0.0)");
	puts("\t-l host\t\tSyslog host (default: disabled)");
	puts("\t-L port\t\tSyslog port (default: 514)");
	puts("\t-R\t\tSend reset packets when changing sources.");
	puts("Server settings:");
	puts("\t-b addr\t\tLocal IP address to bind.   (default: 0.0.0.0)");
	puts("\t-p port\t\tPort to listen.             (default: 0)");
	puts("");
}

void set_ident(char *new_ident, struct config *cfg) {
	cfg->ident = new_ident;
	cfg->logident = strdup(new_ident);
	char *c = cfg->logident;
	while (*c) {
		if (*c=='/')
			*c='-';
		c++;
	}
}

void parse_options(int argc, char **argv, struct config *cfg) {
	int j, ttl;
	cfg->server_socket = -1;
	pthread_mutex_init(&cfg->channels_lock, NULL);
	while ((j = getopt(argc, argv, "i:b:p:c:d:t:o:l:L:RHh")) != -1) {
		switch (j) {
			case 'b':
				cfg->server_addr = optarg;
				break;
			case 'p':
				cfg->server_port = atoi(optarg);
				break;
			case 'i':
				set_ident(optarg, cfg);
				break;
			case 'c':
				cfg->channels_file = optarg;
				break;
			case 'd':
				cfg->pidfile = optarg;
				break;
			case 'o':
				if (inet_aton(optarg, &output_intf) == 0) {
					fprintf(stderr, "Invalid interface address: %s\n", optarg);
					exit(1);
				}
				break;
			case 't':
				ttl = atoi(optarg);
				multicast_ttl = (ttl && ttl < 127) ? ttl : 1;
				break;
			case 'l':
				cfg->loghost = optarg;
				cfg->syslog_active = 1;
				break;
			case 'L':
				cfg->logport = atoi(optarg);
				break;
			case 'R':
				send_reset_opt = 1;
				break;
			case 'H':
			case 'h':
				show_usage(0);
				exit(0);
				break;
		}
	}

	if (!cfg->channels_file) {
		show_usage(0);
		fprintf(stderr, "ERROR: No channels file is set (use -c option).\n");
		exit(1);
	}

	if (!cfg->ident) {
		set_ident("unixsol/tomcast", cfg);
	}

	printf("Configuration:\n");
	printf("\tServer ident      : %s\n", cfg->ident);
	printf("\tChannels file     : %s\n", cfg->channels_file);
	printf("\tOutput iface addr : %s\n", inet_ntoa(output_intf));
	printf("\tMulticast ttl     : %d\n", multicast_ttl);
	if (cfg->syslog_active) {
		printf("\tSyslog host       : %s\n", cfg->loghost);
		printf("\tSyslog port       : %d\n", cfg->logport);
	} else {
		printf("\tSyslog disabled.\n");
	}
	if (send_reset_opt)
		printf("\tSend reset packets.\n");
	if (cfg->pidfile) {
		printf("\tDaemonize         : %s\n", cfg->pidfile);
	} else {
		printf("\tDo not daemonize.\n");
	}
	if (cfg->server_port) {
		init_server_socket(cfg->server_addr, cfg->server_port, &cfg->server, &cfg->server_socket);
		printf("\tStarting web srv  : http://%s:%d/status (sock: %d)\n", cfg->server_addr, cfg->server_port, cfg->server_socket);
	} else {
		printf("\tNo web server\n");
	}
}

void init_vars(struct config *cfg) {
	cfg->restreamer = list_new("restreamer");
	regcomp(&http_response, "^HTTP/1.[0-1] (([0-9]{3}) .*)", REG_EXTENDED);
	memset(&TS_NULL_FRAME, 0xff, FRAME_PACKET_SIZE);
	int i;
	for (i=0; i<FRAME_PACKET_SIZE; i=i+188) {
		TS_NULL_FRAME[i+0] = 0x47;
		TS_NULL_FRAME[i+1] = 0x1f;
		TS_NULL_FRAME[i+2] = 0xff;
		TS_NULL_FRAME[i+3] = 0x00;
	}
}

void spawn_proxy_threads(struct config *cfg) {
	LNODE *lc, *lctmp;
	LNODE *lr, *lrtmp;
	int spawned = 0;
	list_for_each(cfg->chanconf, lc, lctmp) {
		CHANNEL *c = lc->data;
		int restreamer_active = 0;
		list_lock(cfg->restreamer);
		list_for_each(cfg->restreamer, lr, lrtmp) {
			RESTREAMER *r = lr->data;
			if (strcmp(r->name, c->name)==0) {
				restreamer_active = 1;
				break;
			}
		}
		list_unlock(cfg->restreamer);
		if (!restreamer_active) {
			RESTREAMER *nr = new_restreamer(c->name, c);
			if (nr->clientsock < 0) {
				LOGf("Error creating proxy socket for %s\n", c->name);
				free_restreamer(nr);
			} else {
				list_add(cfg->restreamer, nr);
				if (pthread_create(&nr->thread, NULL, &proxy_ts_stream, nr) == 0) {
					spawned++;
					pthread_detach(nr->thread);
				} else {
					LOGf("Error creating proxy for %s\n", c->name);
				}
			}
		}
	}
	LOGf("INFO : %d proxy threads spawned\n", spawned);
}

void kill_proxy_threads(struct config *cfg) {
	LNODE *l, *tmp;
	int killed = 0;
	list_lock(cfg->restreamer);
	list_for_each(cfg->restreamer, l, tmp) {
		RESTREAMER *r = l->data;
		r->dienow = 1;
		killed++;
	}
	list_unlock(cfg->restreamer);
	LOGf("INFO : %d proxy threads killed\n", killed);
}

int keep_going = 1;

void signal_quit(int sig) {
	keep_going = 0;
	kill_proxy_threads(&config);
	usleep(500000);
	LOGf("KILL : Signal %i | %s %s (%s)\n", sig, server_sig, server_ver, config.ident);
	usleep(100000);
	log_close();
	if (config.pidfile && strlen(config.pidfile))
		unlink(config.pidfile);
	signal(sig, SIG_DFL);
	raise(sig);
}

struct config *get_config(void) {
	return &config;
}

void do_reconnect() {
	LNODE *l, *tmp;
	list_lock(config.restreamer);
	list_for_each(config.restreamer, l, tmp) {
		RESTREAMER *r = l->data;
		r->reconnect = 1;
	}
	list_unlock(config.restreamer);
}

void do_reconf() {
	load_channels_config(&config);
	spawn_proxy_threads(&config);
}

void init_signals() {
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	signal(SIGHUP , do_reconf);
	signal(SIGUSR1, do_reconnect);

	signal(SIGINT , signal_quit);
	signal(SIGTERM, signal_quit);
}

void do_daemonize(struct config *cfg) {
	if (!cfg->pidfile)
		return;
	fprintf(stderr, "Daemonizing.\n");
	pid_t pid = fork();
	if (pid > 0) {
		FILE *F = fopen(cfg->pidfile,"w");
		if (F) {
			fprintf(F,"%i\n",pid);
			fclose(F);
		}
		exit(0);
	}
	// Child process continues...
	setsid();	// request a new session (job control)
	freopen("/dev/null", "r", stdin);
	freopen("/dev/null", "w", stdout);
	freopen("/dev/null", "w", stderr);
}

/* Must be called after daemonize! */
void init_logger(struct config *cfg) {
	if (cfg->syslog_active)
		fprintf(stderr, "Logging to %s:%d\n", cfg->loghost, cfg->logport);
	log_init(cfg->logident, cfg->syslog_active, cfg->pidfile == NULL, cfg->loghost, cfg->logport);
}

int main(int argc, char **argv) {
	set_http_response_server_ident(server_sig, server_ver);
	show_usage(1); // Show copyright and version
	init_vars(&config);
	parse_options(argc, argv, &config);
	do_daemonize(&config);
	init_logger(&config);
	init_signals();

	LOGf("INIT : %s %s (%s)\n" , server_sig, server_ver, config.ident);

	load_channels_config(&config);
	spawn_proxy_threads(&config);
	web_server_start(&config);

	do {
		sleep(60);
	} while(1);

	signal_quit(15);
	exit(0);
}
