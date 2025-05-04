#include <tll/tls/bio-nosignal.h>

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static BIO_METHOD * impl = NULL;
typedef struct tll_tls_bio_t
{
	int fd;
	unsigned char eof:1;
	unsigned char close:1;
} tll_tls_bio_t;

static int tll_tls_bio_create(BIO * bio)
{
	tll_tls_bio_t * data = malloc(sizeof(tll_tls_bio_t));
	memset(data, 0, sizeof(*data));
	data->fd = -1;
	BIO_set_data(bio, data);
	BIO_set_init(bio, 1);
	return 1;
}

static int tll_tls_bio_destroy(BIO * bio)
{
	tll_tls_bio_t * data = BIO_get_data(bio);
	if (!data)
		return 1;
	if (data->close && data->fd != -1)
		close(data->fd);
	free(data);
	return 1;
}

static int tll_tls_bio_read(BIO * bio, char * buf, int size)
{
	tll_tls_bio_t * data = BIO_get_data(bio);
	int r = recv(data->fd, buf, size, MSG_NOSIGNAL);
	BIO_clear_retry_flags(bio);
	if (r < 0 && errno == EAGAIN)
		BIO_set_retry_read(bio);
	else if (r == 0)
		data->eof = 1;
	return r;
}

static int tll_tls_bio_write(BIO * bio, const char * buf, int size)
{
	int fd = BIO_get_fd(bio, NULL);
	int r = send(fd, buf, size, MSG_NOSIGNAL);
	BIO_clear_retry_flags(bio);
	if (r < 0 && errno == EAGAIN)
		BIO_set_retry_write(bio);
	return r;
}

static long tll_tls_bio_ctrl(BIO * bio, int cmd, long larg, void * parg)
{
	tll_tls_bio_t * data = BIO_get_data(bio);
	switch (cmd) {
	case BIO_C_SET_FD:
		data->close = larg;
		if (parg)
			data->fd = *(int *)parg;
		return 1;
	case BIO_C_GET_FD:
		if (parg)
			*(int *)parg = data->fd;
		return data->fd;
	case BIO_CTRL_EOF: return data->eof;
	case BIO_CTRL_FLUSH: return 1;
	default: return 0;
	}
}

BIO_METHOD * tll_tls_bio_nosignal()
{
	if (impl)
		return impl;
	BIO_METHOD * tmp = BIO_meth_new(BIO_TYPE_NONE, "Socket BIO with MSG_NOSIGNAL flag");
	if (!tmp ||
			!BIO_meth_set_create(tmp, tll_tls_bio_create) ||
			!BIO_meth_set_destroy(tmp, tll_tls_bio_destroy) ||
			!BIO_meth_set_read(tmp, tll_tls_bio_read) ||
			!BIO_meth_set_write(tmp, tll_tls_bio_write) ||
			!BIO_meth_set_ctrl(tmp, tll_tls_bio_ctrl)) {
		BIO_meth_free(tmp); // Ok to free NULL
		return NULL;
	}
	impl = tmp;
	return impl;
}
