#ifndef _TLL_TLS_SOCKET_H
#define _TLL_TLS_SOCKET_H

#include <tll/channel/frame.h>
#include <tll/channel/tcp.h>
#include <tll/channel/tcp.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>

#include <filesystem>

#include "tll/tls/bio-nosignal.h"
#include "scheme/tls.h"
#include "scheme/tls-client.h"

namespace tll::tls {

enum class Frame { None, Std };

struct OpenSSL_delete {
	void operator ()(BIO *ptr) const { BIO_free(ptr); }
	void operator ()(EVP_PKEY *ptr) const { EVP_PKEY_free(ptr); }
	void operator ()(OSSL_STORE_CTX *ptr) const { OSSL_STORE_close(ptr); }
	void operator ()(SSL *ptr) const { SSL_free(ptr); }
	void operator ()(SSL_CTX *ptr) const { SSL_CTX_free(ptr); }
	void operator ()(X509 *ptr) const { X509_free(ptr); }
};

struct SSLErrbuf
{
	std::string _errbuf;

	std::string_view operator () ()
	{
		_errbuf.resize(256);
		ERR_error_string_n(ERR_get_error(), _errbuf.data(), _errbuf.size());
		return _errbuf;
	}
};

struct SSLCommon
{
	tll::Logger _log = { "" };

	std::unique_ptr<SSL_CTX, OpenSSL_delete> ssl_ctx;
	std::unique_ptr<X509, OpenSSL_delete> cert;
	std::unique_ptr<EVP_PKEY, OpenSSL_delete> pkey;

	std::string cert_path;
	std::string pkey_path;
	std::string ca_path;
	std::string ciphers;
	int level = -1;

	template <typename Reader>
	int init(const tll::Logger &log, Reader &reader, bool client)
	{
		_log = log;
		if (client)
			cert_path = reader.template getT<std::string>("cert", "");
		else
			cert_path = reader.template getT<std::string>("cert");
		pkey_path = reader.template getT<std::string>("key", cert_path);
		ca_path = reader.template getT<std::string>("ca", "default");
		level = reader.template getT<unsigned>("level", 2);
		ciphers = reader.template getT<std::string>("ciphers", "");
		return 0;
	}

	int open()
	{
		SSLErrbuf ssl_error;
		if (cert_path.size()) {
			if (auto r = load_object<X509>(cert_path); !r)
				return _log.fail(EINVAL, "Failed to load certificate from {}", cert_path);
			else
				cert.reset(r);
		}
		if (pkey_path.size()) {
			if (auto r = load_object<EVP_PKEY>(pkey_path); !r)
				return _log.fail(EINVAL, "Failed to load private key from {}", pkey_path);
			else
				pkey.reset(r);
		}

		ssl_ctx.reset(SSL_CTX_new(TLS_method()));
		if (!ssl_ctx)
			return _log.fail(EINVAL, "Failed to create SSL context: {}", ssl_error());
		SSL_CTX_set_app_data(ssl_ctx.get(), this);
		SSL_CTX_set_mode(ssl_ctx.get(), SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
		SSL_CTX_set_security_level(ssl_ctx.get(), level);
		if (ciphers.size() && !SSL_CTX_set_cipher_list(ssl_ctx.get(), ciphers.c_str()))
			return _log.fail(EINVAL, "Failed to set ciphers list: {}", ssl_error());
		if (cert && !SSL_CTX_use_certificate(ssl_ctx.get(), cert.get()))
			return _log.fail(EINVAL, "Failed to set context certificate: {}", ssl_error());
		if (pkey && !SSL_CTX_use_PrivateKey(ssl_ctx.get(), pkey.get()))
			return _log.fail(EINVAL, "Failed to set context private key: {}", ssl_error());

		std::error_code ec;
		if (ca_path == "default") {
			if (!SSL_CTX_set_default_verify_paths(ssl_ctx.get()))
				return _log.fail(EINVAL, "Failed to set default CA paths: {}", ssl_error());
		} else if (std::filesystem::is_directory(ca_path, ec)) {
			if (!SSL_CTX_load_verify_dir(ssl_ctx.get(), ca_path.c_str()))
				return _log.fail(EINVAL, "Failed to set CA path '{}': {}", ca_path, ssl_error());
		} else if (!SSL_CTX_load_verify_file(ssl_ctx.get(), ca_path.c_str()))
			return _log.fail(EINVAL, "Failed to set CA file '{}': {}", ca_path, ssl_error());

		SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, _verify_cb);

		return 0;
	}

        static int _verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
	{
		if (preverify_ok)
			return preverify_ok;

		auto ssl = static_cast<const SSL *>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
		auto self = static_cast<SSLCommon *>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));

		auto err = X509_STORE_CTX_get_error(ctx);
		auto cert = X509_STORE_CTX_get_current_cert(ctx);
		std::unique_ptr<BIO, OpenSSL_delete> bio { BIO_new(BIO_s_mem()) };
		if (X509_NAME_print_ex(bio.get(), X509_get_subject_name(cert), 0, XN_FLAG_ONELINE) == -1) {
			BIO_reset(bio.get());
			BIO_puts(bio.get(), "Invalid name");
		}
		char * name = nullptr;
		BIO_get_mem_data(bio.get(), &name);

		self->_log.error("Certificate verification failed: {}\n  certificate: {}", X509_verify_cert_error_string(err), name);
		return preverify_ok;
	}

	template <typename T>
	T * load_object(const std::string &path)
	{
		std::unique_ptr<T, OpenSSL_delete> r;
		auto store = OSSL_STORE_open(path.c_str(), nullptr, nullptr, nullptr, nullptr);
		SSLErrbuf ssl_error;
		if (!store)
			return _log.fail(nullptr, "Failed to open object store '{}': {}", path, ssl_error());
		while (!OSSL_STORE_eof(store)) {
			auto info = OSSL_STORE_load(store);
			if (!info)
				continue;
			auto type = OSSL_STORE_INFO_get_type(info);
			if constexpr (std::is_same_v<T, X509>) {
				if (type == OSSL_STORE_INFO_CERT)
					r.reset(OSSL_STORE_INFO_get1_CERT(info));
			} else if constexpr (std::is_same_v<T, EVP_PKEY>) {
				if (type == OSSL_STORE_INFO_PKEY)
					r.reset(OSSL_STORE_INFO_get1_PKEY(info));
			} else {
				static_assert("Unknown object type");
			}
			OSSL_STORE_INFO_free(info);
		}
		OSSL_STORE_close(store);
		return r.release();
	}
};

template <template <typename T> typename Base>
struct Term : public Base<Term<Base>> {};

template <typename T>
class TLSSocket : public tll::channel::TcpSocket<T>
{
 protected:
	std::unique_ptr<SSL, OpenSSL_delete> _ssl;
	SSLErrbuf _ssl_error;
	Frame _frame = Frame::Std;

 public:
	using Base = tll::channel::TcpSocket<T>;

	static constexpr auto open_policy() { return Base::OpenPolicy::Manual; }
	static constexpr std::string_view channel_protocol() { return "tls-socket"; }

	bool with_ssl() const { return _ssl.get(); }

	int _open_ssl(SSL_CTX * ctx, bool client, Frame frame);

	int _post_data(const tll_msg_t *msg, int flags);
	int _process(long timeout, int flags);

	int _process_pending();
	int _process_read();
	int _process_write();
	int _process_handshake();
	int _process_connect() { return 0; }

	int _handle_error(std::string_view op, int r);
	void _on_handshake()
	{
		std::vector<char> buf;
		auto data = tls_scheme::Connect::bind_reset(buf);
		if (auto peer = SSL_get0_peer_certificate(_ssl.get()); peer) {
			auto str = X509_NAME_oneline(X509_get_subject_name(peer), nullptr, 0);
			if (str) {
				data.set_subject(str);
				free(str);
			}
		}
		tll_msg_t msg = {
			.type = TLL_MESSAGE_CONTROL,
			.msgid = data.meta_id(),
			.data = data.view().data(),
			.size = data.view().size(),
			.addr = this->msg_addr(),
		};
		this->_callback(&msg);
	}
};

template <typename T>
int TLSSocket<T>::_open_ssl(SSL_CTX * ctx, bool client, Frame frame)
{

	_frame = frame;
	this->_log.debug("Initialize SSL object for fd {}", this->fd());
	_ssl.reset(SSL_new(ctx));
	if (!_ssl)
		return this->_log.fail(EINVAL, "Failed to create SSL object: {}", _ssl_error());

	//SSL_set_msg_callback(_ssl.get(), SSL_trace);
	//SSL_set_msg_callback_arg(_ssl.get(), BIO_new_fp(stdout, 0));

	auto bio = BIO_new(tll_tls_bio_nosignal());
	if (!bio)
		return this->_log.fail(EINVAL, "Failed to create BIO: {}", _ssl_error());
	BIO_set_fd(bio, this->internal.fd, 0);
	SSL_set_bio(_ssl.get(), bio, bio);
	//BIO_set_close(SSL_get_rbio(_ssl.get()), BIO_NOCLOSE);
	if (client)
		return 0;
	if (!SSL_accept(_ssl.get()))
		return this->_log.fail(EINVAL, "Failed to initiate SSL handshake: {}", _ssl_error());
	return 0;
}

template <typename T>
int TLSSocket<T>::_post_data(const tll_msg_t *msg, int flags)
{
	if (msg->type != TLL_MESSAGE_DATA)
		return 0;
	if (this->_wbuf.size())
		return EAGAIN;

	size_t full_size = msg->size;
	if (_frame == Frame::Std) {
		using Frame = tll_frame_t;
		full_size += sizeof(Frame);
		if (this->_wbuf.available() < full_size)
			this->_wbuf.resize(this->_wbuf.size() + full_size);
		auto frame = static_cast<Frame *>(this->_wbuf.end());
		tll::frame::FrameT<Frame>::write(msg, frame);
		memcpy(frame + 1, msg->data, msg->size);
	} else {
		if (this->_wbuf.available() < msg->size)
			this->_wbuf.resize(this->_wbuf.size() + msg->size);
		memcpy(this->_wbuf.end(), msg->data, msg->size);
	}

	if (this->_wbuf.size()) {
		this->_wbuf.extend(full_size);
		return 0;
	}

	this->_log.trace("Post {} bytes of data", full_size);
	auto r = SSL_write(_ssl.get(), this->_wbuf.end(), full_size);
	if (r >= 0) {
		if ((size_t) r == full_size)
			return 0;
		this->_log.debug("Partial send, store {} bytes of data", full_size - r);
		this->_wbuf.extend(full_size);
		this->_wbuf.done(r);
		this->_on_output_full();
		return 0;
	}

	if (r = _handle_error("Write", r); r == EAGAIN) {
		this->_log.debug("Partial send, store {} bytes of data", full_size);
		this->_wbuf.extend(full_size);
		this->_on_output_full();
		return 0;
	} else
		return r;
}

template <typename T>
int TLSSocket<T>::_process_write()
{
	if (this->_wbuf.size() == 0)
		return 0;
	auto r = SSL_write(_ssl.get(), this->_wbuf.data(), this->_wbuf.size());
	if (r >= 0) {
		this->_wbuf.done(r);
		if (this->_wbuf.size() == 0)
			this->_on_output_ready();
		return 0;
	}
	return _handle_error("Write", r);
}

template <typename T>
int TLSSocket<T>::_process_pending()
{
	this->_log.trace("Check pending data ({} stored)", this->_rbuf.size());
	if (_frame == Frame::None) {
		if (!this->_rbuf.size())
			return EAGAIN;
		tll_msg_t msg = { .type = TLL_MESSAGE_DATA, .data = this->_rbuf.data(), .size = this->_rbuf.size() };
		this->_rbuf.done(this->_rbuf.size());
		this->_dcaps_pending(SSL_pending(_ssl.get()));
		this->_callback_data(&msg);
		return 0;
	}

	using Frame = tll_frame_t;
	auto frame = this->_rbuf.template dataT<Frame>();
	if (!frame)
		return EAGAIN;
	this->_log.trace("Frame available, check for data (size: {}, msgid: {}, seq: {})", frame->size, frame->msgid, frame->seq);
	// Check for pending data
	const auto full_size = sizeof(Frame) + frame->size;
	if (this->_rbuf.size() < full_size) {
		if (full_size > this->_rbuf.capacity())
			return this->_log.fail(EMSGSIZE, "Message size {} too large", full_size);
		this->_dcaps_pending(SSL_pending(_ssl.get()));
		return EAGAIN;
	}

	tll_msg_t msg = { TLL_MESSAGE_DATA };
	tll::frame::FrameT<Frame>::read(&msg, frame);
	msg.data = this->_rbuf.template dataT<void>(sizeof(Frame), 0);
	msg.addr = this->_msg_addr;
	msg.time = this->_timestamp.count();
	this->_rbuf.done(full_size);
	this->_dcaps_pending(this->_rbuf.template dataT<Frame>() || SSL_pending(_ssl.get()));
	this->_callback_data(&msg);
	return 0;
}

template <typename T>
int TLSSocket<T>::_process_read()
{
	if (this->_rbuf._offset >= this->_rbuf.capacity() / 2 || this->_rbuf.available() == 0)
		this->_rbuf.force_shift();

	if (auto r = SSL_read(_ssl.get(), this->_rbuf.end(), this->_rbuf.available()); r < 0) {
		return _handle_error("Read", r);
	} else if (r == 0) {
		this->_log.debug("Connection closed");
		this->channelT()->_on_close();
		return EAGAIN;
	} else {
		this->_log.trace("Got {} bytes of data ({} already stored)", r, this->_rbuf.size());
		this->_rbuf.extend(r);
	}

	return _process_pending();
}

template <typename T>
int TLSSocket<T>::_process_handshake()
{
	this->_log.info("Try handshake");
	char buf[1];
	size_t size = 0;
	if (auto r = SSL_peek_ex(_ssl.get(), buf, 1, &size); r <= 0) {
		if (r = _handle_error("Handshake", r); r != EAGAIN) {
			_ssl.reset();
			return r;
		}
	}

	if (SSL_is_init_finished(_ssl.get())) {
		this->_log.info("Handshake finished");
		this->state(tll::state::Active);
		this->_dcaps_pending(SSL_pending(_ssl.get()));
		this->channelT()->_on_handshake();
		return 0;
	}

	return 0;
}

template <typename T>
int TLSSocket<T>::_handle_error(std::string_view op, int r)
{
	switch (SSL_get_error(_ssl.get(), r)) {
	case SSL_ERROR_WANT_READ:
		this->_log.trace("Want read");
		return EAGAIN;
	case SSL_ERROR_WANT_WRITE:
		this->_log.trace("Want write");
		this->_update_dcaps(tll::dcaps::CPOLLOUT);
		return EAGAIN;
	case SSL_ERROR_ZERO_RETURN:
		this->_log.info("Connection closed by peer");
		this->close();
		return 0;
	case SSL_ERROR_SYSCALL:
		return this->state_fail(EINVAL, "{} failed, syscall error: {}", op, _ssl_error());
	case SSL_ERROR_SSL:
		return this->state_fail(EINVAL, "{} failed, SSL error: {}", op, _ssl_error());
	default:
		return this->_log.fail(EINVAL, "{} failed: {}", op, _ssl_error());
	}
}

template <typename T>
int TLSSocket<T>::_process(long timeout, int flags)
{
	if (this->state() == tll::state::Opening) {
		this->_log.info("Opening process");
		if (!_ssl)
			return this->channelT()->_process_connect();
		return _process_handshake();
	}
	if (auto r = _process_write(); r)
		return r;
	if (auto r = _process_pending(); r != EAGAIN)
		return r;
	return _process_read();
}

} // namespace tll::tls

#endif//_TLL_TLS_SOCKET_H
