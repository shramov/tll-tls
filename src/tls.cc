#include <tll/channel/tcp.h>
#include <tll/channel/tcp.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>

#include "tls.h"
#include "scheme/tls.h"

struct OpenSSL_delete {
	void operator ()(EVP_PKEY *ptr) const { EVP_PKEY_free(ptr); }
	void operator ()(OSSL_STORE_CTX *ptr) const { OSSL_STORE_close(ptr); }
	void operator ()(SSL *ptr) const { SSL_free(ptr); }
	void operator ()(SSL_CTX *ptr) const { SSL_CTX_free(ptr); }
	void operator ()(X509 *ptr) const { X509_free(ptr); }
};

using namespace tll::tls;

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
	int init(const tll::Logger &log, Reader &reader)
	{
		_log = log;
		cert_path = reader.template getT<std::string>("cert");
		pkey_path = reader.template getT<std::string>("key", cert_path);
		ca_path = reader.template getT<std::string>("ca");
		level = reader.template getT<unsigned>("level", 2);
		ciphers = reader.template getT<std::string>("ciphers", "");
		return 0;
	}

	int open()
	{
		SSLErrbuf ssl_error;
		if (auto r = load_object<X509>(cert_path); !r)
			return _log.fail(EINVAL, "Failed to load certificate from {}", cert_path);
		else
			cert.reset(r);
		if (auto r = load_object<EVP_PKEY>(pkey_path); !r)
			return _log.fail(EINVAL, "Failed to load private key from {}", pkey_path);
		else
			pkey.reset(r);

		ssl_ctx.reset(SSL_CTX_new(TLS_method()));
		if (!ssl_ctx)
			return _log.fail(EINVAL, "Failed to create SSL context: {}", ssl_error());
		SSL_CTX_set_mode(ssl_ctx.get(), SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
		SSL_CTX_set_security_level(ssl_ctx.get(), level);
		if (ciphers.size() && !SSL_CTX_set_cipher_list(ssl_ctx.get(), ciphers.c_str()))
			return _log.fail(EINVAL, "Failed to set ciphers list: {}", ssl_error());
		if (!SSL_CTX_use_certificate(ssl_ctx.get(), cert.get()))
			return _log.fail(EINVAL, "Failed to set context certificate: {}", ssl_error());
		if (!SSL_CTX_use_PrivateKey(ssl_ctx.get(), pkey.get()))
			return _log.fail(EINVAL, "Failed to set context private key: {}", ssl_error());
		if (!SSL_CTX_load_verify_file(ssl_ctx.get(), ca_path.c_str()))
			return _log.fail(EINVAL, "Failed to set CA path: {}", ssl_error());

		SSL_CTX_set_verify(ssl_ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, _verify_cb);

		return 0;
	}

        static int _verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
	{
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

template <typename T>
class TLSSocket : public tll::channel::TcpSocket<T>
{
 protected:
	std::unique_ptr<SSL, OpenSSL_delete> _ssl;
	SSLErrbuf _ssl_error;

 public:
	using Base = tll::channel::TcpSocket<T>;

	static constexpr auto open_policy() { return Base::OpenPolicy::Manual; }
	static constexpr std::string_view channel_protocol() { return "tls-socket"; }

	bool with_ssl() const { return _ssl.get(); }

	int _open_ssl(SSL_CTX * ctx, bool client);

	int _post_data(const tll_msg_t *msg, int flags);
	int _process(long timeout, int flags);

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

template <template <typename T> typename Base>
struct Term : public Base<Term<Base>> {};

class TLSClient : public tll::channel::TcpClient<TLSClient, TLSSocket<TLSClient>>
{
	using Base = tll::channel::TcpClient<TLSClient, TLSSocket<TLSClient>>;
	SSLCommon _common;
 public:
	static constexpr std::string_view param_prefix() { return "tls"; }
	static constexpr std::string_view channel_protocol() { return "tls"; } // Only visible in logs
									       //
	int _init(const tll::Channel::Url &url, tll::Channel * master)
	{
		auto reader = channel_props_reader(url);
		if (_common.init(_log, reader))
			return _log.fail(EINVAL, "Failed to parse common SSL parameters");
		if (!reader)
			return _log.fail(EINVAL, "Invalid url: {}", reader.error());
		return Base::_init(url, master);
	}

	int _open(const tll::ConstConfig &cfg)
	{
		if (auto r = _common.open(); r)
			return r;
		return Base::_open(cfg);
	}

	int _on_connect()
	{
		if (auto r = _open_ssl(_common.ssl_ctx.get(), true); r)
			return r;
		_dcaps_poll(tll::dcaps::CPOLLIN);
		return 0;
	}

	auto _process(long timeout, int flags) { return TLSSocket<TLSClient>::_process(timeout, flags); }
	auto _process_connect() { return Base::_process_connect(); }
	auto _on_handshake() {}
};

class TLSServer : public tll::channel::TcpServer<TLSServer, Term<TLSSocket>>
{
	using Base = tll::channel::TcpServer<TLSServer, Term<TLSSocket>>;
	SSLCommon _common;

 public:
	static constexpr std::string_view param_prefix() { return "tls"; }
	static constexpr std::string_view channel_protocol() { return "tls"; }

	int _init(const tll::Channel::Url &url, tll::Channel * master)
	{
		if (auto r = Base::_init(url, master); r)
			return r;

		auto reader = channel_props_reader(url);
		if (_common.init(_log, reader))
			return _log.fail(EINVAL, "Failed to parse common SSL parameters");
		if (!reader)
			return _log.fail(EINVAL, "Invalid url: {}", reader.error());

		_scheme_control.reset(context().scheme_load(tls_scheme::scheme_string));
		if (!_scheme_control.get())
			return _log.fail(EINVAL, "Failed to load control scheme");
		return 0;
	}

	int _open(const tll::ConstConfig &cfg)
	{
		if (auto r = _common.open(); r)
			return r;
		return Base::_open(cfg);
	}

	int _on_accept(tll_channel_t * c)
	{
		auto tlsc = tll::channel_cast<Term<TLSSocket>>(c);
		if (!tlsc)
			return _log.fail(EINVAL, "Can not cast socket channel to TLSSocket");
		if (auto r = tlsc->_open_ssl(_common.ssl_ctx.get(), false); r)
			return r;
		return Base::_on_accept(c);
	}

	void _on_child_connect(Base::tcp_socket_t *, const tll::channel::tcp_connect_t *) {}
	void _on_child_closing(Base::tcp_socket_t * socket)
	{
		if (auto c = tll::channel_cast<Term<TLSSocket>>(socket->self()); c && c->with_ssl())
			return Base::_on_child_closing(socket);
	}
};

TLL_DEFINE_IMPL(Term<TLSSocket>);
TLL_DEFINE_IMPL(TLSClient);
TLL_DEFINE_IMPL(TLSServer);
TLL_DEFINE_IMPL(tll::channel::TcpServerSocket<TLSServer>);

std::optional<const tll_channel_impl_t *> TLS::_init_replace(const tll::Channel::Url &url, tll::Channel *master)
{
	auto reader = channel_props_reader(url);
	auto mode = reader.getT("mode", tll::channel::TcpChannelMode::Client);
	if (!reader)
		return _log.fail(std::nullopt, "Invalid url: {}", reader.error());
	switch (mode) {
	case tll::channel::TcpChannelMode::Client: return &TLSClient::impl;
	case tll::channel::TcpChannelMode::Server: return &TLSServer::impl;
	case tll::channel::TcpChannelMode::Socket: return &Term<TLSSocket>::impl;
	}

	return _log.fail(std::nullopt, "Unknown mode '{}", (int) mode);
}


template <typename T>
int TLSSocket<T>::_open_ssl(SSL_CTX * ctx, bool client)
{

	this->_log.debug("Initialize SSL object for fd {}", this->fd());
	_ssl.reset(SSL_new(ctx));
	if (!_ssl)
		return this->_log.fail(EINVAL, "Failed to create SSL object: {}", _ssl_error());

	//SSL_set_msg_callback(_ssl.get(), SSL_trace);
	//SSL_set_msg_callback_arg(_ssl.get(), BIO_new_fp(stdout, 0));

	if (!SSL_set_fd(_ssl.get(), this->fd()))
		return this->_log.fail(EINVAL, "Failed to set SSL fd {}: {}", this->fd(), _ssl_error());
	BIO_set_close(SSL_get_rbio(_ssl.get()), BIO_NOCLOSE);
	int r = 0;
	if (client)
		r = SSL_connect(_ssl.get());
	else
		r = SSL_accept(_ssl.get());
	if (!r)
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

	this->_log.trace("Post {} bytes of data", msg->size);
	auto r = SSL_write(_ssl.get(), msg->data, msg->size);
	if (r >= 0) {
		if ((size_t) r == msg->size)
			return 0;
		this->_log.debug("Partial send, store {} bytes of data", msg->size - r);
		this->_wbuf.resize(msg->size - r);
		memcpy(this->_wbuf.data(), r + (const char *) msg->data, msg->size - r);
		return 0;
	}

	if (r = _handle_error("Write", r); r == EAGAIN) {
		this->_log.debug("Partial send, store {} bytes of data", msg->size);
		this->_wbuf.resize(msg->size);
		memcpy(this->_wbuf.data(), msg->data, msg->size);
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
	if (r) {
		this->_wbuf.resize(0);
		return 0;
	}
	return _handle_error("Write", r);
}

template <typename T>
int TLSSocket<T>::_process_read()
{
	size_t size = 0;
	if (auto r = SSL_read_ex(_ssl.get(), this->_rbuf.data(), this->_rbuf.capacity(), &size); r <= 0)
		return _handle_error("Read", r);

	if (size == 0)
		return EAGAIN;
	tll_msg_t msg = {};
	msg.data = this->_rbuf.data();
	msg.size = size;
	this->_dcaps_pending(SSL_pending(_ssl.get()));
	this->_callback_data(&msg);
	return 0;
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
		this->_log.info("Want read");
		return EAGAIN;
	case SSL_ERROR_WANT_WRITE:
		this->_log.info("Want write");
		this->_update_dcaps(tll::dcaps::CPOLLOUT);
		return EAGAIN;
	case SSL_ERROR_ZERO_RETURN:
		this->_log.info("Connection closed by peer");
		this->close();
		return 0;
	case SSL_ERROR_SYSCALL:
		return this->_log.fail(EINVAL, "{} failed, syscall error: {}", op, _ssl_error());
	case SSL_ERROR_SSL:
		return this->_log.fail(EINVAL, "{} failed, SSL error: {}", op, _ssl_error());
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
	return _process_read();
}
