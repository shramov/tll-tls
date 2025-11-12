#include <tll/channel/frame.h>
#include <tll/channel/tcp.h>
#include <tll/channel/tcp.hpp>

#include "socket.h"
#include "tls.h"

using namespace tll::tls;

class TLSClient : public tll::channel::TcpClient<TLSClient, TLSSocket<TLSClient>>
{
	using Base = tll::channel::TcpClient<TLSClient, TLSSocket<TLSClient>>;
	SSLCommon _common;

 public:
	static constexpr std::string_view param_prefix() { return "tls"; }
	static constexpr std::string_view channel_protocol() { return "tls"; } // Only visible in logs

	int _init(const tll::Channel::Url &url, tll::Channel * master)
	{
		if (auto r = Base::_init(url, master); r)
			return r;

		auto reader = channel_props_reader(url);
		_frame = reader.getT("frame", Frame::Std, {{"none", Frame::None}, {"std", Frame::Std}, {"l4m4s8", Frame::Std}});
		if (_common.init(_log, reader))
			return _log.fail(EINVAL, "Failed to parse common SSL parameters");
		if (!reader)
			return _log.fail(EINVAL, "Invalid url: {}", reader.error());

		_scheme_control.reset(context().scheme_load(tls_client_scheme::scheme_string));
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

	int _on_connect()
	{
		if (auto r = _open_ssl(_common.ssl_ctx.get(), true, _frame); r)
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
	Frame _frame = Frame::Std;

 public:
	static constexpr std::string_view param_prefix() { return "tls"; }
	static constexpr std::string_view channel_protocol() { return "tls"; }

	int _init(const tll::Channel::Url &url, tll::Channel * master)
	{
		if (auto r = Base::_init(url, master); r)
			return r;

		auto reader = channel_props_reader(url);
		_frame = reader.getT("frame", Frame::Std, {{"none", Frame::None}, {"std", Frame::Std}, {"l4m4s8", Frame::Std}});
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
		if (auto r = tlsc->_open_ssl(_common.ssl_ctx.get(), false, _frame); r)
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
