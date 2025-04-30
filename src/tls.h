// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Pavel Shramov <shramov@mexmat.net>

#ifndef _TLS_H
#define _TLS_H

#include <tll/channel/base.h>

namespace tll::tls {

class TLS : public tll::channel::Base<TLS>
{
 public:
	static constexpr std::string_view channel_protocol() { return "tls"; }

	std::optional<const tll_channel_impl_t *> _init_replace(const tll::Channel::Url &url, tll::Channel *master);

	int _init(const tll::Channel::Url &url, tll::Channel * master) { return _log.fail(EINVAL, "Failed to choose proper TLS channel"); }
};

} // namespace tll::tls

#endif//_TLS_H
