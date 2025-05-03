#pragma once

#include <tll/scheme/binder.h>
#include <tll/util/conv.h>

namespace tls_scheme {

static constexpr std::string_view scheme_string = R"(yamls+gz://eJxdzr8OAiEMBvCdp+jGIgn+mVg1PoCLo0GoiuE4cu0Nl4vvLhhJTremv+9rqiDZDg1IKQD6zKFPZGCWLmdVhbJ1KItzpAu5B3YoX0K11nkIjMcxxloP3sBW/+EJrZ+a7ha671NCx43Wugy3gNGTKROAgvmbpPH6rMkV8JQ/Cx5Cui//OARyv/c2WrwBkVdBEw==)";

struct WriteFull
{
	static constexpr size_t meta_size() { return 0; }
	static constexpr std::string_view meta_name() { return "WriteFull"; }
	static constexpr int meta_id() { return 30; }

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return WriteFull::meta_size(); }
		static constexpr auto meta_name() { return WriteFull::meta_name(); }
		static constexpr auto meta_id() { return WriteFull::meta_id(); }
		void view_resize() { this->_view_resize(meta_size()); }
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

struct WriteReady
{
	static constexpr size_t meta_size() { return 0; }
	static constexpr std::string_view meta_name() { return "WriteReady"; }
	static constexpr int meta_id() { return 40; }

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return WriteReady::meta_size(); }
		static constexpr auto meta_name() { return WriteReady::meta_name(); }
		static constexpr auto meta_id() { return WriteReady::meta_id(); }
		void view_resize() { this->_view_resize(meta_size()); }
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

struct Connect
{
	static constexpr size_t meta_size() { return 8; }
	static constexpr std::string_view meta_name() { return "Connect"; }
	static constexpr int meta_id() { return 10; }
	static constexpr size_t offset_subject = 0;

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return Connect::meta_size(); }
		static constexpr auto meta_name() { return Connect::meta_name(); }
		static constexpr auto meta_id() { return Connect::meta_id(); }
		void view_resize() { this->_view_resize(meta_size()); }

		std::string_view get_subject() const { return this->template _get_string<tll_scheme_offset_ptr_t>(offset_subject); }
		void set_subject(std::string_view v) { return this->template _set_string<tll_scheme_offset_ptr_t>(offset_subject, v); }
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

struct Disconnect
{
	static constexpr size_t meta_size() { return 0; }
	static constexpr std::string_view meta_name() { return "Disconnect"; }
	static constexpr int meta_id() { return 20; }

	template <typename Buf>
	struct binder_type : public tll::scheme::Binder<Buf>
	{
		using tll::scheme::Binder<Buf>::Binder;

		static constexpr auto meta_size() { return Disconnect::meta_size(); }
		static constexpr auto meta_name() { return Disconnect::meta_name(); }
		static constexpr auto meta_id() { return Disconnect::meta_id(); }
		void view_resize() { this->_view_resize(meta_size()); }
	};

	template <typename Buf>
	static binder_type<Buf> bind(Buf &buf, size_t offset = 0) { return binder_type<Buf>(tll::make_view(buf).view(offset)); }

	template <typename Buf>
	static binder_type<Buf> bind_reset(Buf &buf) { return tll::scheme::make_binder_reset<binder_type, Buf>(buf); }
};

} // namespace tls_scheme
