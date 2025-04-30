#pragma once

#include <tll/scheme/binder.h>
#include <tll/util/conv.h>

namespace tls_scheme {

static constexpr std::string_view scheme_string = R"(yamls+gz://eJxVjLEOwjAMRPd8hTcvRCods8J/oOK6YNQ6ETZDVfHvJAgk2E737l0EHRZOgBgAcnHJagk2pFJiI1YGYqzcZzsZXXlhfIb4tQ5ZlcmbLGOCfVfDJDyPlmoCiLB9lvY439pyB76Wd+F30cvv2VGM/v/6LrwAnCgwjA==)";

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
