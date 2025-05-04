project('tll-tls', 'c', 'cpp'
	, version: '0.0.0'
	, license: 'MIT'
	, default_options: ['cpp_std=c++2a', 'werror=true', 'optimization=2']
)

include = [include_directories('src', '.')]

fmt = dependency('fmt')
ssl = dependency('openssl')
tll = dependency('tll')

shared_library('tll-tls'
	, ['src/module.cc', 'src/tls.cc', 'src/nosignal.c']
	, include_directories : include
	, dependencies : [fmt, ssl, tll]
	, install : true
)

test('pytest', import('python').find_installation('python3')
	, args: ['-m', 'pytest', '-v', 'tests']
	, env: 'BUILD_DIR=@0@'.format(meson.current_build_dir())
	, workdir: meson.current_source_dir()
)
