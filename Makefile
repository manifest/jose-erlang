PROJECT = jose
PROJECT_DESCRIPTION = Simple and fast JOSE library

LOCAL_DEPS = \
	crypto \
	public_key

DEPS = \
	base64url \
	jsx

BUILD_DEPS = \
	version.mk

DEP_PLUGINS = \
	version.mk

dep_base64url = git git://github.com/dvv/base64url.git v1.0
dep_jsx = git git://github.com/talentdeficit/jsx.git v2.8.2
dep_version.mk = git git://github.com/manifest/version.mk.git master

SHELL_DEPS = tddreloader
SHELL_OPTS = \
	-eval 'application:ensure_all_started($(PROJECT), permanent)' \
	-s tddreloader start

include erlang.mk
