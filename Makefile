PROJECT = jose
PROJECT_DESCRIPTION = Simple and fast JOSE library
PROJECT_VERSION = 0.1.0

LOCAL_DEPS = \
	crypto \
	public_key

DEPS = \
	base64url \
	jsx

dep_base64url = git git://github.com/dvv/base64url.git v1.0
dep_jsx = git git://github.com/talentdeficit/jsx.git v2.8.0

SHELL_DEPS = tddreloader
SHELL_OPTS = \
	-eval 'application:ensure_all_started($(PROJECT), permanent)' \
	-s tddreloader start

include erlang.mk
