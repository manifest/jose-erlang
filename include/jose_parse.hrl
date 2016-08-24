-ifndef(JOSE_PARSE_HRL).
-define(JOSE_PARSE_HRL, 1).

-define(HS256, <<"HS256">>).
-define(HS384, <<"HS384">>).
-define(HS512, <<"HS512">>).
-define(ES256, <<"ES256">>).
-define(ES384, <<"ES384">>).
-define(ES512, <<"ES512">>).

%% NOTE: total size is calculated as size of the binary key
%% +1 byte for asn1 der-encoded type
-define(IS_PUBLIC_KEY(ALG, K),
	((ALG =:= ?ES256) andalso byte_size(K) =:= 65) orelse
	((ALG =:= ?ES384) andalso byte_size(K) =:= 97) orelse
	((ALG =:= ?ES512) andalso byte_size(K) =:= 133)).

-endif.
