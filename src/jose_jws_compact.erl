%% ----------------------------------------------------------------------------
%% The MIT License
%%
%% Copyright (c) 2016 Andrei Nesterov <ae.nesterov@gmail.com>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to
%% deal in the Software without restriction, including without limitation the
%% rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
%% sell copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
%% IN THE SOFTWARE.
%% ----------------------------------------------------------------------------

-module(jose_jws_compact).

%% API
-export([
	encode/3,
	decode/3,
	decode/4,
	decode_fn/2,
	decode_fn/3,
	parse/1,
	parse/2
]).

%% Definitions
-define(JWT, <<"JWT">>).

%% Types
-type select_key_result() :: {ok, {jose_jwa:alg(), iodata(), options()}} | {error, any()}.
-type select_key() :: fun((list(), options()) -> select_key_result()).
-type parse_options() :: map().
%% #{parse_header => base64 | binary | map,
%%   parse_payload => base64 | binary | map,
%%   parse_signature => base64 | binary}.
-type options() :: map().
%% parse_options() + jose_claim:verify_options().

-export_type([select_key/0, select_key_result/0, parse_options/0, options/0]).

%% =============================================================================
%% API
%% =============================================================================

-spec encode(map() | binary(), jose_jwa:alg(), iodata()) -> binary().
encode(Payload, Alg, Key) when is_map(Payload) ->
	encode(jsx:encode(Payload), Alg, Key);
encode(Payload, Alg, Key) when is_binary(Alg) ->
	encode_(Payload, jsx:encode(#{typ => ?JWT, alg => Alg}), Alg, Key);
encode(Payload, #{alg := Alg} = Header, Key) ->
	encode_(Payload, jsx:encode(Header), Alg, Key).

-spec decode(binary(), jose_jwa:alg(), iodata()) -> binary() | map().
decode(Token, Alg, Key) ->
	decode(Token, Alg, Key, default_options()).

-spec decode(binary(), jose_jwa:alg(), iodata(), options()) -> binary() | map().
decode(Token, Alg, Key, Opts) ->
	%% NOTE: it's impossible to decode token without parsing its signature
	L = [_Header, Payload, Sign, Input] = parse(Token, Opts#{parse_signature => binary}),
	jose_claim:verify(Payload, Opts),
	case jose_jwa:verify(Input, Sign, Alg, Key) of
		true -> Payload;
		_    -> error({bad_signature, L})
	end.

-spec decode_fn(select_key(), binary()) -> binary() | map().
decode_fn(Fn, Token) ->
	decode_fn(Fn, Token, (default_options())#{parse_header => map}).

-spec decode_fn(select_key(), binary(), options()) -> binary() | map().
decode_fn(Fn, Token, Opts0) ->
	%% NOTE: it's impossible to decode token without parsing its signature
	L = [_Header, Payload, Sign, Input] = parse(Token, Opts0#{parse_signature => binary}),
	{Alg, Key, Opts1} =
		try Fn(L, Opts0) of
			{ok, Res}       -> Res;
			{error, Reason} -> error({bad_token, Reason});
			Result          -> error({bad_select_key, {bad_result, Result}})
		catch _:Reason    -> error({bad_select_key, Reason})
		end,
	jose_claim:verify(Payload, Opts1),
	case jose_jwa:verify(Input, Sign, Alg, Key) of
		true -> Payload;
		_    -> error({bad_signature, L})
	end.

-spec parse(binary()) -> list().
parse(Token) ->
	parse(Token, #{}).

-spec parse(binary(), parse_options()) -> list().
parse(Token, Opts) ->
	parse_header(Token, <<>>, Opts).

%% =============================================================================
%% Internal function
%% =============================================================================

-spec encode_(binary(), binary(), jose_jwa:alg(), iodata()) -> binary().
encode_(Payload, Header, Alg, Key) ->
	Input = <<(base64url:encode(Header))/binary, $., (base64url:encode(Payload))/binary>>,
	SignB64 = base64url:encode(jose_jwa:sign(Input, Alg, Key)),
	<<Input/binary, $., SignB64/binary>>.

-spec parse_header(binary(), binary(), options()) -> list(). 
parse_header(<<$., R/bits>>, Acc, #{parse_header := map} = Opts) ->
	parse_payload(R, <<>>, <<Acc/binary, $.>>, jsx:decode(base64url:decode(Acc), [return_maps]), Opts);
parse_header(<<$., R/bits>>, Acc, #{parse_header := binary} = Opts) ->
	parse_payload(R, <<>>, <<Acc/binary, $.>>, base64url:decode(Acc), Opts);
parse_header(<<$., R/bits>>, Acc, Opts) ->
	parse_payload(R, <<>>, <<Acc/binary, $.>>, Acc, Opts);
parse_header(<<C, R/bits>>, Acc, Opts) ->
	parse_header(R, <<Acc/binary, C>>, Opts).

-spec parse_payload(binary(), binary(), binary(), binary(), options()) -> list().
parse_payload(<<$., R/bits>>, Acc, I, H, #{parse_payload := map} = Opts) ->
	parse_signature(R, <<>>, <<I/binary, Acc/binary>>, H, parse_payload_deep(Acc), Opts);
parse_payload(<<$., R/bits>>, Acc, I, H, #{parse_payload := binary} = Opts) ->
	parse_signature(R, <<>>, <<I/binary, Acc/binary>>, H, base64url:decode(Acc), Opts);
parse_payload(<<$., R/bits>>, Acc, I, H, Opts) ->
	parse_signature(R, <<>>, <<I/binary, Acc/binary>>, H, Acc, Opts);
parse_payload(<<C, R/bits>>, Acc, I, H, Opts) ->
	parse_payload(R, <<Acc/binary, C>>, I, H, Opts).

-spec parse_signature(binary(), binary(), binary(), binary(), binary(), options()) -> list().
parse_signature(<<>>, Acc, I, H, P, #{parse_signature := binary}) ->
	[H, P, base64url:decode(Acc), I];
parse_signature(<<>>, Acc, I, H, P, _Opts) ->
	[H, P, Acc, I];
parse_signature(<<C, R/bits>>, Acc, I, H, P, Opts) ->
	parse_signature(R, <<Acc/binary, C>>, I, H, P, Opts).

-spec parse_payload_deep(binary()) -> map() | binary().
parse_payload_deep(B64) ->
	Data = base64url:decode(B64),
	try jsx:decode(Data, [return_maps])
	catch _:_ -> Data end.

-spec default_options() -> options().
default_options() ->
	#{parse_header => map,
		parse_payload => map,
		parse_signature => binary,
		verify => [exp, nbf, iat],
		leeway => 1}.

%% =============================================================================
%% Tests 
%% =============================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

rfc7515_a3_test_() ->
	%% https://tools.ietf.org/html/rfc7515#appendix-A.3
	%% 
	%% {"kty":"EC",
	%%  "crv":"P-256",
	%%  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
	%%  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
	%%  "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
	%% }

	Alg = <<"ES256">>,
	Payload = <<"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}">>,
	X = <<127,205,206,39,112,246,196,93,65,131,203,238,111,219,75,123,88,7,51,53,123, 233,239,19,186,207,110,60,123,209,84,69>>,
	Y = <<199,241,68,205,27,189,155,126,135,44,223,237,185,238,185,244,179,105,93,110,169,11,36,173,138,70,35,40,133,136,229,173>>,
	D = <<142,155,16,158,113,144,152,191,152,4,135,223,31,93,119,233,203,41,96,110,190,210,38,59,95,87,194,19,223,132,244,178>>,
	[{"round trip", ?_assertEqual(Payload, decode(encode(Payload, Alg, D), Alg, <<4, X/binary, Y/binary>>, #{parse_payload => binary}))}].

-endif.
