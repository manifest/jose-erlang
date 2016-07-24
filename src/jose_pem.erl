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

-module(jose_pem).

-include_lib("public_key/include/public_key.hrl").
-include("jose_parse.hrl").

%% API
-export([
	key/2,
	public_key/2,
	private_key/2,
	parse_key/1
]).

%% =============================================================================
%% API
%% =============================================================================

-spec key(jose_jwa:alg(), iodata()) -> iodata().
key(<<"ES", _/bits>> = Alg, Key) when ?IS_PUBLIC_KEY(Alg, Key) -> public_key(Alg, Key);
key(<<"ES", _/bits>> = Alg, Key)                               -> private_key(Alg, Key).

-spec public_key(jose_jwa:alg(), iodata()) -> iodata().
public_key(Alg, Key) ->
	public_key:pem_encode([public_key:pem_entry_encode('SubjectPublicKeyInfo', jose_jwa:asn1der_public_key(Alg, Key))]).

-spec private_key(jose_jwa:alg(), iodata()) -> iodata().
private_key(Alg, Key) ->
	public_key:pem_encode([public_key:pem_entry_encode('ECPrivateKey', jose_jwa:asn1der_private_key(Alg, Key))]).

-spec parse_key(iodata()) -> {jose_jwa:alg(), iodata()}.
parse_key(PemData) ->
	jose_jwa:parse_asn1der_key(public_key:pem_entry_decode(hd(public_key:pem_decode(PemData)))).

%% =============================================================================
%% Tests 
%% =============================================================================

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

round_trip_test_() ->
	Test =
		lists:foldl(
			fun
				(<<"ES", _/bits>> = Alg, Acc) ->
					{Pub, Priv} = jose_jwa:generate_key(Alg),
					[{Alg, Pub}, {Alg, Priv} | Acc];
				(_Alg, Acc) ->
					Acc
			end,
			[],
			jose_jwa:supports()),

	[{Alg, ?_assertEqual({Alg, Key}, jose_pem:parse_key(jose_pem:key(Alg, Key)))}
		|| {Alg, Key} <- Test].

-endif.
