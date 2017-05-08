%% ----------------------------------------------------------------------------
%% The MIT License
%%
%% Copyright (c) 2016-2017 Andrei Nesterov <ae.nesterov@gmail.com>
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

-module(jose_jwa).

-include_lib("public_key/include/public_key.hrl").
-include("jose_parse.hrl").

%% API
-export([
	supports/0,
	from_curve/1,
	to_curve/1,
	sign/3,
	verify/4,
	generate_key/1
]).

%% Low Level API
-export([
	asn1der_ecdsa_sign/2,
	parse_asn1der_ecdsa_sign/2,
	asn1der_public_key/2,
	asn1der_private_key/2,
	parse_asn1der_key/1,
	asn1der_key_parameters/1,
	parse_asn1der_key_parameters/1
]).

%% Types
-type alg() :: binary().

-export_type([alg/0]).

%% =============================================================================
%% API
%% =============================================================================

-spec supports() -> [alg()].
supports() ->
	[?HS256, ?HS384, ?HS512, ?ES256, ?ES384, ?ES512]. %% none, rs256

-spec from_curve(atom()) -> alg().
from_curve(secp256r1) -> ?ES256;
from_curve(secp384r1) -> ?ES384;
from_curve(secp521r1) -> ?ES512.

-spec to_curve(alg()) -> atom().
to_curve(?ES256) -> secp256r1;
to_curve(?ES384) -> secp384r1;
to_curve(?ES512) -> secp521r1.

-spec sign(jsx:json_text(), alg(), iodata()) -> binary().
sign(Input, ?HS256, Key) -> crypto:hmac(sha256, Key, Input);
sign(Input, ?HS384, Key) -> crypto:hmac(sha384, Key, Input);
sign(Input, ?HS512, Key) -> crypto:hmac(sha512, Key, Input);
sign(Input, ?ES256, Key) -> parse_asn1der_ecdsa_sign(crypto:sign(ecdsa, sha256, Input, [Key, secp256r1]), 256);
sign(Input, ?ES384, Key) -> parse_asn1der_ecdsa_sign(crypto:sign(ecdsa, sha384, Input, [Key, secp384r1]), 384);
sign(Input, ?ES512, Key) -> parse_asn1der_ecdsa_sign(crypto:sign(ecdsa, sha512, Input, [Key, secp521r1]), 528).

-spec verify(jsx:json_text(), binary(), alg(), iodata()) -> boolean().
verify(Input, Sign, ?HS256, Key) -> Sign =:= crypto:hmac(sha256, Key, Input);
verify(Input, Sign, ?HS384, Key) -> Sign =:= crypto:hmac(sha384, Key, Input);
verify(Input, Sign, ?HS512, Key) -> Sign =:= crypto:hmac(sha512, Key, Input);
verify(Input, Sign, ?ES256, Key) -> crypto:verify(ecdsa, sha256, Input, asn1der_ecdsa_sign(Sign, 256), [Key, secp256r1]);
verify(Input, Sign, ?ES384, Key) -> crypto:verify(ecdsa, sha384, Input, asn1der_ecdsa_sign(Sign, 384), [Key, secp384r1]);
verify(Input, Sign, ?ES512, Key) -> crypto:verify(ecdsa, sha512, Input, asn1der_ecdsa_sign(Sign, 528), [Key, secp521r1]).

%% NOTE: the maximum effective length is chosen for keys
%%
%% The key for HMAC can be of any length (keys longer than B bytes are
%% first hashed using H).  However, less than L bytes is strongly
%% discouraged as it would decrease the security strength of the
%% function.  Keys longer than L bytes are acceptable but the extra
%% length would not significantly increase the function strength.
%%
%% ... H to be a cryptographic hash function where data is hashed by iterating a basic compression
%% function on blocks of data. We denote by B the byte-length of such blocks ...
%% and by L the byte-length of hash outputs.
%%
%% https://tools.ietf.org/html/rfc2104#section-3

%% SHA256: L=256 B=512
%% SHA384: L=384 B=1024
%% SHA512: L=512 B=1024
%%
%% https://en.wikipedia.org/wiki/SHA-2#Comparison_of_SHA_functions

-spec generate_key(alg()) -> binary() | {binary(), binary()}.
generate_key(?HS256) -> crypto:strong_rand_bytes(64);
generate_key(?HS384) -> crypto:strong_rand_bytes(128);
generate_key(?HS512) -> crypto:strong_rand_bytes(128);
generate_key(?ES256) -> crypto:generate_key(ecdh, secp256r1);
generate_key(?ES384) -> crypto:generate_key(ecdh, secp384r1);
generate_key(?ES512) -> crypto:generate_key(ecdh, secp521r1).

%% =============================================================================
%% Low Level API
%% =============================================================================

-spec asn1der_ecdsa_sign(binary(), non_neg_integer()) -> binary().
asn1der_ecdsa_sign(Val, ECPointSize) ->
	<<R:ECPointSize/big, S:ECPointSize/big>> = Val,
	public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S}).

-spec parse_asn1der_ecdsa_sign(binary(), non_neg_integer()) -> binary().
parse_asn1der_ecdsa_sign(Val, Size) ->
	#'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', Val),
	<<R:Size, S:Size>>.

-spec asn1der_public_key(alg(), iodata()) -> any(). 
asn1der_public_key(<<"ES", _/bits>> = Alg, Key) -> {#'ECPoint'{point = Key}, asn1der_key_parameters(Alg)};
asn1der_public_key(Alg, _Key)                   -> error({unsupported_public_key, Alg}).

-spec asn1der_private_key(alg(), iodata()) -> any().
asn1der_private_key(<<"ES", _/bits>> = Alg, Key) -> #'ECPrivateKey'{version = 1, privateKey = Key, parameters = asn1der_key_parameters(Alg)};
asn1der_private_key(Alg, _Key)                   -> error({unsupported_private_key, Alg}).

-spec parse_asn1der_key(any()) -> {alg(), binary()}.
parse_asn1der_key({#'ECPoint'{point = Point}, Params})                    -> {parse_asn1der_key_parameters(Params), Point};
parse_asn1der_key(#'ECPrivateKey'{privateKey = Key, parameters = Params}) -> {parse_asn1der_key_parameters(Params), Key};
parse_asn1der_key(DerItem)                                                -> error({bad_asn1der, DerItem}). 

-spec asn1der_key_parameters(alg()) -> any().
asn1der_key_parameters(<<"ES", _/bits>> = Alg) -> {namedCurve, pubkey_cert_records:namedCurves(to_curve(Alg))};
asn1der_key_parameters(Alg)                    -> error({unsupported_asn1der_params, Alg}).

-spec parse_asn1der_key_parameters(any()) -> alg().
parse_asn1der_key_parameters({namedCurve, Curve}) -> from_curve(pubkey_cert_records:namedCurves(Curve));
parse_asn1der_key_parameters(Params)              -> error({bad_asn1der_params, Params}).
