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

-module(jose_claim).

%% API
-export([
	verify/2,
	verify_exp/1,
	verify_exp/2,
	verify_nbf/1,
	verify_nbf/2,
	verify_iat/1,
	verify_iat/2,
	unix_time/1
]).

%% Types
-type unix_time() :: non_neg_integer().
-type use() :: required | optional.
-type jti_check() :: fun((map()) -> ok | {error, any()}).
-type check()
	:: exp | {exp, use()}
	 | nbf | {nbf, use()}
	 | iat | {iat, use()}
	 | {iss, binary() | use()} | {iss, binary(), use()}
	 | {sub, binary() | use()} | {sub, binary(), use()}
	 | {aud, [binary()] | use()} | {aud, [binary()], use()}
	 | {jti, jti_check()}.
-type verify_options() :: map().
%% #{verify => [check()],
%%   leeway => non_neg_integer()}.

-export_type([unix_time/0, verify_options/0, check/0]).

%% =============================================================================
%% API
%% =============================================================================

-spec verify(binary() | map(), verify_options()) -> ok.
verify(Payload, #{verify := L} = Opts) when is_map(Payload) -> 
	[verify_claims(Check, Payload, Opts) || Check <- L],
	ok;
verify(_Payload, _Opts) ->
	ok.

-spec verify_exp(unix_time()) -> ok.
verify_exp(Val) ->
	verify_exp(Val, unix_time(erlang:timestamp())).

-spec verify_exp(unix_time(), unix_time()) -> ok.
verify_exp(Val, Time) when is_integer(Val) andalso Val > Time -> ok;
verify_exp(Val, Time)                                         -> error({nomatch_exp, Val, Time}).

-spec verify_nbf(unix_time()) -> ok.
verify_nbf(Val) ->
	verify_nbf(Val, unix_time(erlang:timestamp())).

-spec verify_nbf(unix_time(), unix_time()) -> ok.
verify_nbf(Val, Time) when is_integer(Val) andalso Val =< Time -> ok;
verify_nbf(Val, Time)                                          -> error({nomatch_nbf, Val, Time}).

-spec verify_iat(unix_time()) -> ok.
verify_iat(Val) ->
	verify_nbf(Val).

-spec verify_iat(unix_time(), unix_time()) -> ok.
verify_iat(Val, Time) ->
	verify_nbf(Val, Time).

-spec unix_time(erlang:timestamp()) -> unix_time().
unix_time({MS, S, _}) ->
	MS * 1000000 + S.

%% =============================================================================
%% Internal functions
%% =============================================================================

-spec verify_claims(check(), map(), verify_options()) -> ok.
verify_claims(exp, Payload, Opts)                            -> verify_claims_exp(Payload, Opts, optional);
verify_claims({exp, Use}, Payload, Opts)                     -> verify_claims_exp(Payload, Opts, Use);
verify_claims(nbf, Payload, Opts)                            -> verify_claims_nbf(Payload, Opts, optional);
verify_claims({nbf, Use}, Payload, Opts)                     -> verify_claims_nbf(Payload, Opts, Use);
verify_claims(iat, Payload, Opts)                            -> verify_claims_iat(Payload, Opts, optional);
verify_claims({iat, Use}, Payload, Opts)                     -> verify_claims_iat(Payload, Opts, Use);
verify_claims({iss, Use}, Payload, _Opts) when is_atom(Use)  -> verify_claims_iss(Payload, Use);
verify_claims({iss, Val}, Payload, _Opts)                    -> verify_claims_iss(Val, Payload, required);
verify_claims({iss, Val, Use}, Payload, _Opts)               -> verify_claims_iss(Val, Payload, Use);
verify_claims({sub, Use}, Payload, _Opts) when is_atom(Use)  -> verify_claims_sub(Payload, Use);
verify_claims({sub, Val}, Payload, _Opts)                    -> verify_claims_sub(Val, Payload, required);
verify_claims({sub, Val, Use}, Payload, _Opts)               -> verify_claims_sub(Val, Payload, Use);
verify_claims({aud, Use}, Payload, _Opts) when is_atom(Use)  -> verify_claims_aud(Payload, Use);
verify_claims({aud, Val}, Payload, _Opts)                    -> verify_claims_aud(Val, Payload, required);
verify_claims({aud, Val, Use}, Payload, _Opts)               -> verify_claims_aud(Val, Payload, Use);
verify_claims({jti, Fn}, Payload, _Opts)                     -> verify_claims_jti(Fn, Payload).

%% "iss" (Issuer) Claim
%%
%% The "iss" (issuer) claim identifies the principal that issued the
%% JWT.  The processing of this claim is generally application specific.
%% The "iss" value is a case-sensitive string containing a StringOrURI
%% value.  Use of this claim is OPTIONAL.
%%
%% https://tools.ietf.org/html/rfc7519#section-4.1.1

-spec verify_claims_iss(map(), use()) -> ok.
verify_claims_iss(#{<<"iss">> := _}, _Use)  -> ok;
verify_claims_iss(_Payload, required)       -> error(missing_iss);
verify_claims_iss(_Payload, _Use)           -> ok.

-spec verify_claims_iss(binary(), map(), use()) -> ok.
verify_claims_iss(Val, #{<<"iss">> := Val}, _Use) -> ok;
verify_claims_iss(Exp, #{<<"iss">> := Val}, _Use) -> error({no_match_iss, Exp, Val});
verify_claims_iss(_Exp, _Payload, required)       -> error(missing_iss);
verify_claims_iss(_Exp, _Payload, _Use)           -> ok.

%% "sub" (Subject) Claim
%%
%% The "sub" (subject) claim identifies the principal that is the
%% subject of the JWT.  The claims in a JWT are normally statements
%% about the subject.  The subject value MUST either be scoped to be
%% locally unique in the context of the issuer or be globally unique.
%% The processing of this claim is generally application specific.  The
%% "sub" value is a case-sensitive string containing a StringOrURI
%% value.  Use of this claim is OPTIONAL.
%%
%% https://tools.ietf.org/html/rfc7519#section-4.1.2

-spec verify_claims_sub(map(), use()) -> ok.
verify_claims_sub(#{<<"sub">> := _}, _Use)  -> ok;
verify_claims_sub(_Payload, required)       -> error(missing_sub);
verify_claims_sub(_Payload, _Use)           -> ok.

-spec verify_claims_sub(binary(), map(), use()) -> ok.
verify_claims_sub(Val, #{<<"sub">> := Val}, _Use) -> ok;
verify_claims_sub(Exp, #{<<"sub">> := Val}, _Use) -> error({no_match_sub, Exp, Val});
verify_claims_sub(_Exp, _Payload, required)       -> error(missing_sub);
verify_claims_sub(_Exp, _Payload, _Use)           -> ok.

%% "aud" (Audience) Claim
%%
%% The "aud" (audience) claim identifies the recipients that the JWT is
%% intended for.  Each principal intended to process the JWT MUST
%% identify itself with a value in the audience claim.  If the principal
%% processing the claim does not identify itself with a value in the
%% "aud" claim when this claim is present, then the JWT MUST be
%% rejected.  In the general case, the "aud" value is an array of case-
%% sensitive strings, each containing a StringOrURI value.  In the
%% special case when the JWT has one audience, the "aud" value MAY be a
%% single case-sensitive string containing a StringOrURI value.  The
%% interpretation of audience values is generally application specific.
%% Use of this claim is OPTIONAL.
%%
%% https://tools.ietf.org/html/rfc7519#section-4.1.3

-spec verify_claims_aud(map(), use()) -> ok.
verify_claims_aud(#{<<"aud">> := _}, _Use)  -> ok;
verify_claims_aud(_Payload, required)       -> error(missing_aud);
verify_claims_aud(_Payload, _Use)           -> ok.

-spec verify_claims_aud(binary(), map(), use()) -> ok.
verify_claims_aud(Val, #{<<"aud">> := Val}, _Use)                     -> ok;
verify_claims_aud(Exp, #{<<"aud">> := Val}, _Use) when is_binary(Val) -> error({no_match_aud, Exp, Val});
verify_claims_aud(Exp, #{<<"aud">> := L}, _Use)                       -> case lists:member(Exp, L) of true -> ok; _ -> error({no_match_aud, Exp, L}) end;
verify_claims_aud(_Exp, _Payload, required)                           -> error(missing_aud);
verify_claims_aud(_Exp, _Payload, _Use)                               -> ok.

%% "exp" (Expiration Time) Claim
%%
%% The "exp" (expiration time) claim identifies the expiration time on
%% or after which the JWT MUST NOT be accepted for processing.  The
%% processing of the "exp" claim requires that the current date/time
%% MUST be before the expiration date/time listed in the "exp" claim.
%% Implementers MAY provide for some small leeway, usually no more than
%% a few minutes, to account for clock skew.  Its value MUST be a number
%% containing a NumericDate value.  Use of this claim is OPTIONAL.
%%
%% https://tools.ietf.org/html/rfc7519#section-4.1.4

-spec verify_claims_exp(map(), verify_options(), use()) -> ok.
verify_claims_exp(#{<<"exp">> := Val}, #{leeway := N}, _Use) -> verify_exp(Val, unix_time(erlang:timestamp()) +N);
verify_claims_exp(#{<<"exp">> := Val}, _Opts, _Use)          -> verify_exp(Val);
verify_claims_exp(_Payload, _Opts, required)                 -> error(missing_exp);
verify_claims_exp(_Payload, _Opts, _Use)                     -> ok.

%% "nbf" (Not Before) Claim
%%
%% The "nbf" (not before) claim identifies the time before which the JWT
%% MUST NOT be accepted for processing.  The processing of the "nbf"
%% claim requires that the current date/time MUST be after or equal to
%% the not-before date/time listed in the "nbf" claim.  Implementers MAY
%% provide for some small leeway, usually no more than a few minutes, to
%% account for clock skew.  Its value MUST be a number containing a
%% NumericDate value.  Use of this claim is OPTIONAL.
%%
%% https://tools.ietf.org/html/rfc7519#section-4.1.5

-spec verify_claims_nbf(map(), verify_options(), use()) -> ok.
verify_claims_nbf(#{<<"nbf">> := Val}, #{leeway := N}, _Use) -> verify_nbf(Val, unix_time(erlang:timestamp()) -N);
verify_claims_nbf(#{<<"nbf">> := Val}, _Opts, _Use)          -> verify_nbf(Val);
verify_claims_nbf(_Payload, _Opts, required)                 -> error(missing_nbf);
verify_claims_nbf(_Payload, _Opts, _Use)                     -> ok.

%% "iat" (Issued At) Claim
%%
%% The "iat" (issued at) claim identifies the time at which the JWT was
%% issued.  This claim can be used to determine the age of the JWT.  Its
%% value MUST be a number containing a NumericDate value.  Use of this
%% claim is OPTIONAL.
%%
%% https://tools.ietf.org/html/rfc7519#section-4.1.6

-spec verify_claims_iat(map(), verify_options(), use()) -> ok.
verify_claims_iat(#{<<"iat">> := Val}, #{leeway := N}, _Use) -> verify_iat(Val, unix_time(erlang:timestamp()) -N);
verify_claims_iat(#{<<"iat">> := Val}, _Opts, _Use)          -> verify_iat(Val);
verify_claims_iat(_Payload, _Opts, required)                 -> error(missing_iat);
verify_claims_iat(_Payload, _Opts, _Use)                     -> ok.

%% "jti" (JWT ID) Claim
%%
%% The "jti" (JWT ID) claim provides a unique identifier for the JWT.
%% The identifier value MUST be assigned in a manner that ensures that
%% there is a negligible probability that the same value will be
%% accidentally assigned to a different data object; if the application
%% uses multiple issuers, collisions MUST be prevented among values
%% produced by different issuers as well.  The "jti" claim can be used
%% to prevent the JWT from being replayed.  The "jti" value is a case-
%% sensitive string.  Use of this claim is OPTIONAL.
%%
%% https://tools.ietf.org/html/rfc7519#section-4.1.7

-spec verify_claims_jti(jti_check(), map()) -> ok.
verify_claims_jti(Fn, Payload) ->
	try Fn(Payload) of
		ok              -> ok;
		{error, Reason} -> error({bad_jty, Reason});
		Result          -> error({bad_check_jti, {bad_result, Result}})
	catch _:Reason    -> error({bad_check_jti, Reason})
	end.
