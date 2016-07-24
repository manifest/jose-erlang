# JSON Object Signing and Encryption (JOSE) library

[![Build Status][travis-img]][travis]

Simple and fast JOSE library for Erlang



### Key Generation

**Supported algorithms:**
**HS256**, **HS384**, **HS512**
**ES256**, **ES384**, **ES512**

The maximum effective length is chosen for `HS` keys according to [RFC 2104 - HMAC: Keyed-Hashing for Message Authentication - 3. Keys][rfc2104-keys]:

	The key for HMAC can be of any length (keys longer than B bytes are
	first hashed using H).  However, less than L bytes is strongly
	discouraged as it would decrease the security strength of the
	function.  Keys longer than L bytes are acceptable but the extra
	length would not significantly increase the function strength.

	... H to be a cryptographic hash function where data is hashed by iterating a basic compression
	function on blocks of data. We denote by B the byte-length of such blocks ...
	and by L the byte-length of hash outputs.

```erlang
%% Generating a symmetric key
Key = jose_jwa:generate_key(<<"HS256">>).

%% Generating a pair of asymmetric keys
{Pub, Priv} = jose_jwa:generate_key(<<"ES256">>).
```



### JSON Web Token (JWT)

From [RFC 7519 - JSON Web Token (JWT) - 1. Introduction][rfc7519-introduction]:

	JWTs are always represented using the JWS Compact Serialization or the JWE Compact Serialization.

#### JSON Web Signature (JWS) Compact Serialization

**Supported algorithms:**
**HS256**, **HS384**, **HS512**
**ES256**, **ES384**, **ES512**

```erlang
%% Generating a pair of keys
Alg = <<"ES256">>,
{Pub, Priv} = jose_jwa:generate_key(Alg).

%% Encoding a token
Token =
  jose_jws_compact:encode(
    #{iss => <<"example.org">>,
      aud => <<"app.example.org">>,
      sub => <<"joe">>,
      exp => 4607280000},
    Alg,
    Priv).

%% Decoding the token (by default, claim verification will be performed)
jose_jws_compact:decode(Token, Alg, Pub).
%% #{<<"aud">> => <<"app.example.org">>,
%%   <<"exp">> => 4607280000,
%%   <<"iss">> => <<"example.org">>,
%%   <<"sub">> => <<"joe">>}

%% It's possible to just verify token's signature and don't decode payload
jose_jws_compact:decode(Token, Alg, Pub, #{parse_payload => base64}).
%% <<"eyJhdWQiOiJhcHAuZXhhbXBsZS5vcmciLCJleHAiOjQ2MDcyODAwMDAsImlzcyI6ImV4YW1wbGUub3JnIiwic3ViIjoiam9lIn0">>

%% To decode token's payload and verify just chosen claims (token's expiration time claim `exp` in this example)
jose_jws_compact:decode(Token, Alg, Pub, #{parse_payload => map, verify => [exp]}).
%% #{<<"aud">> => <<"app.example.org">>,
%%   <<"exp">> => 4607280000,
%%   <<"iss">> => <<"example.org">>,
%%   <<"sub">> => <<"joe">>}

%% There is more effective and flexible way to decode a token by using a key selection function.
%% (selecting a key by token's key id parameter `kid` and token's issuer claim `iss`).
%% The function must return a tuple `{ok, {Alg, Key, NewOpts}}` on success
%% or a tuple `{error, Reason}` on failure.
jose_jws_compact:decode_fn(
  fun([ #{<<"kid">> := Kid}, #{<<"iss">> := Iss} | _ ], _Opts) ->
    lookup_key(Iss, Kid)
    %% {Alg, Key, NewOpts}
  end,
  Token).

%% The first argument of the key selection function above is a result of parsing the token.
%% It's a list of four elements: header, payload, signature, input (header + payload base64 encoded).
%% You can use following function anytime you want just parse a token (without any verifications).
jose_jws_compact:parse(Token).
%% [<<"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9">>,
%%  <<"eyJhdWQiOiJhcHAuZXhhbXBsZS5vcmciLCJleHAiOjQ2MDcyODAwMDAsImlzcyI6ImV4YW1wbGUub3JnIiwic3ViIjoiam9lIn0">>,
%%  <<"KEr9hLuo0iRnx073C5z3eB-I9TptZbqDkPUyDI_590j0GY3Jbfos1JcAkSznsiLF69vyorcIitdBIsAwPkCgZw">>,
%%  <<"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHAuZXhhbXBsZS5vcmciLCJleHAiOjQ2MDcyODAwMDAsImlzcyI"...>>]

%% By default, the parsing function just split token's elements. To change this behaviour use options.
%% With `#{parse_payload => map}`, the parsing function uses base64 decoder against payload
%% and then performs an attempt to use json decoder. If json decoder fails, binary will be returned.
jose_jws_compact:parse(Token, #{parse_header => map, parse_payload => map, parse_signature => binary}).
%% [#{<<"alg">> => <<"ES256">>,<<"typ">> => <<"JWT">>},
%%  #{<<"aud">> => <<"app.example.org">>,
%%    <<"exp">> => 4607280000,
%%    <<"iss">> => <<"example.org">>,
%%    <<"sub">> => <<"joe">>},
%%  <<40,74,253,132,187,168,210,36,103,199,78,247,11,156,247,
%%    120,31,136,245,58,109,101,186,131,144,245,...>>,
%%  <<"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcHAuZXhhbXBsZS5vcmciLCJleHAiOjQ2MDcyODAwMDAsImlzcyI"...>>]
```

####  Verification of reserved claim names

##### Expiration Time Claim

From [RFC 7519 - JSON Web Token (JWT) - 4.1.4. "exp" (Expiration Time) Claim][rfc7519-claims-exp]:

	The "exp" (expiration time) claim identifies the expiration time on
	or after which the JWT MUST NOT be accepted for processing.  The
	processing of the "exp" claim requires that the current date/time
	MUST be before the expiration date/time listed in the "exp" claim.
	Implementers MAY provide for some small leeway, usually no more than
	a few minutes, to account for clock skew.  Its value MUST be a number
	containing a NumericDate value.  Use of this claim is OPTIONAL.

```erlang
%% To verify token's expiration time claim if presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [exp]}).
%% To verify token's expiration time claim and fail when it isn't presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{exp, required}]}).
```

##### Not Before Claim

From [RFC 7519 - JSON Web Token (JWT) - 4.1.5. "nbf" (Not Before) Claim][rfc7519-claims-nbf]:

	The "nbf" (not before) claim identifies the time before which the JWT
	MUST NOT be accepted for processing.  The processing of the "nbf"
	claim requires that the current date/time MUST be after or equal to
	the not-before date/time listed in the "nbf" claim.  Implementers MAY
	provide for some small leeway, usually no more than a few minutes, to
	account for clock skew.  Its value MUST be a number containing a
	NumericDate value.  Use of this claim is OPTIONAL.

```erlang
%% To verify token's not before claim if presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [nbf]}).
%% To verify token's not before claim and fail when it isn't presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{nbf, required}]}).
```

##### Issued At Claim

From [RFC 7519 - JSON Web Token (JWT) - 4.1.6. "iat" (Issued At) Claim][rfc7519-claims-iat]:

	The "iat" (issued at) claim identifies the time at which the JWT was
	issued.  This claim can be used to determine the age of the JWT.  Its
	value MUST be a number containing a NumericDate value.  Use of this
	claim is OPTIONAL.

```erlang
%% To verify token's issued at claim if presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [iat]}).
%% To verify token's issued at claim and fail when it isn't presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{iat, required}]}).
```

##### Issuer Claim

From [RFC 7519 - JSON Web Token (JWT) - 4.1.1. "iss" (Issuer) Claim][rfc7519-claims-iss]:

	The "iss" (issuer) claim identifies the principal that issued the
	JWT.  The processing of this claim is generally application specific.
	The "iss" value is a case-sensitive string containing a StringOrURI
	value.  Use of this claim is OPTIONAL.

```erlang
%% To verify a presence of token's issuer claim and fail if it's not
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{iss, required}]}).
%% To verify token's issuer claim and fail when it isn't presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{iss, <<"example.org">>}]}).
%% To verify token's issuer claim but don't fail if it isn't presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{iss, <<"example.org">>, optional}]}).
```

##### Subject Claim

From [RFC 7519 - JSON Web Token (JWT) - 4.1.2. "sub" (Subject) Claim][rfc7519-claims-sub]:

	The "sub" (subject) claim identifies the principal that is the
	subject of the JWT.  The claims in a JWT are normally statements
	about the subject.  The subject value MUST either be scoped to be
	locally unique in the context of the issuer or be globally unique.
	The processing of this claim is generally application specific.  The
	"sub" value is a case-sensitive string containing a StringOrURI
	value.  Use of this claim is OPTIONAL.

```erlang
%% To verify a presence of token's subject claim and fail if it's not
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{sub, required}]}).
%% To verify token's subject claim and fail when it isn't presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{sub, <<"joe">>}]}).
%% To verify token's subject claim but don't fail if it isn't presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{sub, <<"joe">>, optional}]}).
```

##### Audience Claim

From [RFC 7519 - JSON Web Token (JWT) - 4.1.3. "aud" (Audience) Claim][rfc7519-claims-aud]:

	The "aud" (audience) claim identifies the recipients that the JWT is
	intended for.  Each principal intended to process the JWT MUST
	identify itself with a value in the audience claim.  If the principal
	processing the claim does not identify itself with a value in the
	"aud" claim when this claim is present, then the JWT MUST be
	rejected.  In the general case, the "aud" value is an array of case-
	sensitive strings, each containing a StringOrURI value.  In the
	special case when the JWT has one audience, the "aud" value MAY be a
	single case-sensitive string containing a StringOrURI value.  The
	interpretation of audience values is generally application specific.
	Use of this claim is OPTIONAL.

```erlang
%% To verify a presence of token's audience claim and fail if it's not
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{aud, required}]}).
%% To verify token's audience claim and fail when it isn't presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{aud, <<"app.example.org">>}]}).
%% To verify token's audience claim but don't fail if it isn't presented
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, verify => [{aud, <<"app.example.org">>, optional}]}).
```

##### JWT ID Claim

From [RFC 7519 - JSON Web Token (JWT) - 4.1.7. "exp" (Expiration Time) Claim][rfc7519-claims-exp]:

	The "jti" (JWT ID) claim provides a unique identifier for the JWT.
	The identifier value MUST be assigned in a manner that ensures that
	there is a negligible probability that the same value will be
	accidentally assigned to a different data object; if the application
	uses multiple issuers, collisions MUST be prevented among values
	produced by different issuers as well.  The "jti" claim can be used
	to prevent the JWT from being replayed.  The "jti" value is a case-
	sensitive string.  Use of this claim is OPTIONAL.

```erlang
%% To verify JWT ID claim its verification function should be provided.
%% The function must return an atom `ok` on success or a tuple `{error, Reason}` on failure.
CheckJti =
  fun(#{<<"jti">> := Jti} = _Payload) ->
  	verify_jti(Jti)
  	%% ok | {error, Rason}
  end,
jose_jws_compact:decode(Token, Alg, Key, #{parse_payload => map, [{jti, CheckJti}]}).
```



### PEM Key Format

**Supported algorithms:**
**ES256**, **ES384**, **ES512**

```erlang
%% Generting a key
{_, Priv} = jose_jwa:generate_key(<<"ES256">>).

%% Serializing the private key to the PEM file
Pem = jose_pem:key(<<"ES256">>, Priv),
file:write_file("key.pem", Pem).

%% Reading the key back
{ok, Pem} = file:read_file("key.pem"),
{<<"ES256">>, Key} = jose_pem:parse_key(Pem).
```



### License

The source code is provided under the terms of [the MIT license][license].

[license]:http://www.opensource.org/licenses/MIT
[travis]:https://travis-ci.org/manifest/jose-erlang?branch=master
[travis-img]:https://secure.travis-ci.org/manifest/jose-erlang.png
[rfc7519-introduction]:https://tools.ietf.org/html/rfc7519#section-1
[rfc7519-claims-iss]:https://tools.ietf.org/html/rfc7519#section-4.1.1
[rfc7519-claims-sub]:https://tools.ietf.org/html/rfc7519#section-4.1.2
[rfc7519-claims-aud]:https://tools.ietf.org/html/rfc7519#section-4.1.3
[rfc7519-claims-exp]:https://tools.ietf.org/html/rfc7519#section-4.1.4
[rfc7519-claims-nbf]:https://tools.ietf.org/html/rfc7519#section-4.1.5
[rfc7519-claims-iat]:https://tools.ietf.org/html/rfc7519#section-4.1.6
[rfc7519-claims-jti]:https://tools.ietf.org/html/rfc7519#section-4.1.7
[rfc2104-keys]:https://tools.ietf.org/html/rfc2104#section-3
