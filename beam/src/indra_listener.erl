%% @doc MQTT TCP/TLS listener (BEAM edge side).
%%
%% A supervision-friendly {@code gen_server} that owns the client-facing
%% listen socket (default ports: 1883 plaintext, 8883 TLS) and hands each
%% accepted connection to an {@link indra_conn} process. The blocking
%% accept loop runs in a linked acceptor process so the server itself
%% stays responsive to {@code stop/1} and supervisor signals.
%%
%% TLS termination uses OTP {@code ssl}: with
%% {@code {transport, ssl}, {certfile, Cert}, {keyfile, Key}} the listener
%% accepts via {@code ssl:transport_accept/1} plus a bounded
%% {@code ssl:handshake/2}, then transfers the TLS socket to a conn
%% started with the matching {@code {transport, ssl}} option.
%%
%% Pre-shared-key (PSK) TLS for constrained devices (B5-05):
%% <ul>
%% <li>Offered PSK suites (fixed set, stated for the operator):
%% {@code PSK-AES128-GCM-SHA256} and {@code PSK-AES256-GCM-SHA384}
%% (pure-PSK, RFC 4279: no certificate on either side). Reasoning: AEAD
%% (GCM) only, so no CBC padding-oracle class and no RC4/3DES; SHA-256 /
%% SHA-384 PRF; TLS 1.2, because the OTP PSK hooks
%% ({@code psk_identity}, {@code user_lookup_fun}) are pre-TLS-1.3-only.
%% Deliberately not offered: RSA/DHE/ECDHE-PSK (need certificates or DH
%% and buy nothing for constrained devices), CCM variants (narrower
%% interop, GCM suffices) and every CBC/SHA/RC4 suite (weak). The two
%% suites are appended after the OTP default suites, so a certificate
%% client negotiates exactly as before.</li>
%% <li>Identities and keys come from {@code {psk_keys, [{Id, Key}]}}:
%% read once at listener start; changing the set requires a listener
%% restart (stop/start or supervisor restart). No file watching, no hot
%% reload. In-flight connections are unaffected by a restart.</li>
%% <li>The presented identity is captured in {@link psk_lookup/3} and
%% handed to the new conn as {@code {psk_identity, Id}}; the conn maps
%% it onto the bind username (see {@link indra_conn}), so the kernel
%% authenticates and authorizes it like any other CONNECT identity.
%% Unknown identity or wrong key fails the handshake (fail closed, no
%% bind ever sent).</li>
%% <li>Bounds: the PSK table holds at most 1024 entries (operator config;
%% larger fleets belong in a directory, not a static list); each
%% identity is 1..128 bytes and each key 16..64 bytes (at least 128
%% bits of entropy, at most 512 bits to bound memory). Pending
%% handshakes are bounded by the single sequential acceptor (one at a
%% time per listener) plus the 5 s handshake timeout. The capture table
%% holds at most one entry (only during an in-flight PSK handshake) and
%% is drained after every handshake, success or failure. A PSK-enabled
%% listener sets {@code reuse_sessions=false}: every PSK handshake is
%% full, so there is no session cache to bound and a removed identity
%% stops working on the next connect. Certificate-only listeners are
%% untouched.</li>
%% </ul>
-module(indra_listener).

-behaviour(gen_server).

-export([start_link/0,
         start_link/1,
         stop/1,
         get_port/1,
         listen_sock_opts/0]).

%% gen_server callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% PSK credential lookup for OTP ssl (called by the TLS connection
%% process, not the acceptor; see build_ssl_opts/2).
-export([psk_lookup/3]).

-define(DEFAULT_PORT, 1883).
-define(DEFAULT_TLS_PORT, 8883).
-define(HANDSHAKE_TIMEOUT_MS, 5000).
%% PSK bounds (see the module doc for the reason behind each one).
-define(MAX_PSK_ENTRIES, 1024).
-define(MIN_PSK_KEY_BYTES, 16).
-define(MAX_PSK_KEY_BYTES, 64).
-define(MAX_PSK_IDENTITY_BYTES, 128).

-type listen_opt() :: {port, inet:port_number()}
                    | {transport, tcp | ssl}
                    | {certfile, file:filename()}
                    | {keyfile, file:filename()}
                    | {psk_keys, [{binary(), binary()}]}
                    | {psk_hint, binary() | string()}
                    | {conn, [tuple()]}.

%%====================================================================
%% API
%%====================================================================

%% @doc Start a plaintext listener on the default MQTT port (1883).
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

%% @doc Start a listener. Options:
%% <ul>
%% <li>{@code {port, Port}} — default 1883 for {@code tcp}, 8883 for
%% {@code ssl}; use 0 for an ephemeral port (see {@link get_port/1}).</li>
%% <li>{@code {transport, tcp | ssl}} — default {@code tcp}.</li>
%% <li>{@code {certfile, Path}, {keyfile, Path}} — required for
%% {@code ssl} unless {@code psk_keys} is given (a pure-PSK listener
%% needs no certificate); PEM-encoded certificate and private key.</li>
%% <li>{@code {psk_keys, [{Id, Key}]}} — enables the TLS PSK path:
%% {@code Id} (1..128 bytes) is the client identity, {@code Key}
%% (16..64 bytes) the pre-shared secret. At most 1024 entries. Read
%% once at start; restart the listener to reload. Rejected with
%% {@code tcp} transport (PSK is a TLS cipher suite).</li>
%% <li>{@code {psk_hint, Hint}} — server identity hint sent to PSK
%% clients (optional, defaults to none).</li>
%% <li>{@code {conn, ConnOpts}} — extra options forwarded to every
%% {@code indra_conn} (must include {@code {broker, pid() | [pid()]}};
%% a shard list pins each connection by {@code conn_id rem K}; pass
%% {@code {transport, ssl}} through for TLS sockets).</li>
%% </ul>
-spec start_link([listen_opt()]) -> {ok, pid()} | {error, term()}.
start_link(Opts) when is_list(Opts) ->
    gen_server:start_link(?MODULE, Opts, []).

%% @doc Stop the listener (closes the listen socket).
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% @doc Return the actual bound port (useful with {@code {port, 0}}).
-spec get_port(pid()) -> {ok, inet:port_number()} | {error, term()}.
get_port(Pid) ->
    gen_server:call(Pid, get_port).

%%====================================================================
%% gen_server callbacks
%%====================================================================

%% @doc Socket options for the client-facing listen socket.
%% `nodelay' avoids delayed-ACK interaction on small MQTT frames;
%% 64 KiB buffers bound per-connection memory (1M-session scale)
%% while giving the bursty accept path headroom.
-spec listen_sock_opts() -> [term()].
listen_sock_opts() ->
    [binary, {packet, raw}, {active, false}, {reuseaddr, true},
     {nodelay, true}, {recbuf, 65536}, {sndbuf, 65536}].

init(Opts) ->
    process_flag(trap_exit, true),
    Transport = proplists:get_value(transport, Opts, tcp),
    DefaultPort = case Transport of ssl -> ?DEFAULT_TLS_PORT; _ -> ?DEFAULT_PORT end,
    Port = proplists:get_value(port, Opts, DefaultPort),
    ConnOpts = proplists:get_value(conn, Opts, []),
    SockOpts = listen_sock_opts(),
    ListenResult = case Transport of
        ssl ->
            %% TLS needs the ssl application (and its tracker sup) even
            %% when embedded without a full release boot.
            {ok, _} = application:ensure_all_started(ssl),
            case build_ssl_opts(Opts, SockOpts) of
                {ok, SslOpts, PskTab} ->
                    case ssl:listen(Port, SslOpts) of
                        {ok, LSocket} ->
                            {ok, LSocket, PskTab};
                        {error, _} = Err ->
                            catch ets:delete(PskTab),
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        _ ->
            case proplists:get_value(psk_keys, Opts, undefined) of
                undefined ->
                    case gen_tcp:listen(Port, SockOpts) of
                        {ok, LSocket} -> {ok, LSocket, undefined};
                        {error, _} = Err -> Err
                    end;
                _ ->
                    %% PSK is a TLS cipher suite: a plaintext listener
                    %% cannot offer it. Fail start, never silently drop.
                    {error, psk_requires_tls}
            end
    end,
    case ListenResult of
        {ok, LSock, PskTable} ->
            case bound_port(Transport, LSock) of
                {ok, Actual} ->
                    Acceptor = spawn_link(
                        fun() -> accept_loop(Transport, LSock, ConnOpts, PskTable) end),
                    {ok, #{transport => Transport, lsock => LSock, port => Actual,
                           acceptor => Acceptor, conn_opts => ConnOpts,
                           psk_table => PskTable}};
                {error, Reason} ->
                    catch ets:delete(PskTable),
                    catch close_listen(Transport, LSock),
                    {stop, Reason}
            end;
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(get_port, _From, #{port := Port} = State) ->
    {reply, {ok, Port}, State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason}, #{acceptor := Pid} = State) ->
    case Reason of
        normal ->
            %% Listen socket was closed (usually our own shutdown).
            {noreply, State};
        _ ->
            %% Acceptor crashed: re-arm unless the socket is gone.
            #{transport := Transport, lsock := LSock, conn_opts := ConnOpts} = State,
            case listen_alive(Transport, LSock) of
                true ->
                    PskTable = maps:get(psk_table, State, undefined),
                    Acceptor = spawn_link(
                        fun() -> accept_loop(Transport, LSock, ConnOpts, PskTable) end),
                    {noreply, State#{acceptor => Acceptor}};
                false ->
                    {stop, {acceptor_died, Reason}, State}
            end
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{transport := Transport, lsock := LSock} = State) ->
    catch ets:delete(maps:get(psk_table, State, undefined)),
    catch close_listen(Transport, LSock),
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% TLS PSK option builder + credential lookup
%%====================================================================

%% @private Build the `ssl:listen/2' options. Without `psk_keys' the
%% result is exactly the historic `{certfile, keyfile}' form, so
%% certificate behaviour is unchanged. With `psk_keys' the two stated
%% PSK suites are appended after the OTP defaults (certificate clients
%% keep their preference order) and the credential lookup plus
%% `reuse_sessions=false' are added (every PSK handshake is full, so
%% there is no session cache to bound). Returns the options and the
%% capture table (`undefined' when PSK is off).
-spec build_ssl_opts([listen_opt()], [term()]) ->
    {ok, [term()], ets:tid() | undefined} | {error, term()}.
build_ssl_opts(Opts, SockOpts) ->
    Cert = proplists:get_value(certfile, Opts, undefined),
    Key = proplists:get_value(keyfile, Opts, undefined),
    PskKeys = proplists:get_value(psk_keys, Opts, undefined),
    case PskKeys of
        undefined ->
            case {Cert, Key} of
                {undefined, _} -> {error, {missing_option, certfile}};
                {_, undefined} -> {error, {missing_option, keyfile}};
                {_, _} -> {ok, [{certfile, Cert}, {keyfile, Key} | SockOpts], undefined}
            end;
        _ ->
            case validate_psk_keys(PskKeys) of
                {ok, PskMap} ->
                    case psk_cipher_suites() of
                        {ok, PskSuites} ->
                            %% Public so the TLS connection process (which
                            %% runs the lookup fun, not the listener) can
                            %% stash the identity; it holds identities
                            %% only, never keys, and at most one entry.
                            Table = ets:new(psk_handshake, [set, public]),
                            Lookup = {fun ?MODULE:psk_lookup/3, {PskMap, Table}},
                            Ciphers = ssl:cipher_suites(default, 'tlsv1.2')
                                ++ ssl:cipher_suites(default, 'tlsv1.3')
                                ++ PskSuites,
                            Base = [{ciphers, Ciphers},
                                    {user_lookup_fun, Lookup},
                                    {reuse_sessions, false}],
                            WithHint = case proplists:get_value(psk_hint, Opts, undefined) of
                                undefined -> Base;
                                Hint -> [{psk_identity, Hint} | Base]
                            end,
                            WithCert = case {Cert, Key} of
                                {undefined, undefined} -> WithHint;
                                {_, undefined} -> ets:delete(Table), {error, {missing_option, keyfile}};
                                {undefined, _} -> ets:delete(Table), {error, {missing_option, certfile}};
                                {_, _} -> [{certfile, Cert}, {keyfile, Key} | WithHint]
                            end,
                            case WithCert of
                                {error, _} = Err -> Err;
                                _ -> {ok, WithCert ++ SockOpts, Table}
                            end;
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end
    end.

%% @private The two offered PSK suites, resolved on this host's OTP.
%% A suite OTP does not recognise fails the listener start (fail
%% closed): silently offering no PSK suite would strand devices.
-spec psk_cipher_suites() -> {ok, [term()]} | {error, term()}.
psk_cipher_suites() ->
    Names = ["PSK-AES128-GCM-SHA256", "PSK-AES256-GCM-SHA384"],
    try
        Suites = [case ssl:str_to_suite(N) of
                      Suite when is_map(Suite) -> Suite;
                      Other -> throw({unknown_psk_cipher, N, Other})
                  end || N <- Names],
            {ok, Suites}
    catch
        throw:Reason -> {error, Reason}
    end.

%% @private Validate the static PSK table into a lookup map. Bounds
%% (see the module doc): 1..1024 entries, identity 1..128 bytes, key
%% 16..64 bytes, no duplicate identities. Anything else fails the
%% listener start: a misconfigured credential set must never open.
-spec validate_psk_keys(term()) -> {ok, map()} | {error, term()}.
validate_psk_keys(Keys) when is_list(Keys), length(Keys) >= 1,
                             length(Keys) =< ?MAX_PSK_ENTRIES ->
    try
        Map = lists:foldl(
            fun({Id, Secret}, Acc) ->
                ok = check_psk_entry(Id, Secret),
                case maps:is_key(Id, Acc) of
                    true -> throw({duplicate_psk_identity, Id});
                    false -> Acc#{Id => Secret}
                end;
               (_, _) ->
                throw(invalid_psk_keys)
            end, #{}, Keys),
        {ok, Map}
    catch
        throw:Reason -> {error, Reason}
    end;
validate_psk_keys(_) ->
    {error, invalid_psk_keys}.

check_psk_entry(Id, Secret)
  when is_binary(Id), byte_size(Id) >= 1,
       byte_size(Id) =< ?MAX_PSK_IDENTITY_BYTES,
       is_binary(Secret), byte_size(Secret) >= ?MIN_PSK_KEY_BYTES,
       byte_size(Secret) =< ?MAX_PSK_KEY_BYTES ->
    ok;
check_psk_entry(_, _) ->
    throw(invalid_psk_keys).

%% @doc OTP ssl credential lookup for the PSK path (fail closed).
%%
%% Runs in the TLS connection process during the handshake, not in the
%% acceptor: the presented identity is stashed in the capture table for
%% the acceptor to collect after the handshake (the table holds at most
%% one entry because the acceptor performs one handshake at a time).
%% Unknown identity returns `error', which fails the handshake with no
%% bind ever sent. Exported for the `{fun, state}' hook only.
-spec psk_lookup(psk, binary(), {map(), ets:tid()}) ->
    {ok, binary()} | {error, term()}.
psk_lookup(psk, Identity, {PskMap, Table}) when is_binary(Identity) ->
    case maps:get(Identity, PskMap, undefined) of
        undefined ->
            {error, unknown_psk_identity};
        Secret ->
            ets:insert(Table, {psk_identity, Identity}),
            {ok, Secret}
    end;
psk_lookup(_, _, _) ->
    {error, unknown_psk_identity}.

%% @private Collect (and clear) the identity captured during the last
%% handshake. `undefined' when PSK is off or the peer negotiated a
%% certificate suite (no lookup ran). Always called after every
%% handshake, success or failure, so a stale identity can never leak
%% into the next connection.
-spec take_psk_identity(ets:tid() | undefined) -> binary() | undefined.
take_psk_identity(undefined) ->
    undefined;
take_psk_identity(Table) ->
    case ets:take(Table, psk_identity) of
        [{psk_identity, Identity}] -> Identity;
        [] -> undefined
    end.

%%====================================================================
%% Transport helpers
%%====================================================================

bound_port(tcp, LSock) -> inet:port(LSock);
bound_port(ssl, LSock) ->
    case ssl:sockname(LSock) of
        {ok, {_Addr, Port}} -> {ok, Port};
        {error, _} = Err -> Err
    end.

listen_alive(tcp, LSock) ->
    case inet:getstat(LSock) of
        {ok, _} -> true;
        _ -> false
    end;
listen_alive(ssl, LSock) ->
    case ssl:getstat(LSock) of
        {ok, _} -> true;
        _ -> false
    end.

close_listen(tcp, LSock) -> gen_tcp:close(LSock);
close_listen(ssl, LSock) -> ssl:close(LSock).

%%====================================================================
%% Acceptor loop (linked helper process)
%%====================================================================

%% @private Block in accept; each success (plus TLS handshake) spawns a
%% conn and transfers socket ownership before arming it. Ends when the
%% listen socket closes. ConnOpts (including `{broker, Pid | [Pid]}')
%% is handed to each connection untouched, so a shard list from the
%% supervisor pins every conn by `conn_id rem K' inside {@link
%% indra_conn}. A PSK handshake additionally pins `{psk_identity, Id}'
%% onto that connection's options so the conn can map it onto the bind
%% username; certificate and plaintext conns carry none.
accept_loop(Transport, LSock, ConnOpts, PskTable) ->
    case accept_one(Transport, LSock, PskTable) of
        {ok, Sock, PskId} ->
            ConnOpts1 = case PskId of
                undefined -> ConnOpts;
                _ -> [{psk_identity, PskId} | ConnOpts]
            end,
            case indra_conn:start_link(Sock, ConnOpts1) of
                {ok, Pid} ->
                    case controlling_process(Transport, Sock, Pid) of
                        ok ->
                            gen_statem:cast(Pid, takeover);
                        {error, _} ->
                            catch close_socket(Transport, Sock),
                            catch indra_conn:stop(Pid)
                    end;
                {error, _} ->
                    catch close_socket(Transport, Sock)
            end,
            accept_loop(Transport, LSock, ConnOpts, PskTable);
        {error, closed} ->
            exit(normal);
        {error, _Reason} ->
            %% Transient accept failure: back off briefly, then retry.
            timer:sleep(100),
            accept_loop(Transport, LSock, ConnOpts, PskTable)
    end.

accept_one(tcp, LSock, _PskTable) ->
    case gen_tcp:accept(LSock) of
        {ok, Sock} -> {ok, Sock, undefined};
        {error, _} = Err -> Err
    end;
accept_one(ssl, LSock, PskTable) ->
    case ssl:transport_accept(LSock) of
        {ok, Sock} ->
            Res = ssl:handshake(Sock, ?HANDSHAKE_TIMEOUT_MS),
            PskId = take_psk_identity(PskTable),
            case Res of
                {ok, TLSSock} -> {ok, TLSSock, PskId};
                {error, _} = Err ->
                    catch ssl:close(Sock),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

controlling_process(tcp, Sock, Pid) -> gen_tcp:controlling_process(Sock, Pid);
controlling_process(ssl, Sock, Pid) -> ssl:controlling_process(Sock, Pid).

close_socket(tcp, Sock) -> gen_tcp:close(Sock);
close_socket(ssl, Sock) -> ssl:close(Sock).
