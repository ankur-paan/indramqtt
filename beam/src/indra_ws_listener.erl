%% @doc MQTT-over-WebSocket plaintext/TLS listener (BEAM edge side).
%%
%% A supervision-friendly {@code gen_server} owning the WS listen socket
%% (default ports 8083 plaintext, 8084 TLS/`wss', default path `/mqtt')
%% beside the TCP/TLS {@link indra_listener}. Each accepted socket first
%% completes the RFC 6455 upgrade in {@link indra_ws} (HTTP request,
%% `mqtt' subprotocol negotiation); only then is the socket handed to an
%% {@link indra_conn} started with {@code {transport, ws}} (plaintext)
%% or {@code {transport, wss}} (TLS). On a `wss' listener the TLS
%% handshake runs first on the encrypted channel and the WS upgrade
%% runs inside it. From the handshake on, every binary message payload
%% is raw MQTT taking exactly the TCP bind path (same CONNECT parsing,
%% same bind metadata, same auth, limits and keepalive), so the kernel
%% cannot tell WS clients apart from TCP clients except by listener
%% label.
%%
%% TLS terminates in the maintained OTP `ssl' application (never
%% hand-rolled cryptography): the offered versions are TLS 1.2 and
%% TLS 1.3 (the OTP defaults, which exclude TLS 1.0/1.1) with the OTP
%% default cipher suite posture, the same posture as the TCP/TLS
%% listener. No client-certificate authentication is requested, matching
%% TCP. Certificate material is read once at startup; there is no
%% in-place reload (the TCP/TLS listener has none either), so rotating
%% the certificate requires a listener restart.
%%
%% Bounds (all finite): the handshake deadline, the per-frame payload
%% cap and the concurrent-connection cap each default in
%% {@link indra_ws} with the reason written next to it.
-module(indra_ws_listener).

-behaviour(gen_server).

-export([start_link/0,
         start_link/1,
         stop/1,
         get_port/1]).

%% gen_server callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% @private Admission handshake (exported for spawn only).
-export([wait_go/6, handle_client/7]).

-define(TLS_HANDSHAKE_TIMEOUT_MS, 5000).

-type ws_listen_opt() :: {port, inet:port_number()}
                       | {ip, inet:ip_address()}
                       | {transport, tcp | ssl}
                       | {certfile, file:filename()}
                       | {keyfile, file:filename()}
                       | {path, string() | binary()}
                       | {handshake_timeout_ms, pos_integer()}
                       | {max_frame_bytes, pos_integer()}
                       | {max_connections, pos_integer()}
                       | {conn, [tuple()]}.

%%====================================================================
%% API
%%====================================================================

%% @doc Start a WS listener on the default port (8083) and path (/mqtt).
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link([]).

%% @doc Start a WS listener. Options:
%% <ul>
%% <li>{@code {port, Port}} — default 8083 for {@code tcp}, 8084 for
%% {@code ssl}; use 0 for an ephemeral port (see {@link get_port/1}).</li>
%% <li>{@code {transport, tcp | ssl}} — default {@code tcp}; {@code ssl}
%% serves `wss' (TLS handshake first, then the WS upgrade inside it).</li>
%% <li>{@code {certfile, Path}, {keyfile, Path}} — required for
%% {@code ssl}; PEM-encoded certificate and private key, same shape and
%% validation as the TCP/TLS listener. Missing or unreadable material
%% is a startup error, never a silent plaintext fallback.</li>
%% <li>{@code {path, Path}} — WS endpoint path, default `/mqtt'.</li>
%% <li>{@code {handshake_timeout_ms, Ms}} — HTTP upgrade deadline,
%% default 5000 (same bound as the TLS handshake).</li>
%% <li>{@code {max_frame_bytes, N}} — per-frame and per-message payload
%% cap, default 1048576 (1 MiB); forwarded to every
%% {@code indra_conn} as {@code {ws_max_frame_bytes, N}}.</li>
%% <li>{@code {max_connections, N}} — concurrent-connection cap,
%% default 10000; further accepts are failed closed until a slot
%% frees.</li>
%% <li>{@code {conn, ConnOpts}} — extra options forwarded to every
%% {@code indra_conn} (must include {@code {broker, pid() | [pid()]}}).</li>
%% </ul>
-spec start_link([ws_listen_opt()]) -> {ok, pid()} | {error, term()}.
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

init(Opts) ->
    process_flag(trap_exit, true),
    %% The accept hash runs in `crypto' even when embedded without a
    %% full release boot; `ssl' is needed for the `wss' transport only.
    {ok, _} = application:ensure_all_started(crypto),
    Transport = proplists:get_value(transport, Opts, tcp),
    DefaultPort = case Transport of
        ssl -> indra_ws:default_wss_port();
        _ -> indra_ws:default_port()
    end,
    Port = proplists:get_value(port, Opts, DefaultPort),
    Path = norm_path(proplists:get_value(path, Opts, indra_ws:default_path())),
    HsTimeout = proplists:get_value(handshake_timeout_ms, Opts,
                                    indra_ws:default_handshake_timeout_ms()),
    MaxFrame = proplists:get_value(max_frame_bytes, Opts,
                                   indra_ws:default_max_frame_bytes()),
    MaxConns = proplists:get_value(max_connections, Opts,
                                   indra_ws:default_max_connections()),
    ConnOpts = proplists:get_value(conn, Opts, []),
    %% `{ip, Addr}' binds one interface; absent binds every interface.
    SockOpts = indra_listener:listen_sock_opts() ++ [{ip, Ip} || {ip, Ip} <- Opts],
    ListenResult = case Transport of
        ssl ->
            {ok, _} = application:ensure_all_started(ssl),
            case {proplists:get_value(certfile, Opts),
                  proplists:get_value(keyfile, Opts)} of
                {undefined, _} -> {error, {missing_option, certfile}};
                {_, undefined} -> {error, {missing_option, keyfile}};
                {Cert, Key} ->
                    %% Same posture as the TCP/TLS listener: OTP `ssl'
                    %% defaults (TLS 1.2 + 1.3, default ciphers), no
                    %% client-certificate verification. Material is read
                    %% once here; rotation needs a restart.
                    ssl:listen(Port, [{certfile, Cert}, {keyfile, Key} | SockOpts])
            end;
        _ ->
            gen_tcp:listen(Port, SockOpts)
    end,
    case ListenResult of
        {ok, LSock} ->
            case bound_port(Transport, LSock) of
                {ok, Actual} ->
                    Server = self(),
                    Acceptor = spawn_link(fun() -> accept_loop(Server, Transport, LSock) end),
                    {ok, #{transport => Transport, lsock => LSock,
                           port => Actual, path => Path,
                           hs_timeout => HsTimeout, max_frame => MaxFrame,
                           max_conns => MaxConns, conn_opts => ConnOpts,
                           acceptor => Acceptor, conns => #{}}};
                {error, Reason} ->
                    catch close_listen(Transport, LSock),
                    {stop, Reason}
            end;
        {error, Reason} ->
            {stop, Reason}
    end.

handle_call(get_port, _From, #{port := Port} = State) ->
    {reply, {ok, Port}, State};
%% @private Admission for one accepted socket. The server spawns and
%% monitors the handshake handler itself (so the count can never leak),
%% then the acceptor transfers socket ownership to it. At the cap the
%% acceptor is told `full' and fails the socket closed.
handle_call(admit, _From, #{conns := Conns, max_conns := Max} = State)
  when map_size(Conns) >= Max ->
    {reply, full, State};
handle_call(admit, _From, #{transport := Transport, path := Path,
                            hs_timeout := HsTimeout,
                            max_frame := MaxFrame, conn_opts := ConnOpts,
                            conns := Conns} = State) ->
    Server = self(),
    Pid = spawn(fun() -> wait_go(Transport, Path, HsTimeout, MaxFrame, ConnOpts, Server) end),
    Ref = monitor(process, Pid),
    {reply, {ok, Pid}, State#{conns => Conns#{Pid => Ref}}};
%% @private A handshake handler finished its handoff: the count moves
%% from the short-lived handler to the connection it spawned.
handle_call({handoff, ConnPid}, {HandlerPid, _Tag},
            #{conns := Conns} = State) ->
    case maps:take(HandlerPid, Conns) of
        {Ref, Rest} ->
            demonitor(Ref, [flush]),
            Ref2 = monitor(process, ConnPid),
            {reply, ok, State#{conns => Rest#{ConnPid => Ref2}}};
        error ->
            {reply, ok, State}
    end;
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

%% @private A socket admission that never reached its handler (the
%% ownership transfer failed): release the slot.
handle_cast({dropped, Pid}, #{conns := Conns} = State) ->
    case maps:take(Pid, Conns) of
        {Ref, Rest} ->
            demonitor(Ref, [flush]),
            {noreply, State#{conns => Rest}};
        error ->
            {noreply, State}
    end;
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'EXIT', Pid, Reason}, #{acceptor := Pid} = State) ->
    case Reason of
        normal ->
            {noreply, State};
        _ ->
            #{transport := Transport, lsock := LSock} = State,
            Server = self(),
            case listen_alive(Transport, LSock) of
                true ->
                    Acceptor = spawn_link(fun() -> accept_loop(Server, Transport, LSock) end),
                    {noreply, State#{acceptor => Acceptor}};
                false ->
                    {stop, {acceptor_died, Reason}, State}
            end
    end;
handle_info({'DOWN', Ref, process, Pid, _Reason}, #{conns := Conns} = State) ->
    case Conns of
        #{Pid := Ref} ->
            {noreply, State#{conns => maps:remove(Pid, Conns)}};
        _ ->
            {noreply, State}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #{transport := Transport, lsock := LSock}) ->
    catch close_listen(Transport, LSock),
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%====================================================================
%% Acceptor + handshake handoff
%%====================================================================

accept_loop(Server, Transport, LSock) ->
    case accept_one(Transport, LSock) of
        {ok, Sock} ->
            %% Only the acceptor owns the socket here, so only it can
            %% transfer ownership: admit a handler first, then hand the
            %% socket over. At the cap the socket fails closed.
            case gen_server:call(Server, admit) of
                {ok, Pid} ->
                    case controlling_process(Transport, Sock, Pid) of
                        ok ->
                            Pid ! {go, Sock};
                        {error, _} ->
                            catch close_socket(Transport, Sock),
                            gen_server:cast(Server, {dropped, Pid})
                    end;
                full ->
                    catch close_socket(Transport, Sock)
            end,
            accept_loop(Server, Transport, LSock);
        {error, closed} ->
            exit(normal);
        {error, _Reason} ->
            timer:sleep(100),
            accept_loop(Server, Transport, LSock)
    end.

%% @private Accept one client socket.
accept_one(tcp, LSock) ->
    gen_tcp:accept(LSock);
accept_one(ssl, LSock) ->
    %% Only the transport accept runs here. The TLS handshake runs in the
    %% per-connection handler (see `tls_upgrade/2'), so a client that
    %% opens a socket and sends nothing holds one handler for the
    %% handshake timeout and never stalls the accept loop.
    ssl:transport_accept(LSock).

%% @private Complete the TLS handshake on a `wss' socket inside its own
%% handler process, bounded by the same 5 s as the TCP/TLS listener. A
%% plaintext socket passes through. Any failure (including plaintext
%% bytes on the `wss' port) logs its reason and fails the socket closed.
tls_upgrade(tcp, Sock) ->
    {ok, Sock};
tls_upgrade(ssl, Sock) ->
    case ssl:handshake(Sock, ?TLS_HANDSHAKE_TIMEOUT_MS) of
        {ok, TLSSock} ->
            {ok, TLSSock};
        {error, Reason} ->
            logger:warning("wss TLS handshake failed: ~p", [Reason]),
            catch ssl:close(Sock),
            {error, Reason}
    end.

%% @private Wait for the acceptor's ownership transfer. The 10 s bound
%% only fires for an orphaned admission (the acceptor died mid-handoff);
%% the monitor on the server then releases the slot.
wait_go(Transport, Path, HsTimeout, MaxFrame, ConnOpts, Server) ->
    receive
        {go, Sock} ->
            handle_client(Sock, Transport, Path, HsTimeout, MaxFrame, ConnOpts, Server)
    after 10000 ->
        exit(normal)
    end.

%% @private Upgrade one socket, then hand it to `indra_conn' on the
%% exact TCP bind path. Any handshake failure closes the socket; the
%% connection count is released through the monitor. A TLS socket that
%% reaches here already completed its handshake; the WS upgrade runs on
%% the encrypted channel and a `wss' conn owns the TLS socket after.
handle_client(Sock0, Transport, Path, HsTimeout, MaxFrame, ConnOpts, Server) ->
    case tls_upgrade(Transport, Sock0) of
        {ok, Sock} ->
            upgrade_client(Sock, Transport, Path, HsTimeout, MaxFrame, ConnOpts, Server);
        {error, _} ->
            ok
    end.

upgrade_client(Sock, Transport, Path, HsTimeout, MaxFrame, ConnOpts, Server) ->
    case indra_ws:handshake(Sock, Transport, Path, HsTimeout) of
        ok ->
            WsConnOpts = lists:keystore(ws_max_frame_bytes, 1, ConnOpts,
                                        {ws_max_frame_bytes, MaxFrame}),
            ConnTransport = case Transport of ssl -> wss; _ -> ws end,
            case indra_conn:start_link(Sock, [{transport, ConnTransport} | WsConnOpts]) of
                {ok, Pid} ->
                    case controlling_process(Transport, Sock, Pid) of
                        ok ->
                            gen_server:call(Server, {handoff, Pid}),
                            gen_statem:cast(Pid, takeover);
                        {error, _} ->
                            catch close_socket(Transport, Sock),
                            catch indra_conn:stop(Pid)
                    end;
                {error, _} ->
                    catch close_socket(Transport, Sock)
            end;
        {error, _} ->
            catch close_socket(Transport, Sock)
    end.

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

controlling_process(tcp, Sock, Pid) -> gen_tcp:controlling_process(Sock, Pid);
controlling_process(ssl, Sock, Pid) -> ssl:controlling_process(Sock, Pid).

close_socket(tcp, Sock) -> gen_tcp:close(Sock);
close_socket(ssl, Sock) -> ssl:close(Sock).

norm_path(Path) when is_binary(Path) -> binary_to_list(Path);
norm_path(Path) when is_list(Path) -> Path.
