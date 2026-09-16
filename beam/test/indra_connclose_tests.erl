%% @doc EUnit tests for BrokerLink ConnClose handling (W0-25, edge side).
%%
%% The kernel orders the close with opcode 16#0041 and empty metadata;
%% the edge only closes the client socket and terminates normally.
%% All tests are self-terminating: every socket is closed and every
%% process stopped within the test. The Rust core is replaced by
%% {@link mock_broker}.
-module(indra_connclose_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).

%%====================================================================
%% ConnClose handling
%%====================================================================

connclose_closes_socket_test() ->
    {LSock, Port, Mock, Client, Conn} = setup([{conn_id, 6301}]),
    _ = Port,
    Ref = monitor(process, Conn),
    try
        handshake(Client, Mock, <<"dev-close">>, Conn),
        %% Kernel orders the close: empty meta, empty payload (W0-24).
        Meta = indra_brokerlink:encode_connclose_meta(),
        ok = indra_conn:broker_frame(Conn, #{opcode => 16#0041}, Meta, <<>>),
        %% Peer observes the TCP close.
        ?assertEqual({error, closed}, gen_tcp:recv(Client, 0, ?RECV_TIMEOUT)),
        %% The connection process terminates normally.
        receive
            {'DOWN', Ref, process, Conn, normal} -> ok
        after ?RECV_TIMEOUT ->
            error(conn_did_not_stop)
        end,
        %% No reply or unbind is emitted: the kernel already unbound.
        ?assertEqual(1, length(mock_broker:sent(Mock)))
    after
        teardown(LSock, Mock, Client, Conn),
        demonitor(Ref, [flush])
    end.

connclose_opcode_round_trip_test() ->
    ?assertEqual(16#0041, indra_brokerlink:opcode_to_int(conn_close)),
    ?assertEqual(conn_close, indra_brokerlink:int_to_opcode(16#0041)),
    ?assertEqual(conn_close,
                 indra_brokerlink:int_to_opcode(
                   indra_brokerlink:opcode_to_int(conn_close))),
    %% Atom and raw-int encodings agree through the framing helpers.
    Meta = indra_brokerlink:encode_connclose_meta(),
    ?assertEqual(<<>>, Meta),
    A = indra_brokerlink:encode_frame(conn_close, 4242, 7, Meta, <<>>),
    B = indra_brokerlink:encode_frame(16#0041, 4242, 7, <<>>, <<>>),
    ?assertEqual(A, B),
    {ok, Header, GotMeta, GotPayload, Rest} = indra_brokerlink:decode_frame(A),
    ?assertEqual(<<>>, Rest),
    ?assertEqual(16#0041, maps:get(opcode, Header)),
    ?assertEqual(4242, maps:get(conn_id, Header)),
    ?assertEqual(7, maps:get(seq_no, Header)),
    ?assertEqual(<<>>, GotMeta),
    ?assertEqual(<<>>, GotPayload),
    ?assertEqual({ok, #{}}, indra_brokerlink:decode_connclose_meta(GotMeta)),
    ?assertEqual({error, malformed_connclose_meta},
                 indra_brokerlink:decode_connclose_meta(<<"x">>)).

%%====================================================================
%% Helpers
%%====================================================================

%% @private Listen on loopback, accept one socket into an indra_conn,
%% and connect a test client. Returns {LSock, Port, Mock, Client, Conn}.
setup(ConnOpts) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    {ok, Mock} = mock_broker:start_link(),
    Parent = self(),
    spawn(fun() ->
        {ok, Sock} = gen_tcp:accept(LSock, 5000),
        {ok, Conn} = indra_conn:start_link(Sock, [{broker, Mock} | ConnOpts]),
        ok = gen_tcp:controlling_process(Sock, Conn),
        gen_statem:cast(Conn, takeover),
        Parent ! {conn_ready, Conn}
    end),
    {ok, Client} = gen_tcp:connect("127.0.0.1", Port,
                                   [binary, {packet, raw}, {active, false}],
                                   5000),
    Conn = receive {conn_ready, C} -> C
           after 5000 -> error(conn_not_ready)
           end,
    {LSock, Port, Mock, Client, Conn}.

teardown(LSock, Mock, Client, Conn) ->
    catch indra_conn:stop(Conn),
    catch gen_tcp:close(Client),
    catch gen_tcp:close(LSock),
    catch mock_broker:stop(Mock),
    ok.

%% @private Run CONNECT -> CONNACK against the mock broker.
handshake(Client, Mock, ClientId, Conn) ->
    ok = gen_tcp:send(Client, connect_packet(ClientId, true, 60)),
    [_Bind] = wait_frames(Mock, 1),
    Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
    ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
    <<16#20, 16#02, 16#00, 16#00>> = recv_exact(Client, 4),
    ok.

wait_frames(Mock, N) ->
    wait_frames(Mock, N, 40).

wait_frames(_Mock, _N, 0) ->
    error(broker_frame_timeout);
wait_frames(Mock, N, Tries) ->
    case mock_broker:sent(Mock) of
        Frames when length(Frames) >= N -> Frames;
        _ -> timer:sleep(50), wait_frames(Mock, N, Tries - 1)
    end.

recv_exact(Sock, N) ->
    {ok, Bin} = gen_tcp:recv(Sock, N, ?RECV_TIMEOUT),
    Bin.

%% @private Minimal MQTT 3.1.1 CONNECT (remaining length < 128 bytes).
connect_packet(ClientId, CleanStart, Keepalive) ->
    Flags = case CleanStart of true -> 16#02; false -> 16#00 end,
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.
