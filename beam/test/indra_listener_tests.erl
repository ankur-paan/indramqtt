%% @doc EUnit tests for {@link indra_listener}.
%%
%% Self-terminating integration coverage: the listener binds an
%% ephemeral port, accepts a real client socket into a real
%% `indra_conn`, and completes the CONNECT -> CONNACK handshake against
%% {@link mock_broker}. Nothing outlives the test.
-module(indra_listener_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 2000).

start_stop_ephemeral_test() ->
    {ok, Listener} = indra_listener:start_link([{port, 0}]),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        ?assert(Port > 0),
        %% A client can open (and close) a TCP connection.
        {ok, Sock} = gen_tcp:connect("127.0.0.1", Port,
                                     [binary, {packet, raw}, {active, false}],
                                     2000),
        gen_tcp:close(Sock)
    after
        indra_listener:stop(Listener)
    end,
    %% After stop the port is closed again.
    {ok, Probe} = indra_listener:start_link([{port, 0}]),
    {ok, Port2} = indra_listener:get_port(Probe),
    indra_listener:stop(Probe),
    ?assertMatch({error, _},
                 gen_tcp:connect("127.0.0.1", Port2,
                                 [binary, {packet, raw}, {active, false}],
                                 500)).

full_handshake_through_listener_test() ->
    {ok, Mock} = mock_broker:start_link(),
    {ok, Listener} = indra_listener:start_link([{port, 0},
                                                {conn, [{broker, Mock},
                                                        {conn_id, 9001}]}]),
    try
        {ok, Port} = indra_listener:get_port(Listener),
        {ok, Client} = gen_tcp:connect("127.0.0.1", Port,
                                       [binary, {packet, raw}, {active, false}],
                                       2000),
        try
            ok = gen_tcp:send(Client, connect_packet(<<"via-listener">>, true, 60)),
            [Sent] = wait_frames(Mock, 1),
            ?assertEqual(16#0010, maps:get(opcode, Sent)),
            ?assertEqual(9001, maps:get(conn_id, Sent)),
            {ok, Bind} = indra_brokerlink:decode_bind_meta(maps:get(meta, Sent)),
            ?assertEqual(<<"via-listener">>, maps:get(client_id, Bind)),
            %% The conn under test is the frame sender; answer it directly.
            Conn = maps:get(from, Sent),
            Binding = indra_brokerlink:encode_session_binding_meta(4242, true, 0),
            ok = indra_conn:broker_frame(Conn, #{opcode => 16#0011}, Binding, <<>>),
            {ok, Connack} = gen_tcp:recv(Client, 4, ?RECV_TIMEOUT),
            ?assertEqual(<<16#20, 16#02, 16#01, 16#00>>, Connack),
            ?assertMatch({connected, _}, sys:get_state(Conn))
        after
            gen_tcp:close(Client)
        end
    after
        indra_listener:stop(Listener),
        mock_broker:stop(Mock)
    end.

%%====================================================================
%% Helpers
%%====================================================================

wait_frames(_Mock, _N, 0) ->
    error(broker_frame_timeout);
wait_frames(Mock, N, Tries) ->
    case mock_broker:sent(Mock) of
        Frames when length(Frames) >= N -> Frames;
        _ -> timer:sleep(50), wait_frames(Mock, N, Tries - 1)
    end.

wait_frames(Mock, N) ->
    wait_frames(Mock, N, 40).

connect_packet(ClientId, CleanStart, Keepalive) ->
    Flags = case CleanStart of true -> 16#02; false -> 16#00 end,
    Var = <<0, 4, "MQTT", 4, Flags:8, Keepalive:16/big>>,
    Payload = <<(byte_size(ClientId)):16/big, ClientId/binary>>,
    Body = <<Var/binary, Payload/binary>>,
    <<16#10, (byte_size(Body)), Body/binary>>.
