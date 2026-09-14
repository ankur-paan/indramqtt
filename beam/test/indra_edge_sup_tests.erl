%% Supervisor wiring tests for the indra_edge application tree.
%%
%% The shipped tree must connect the MQTT listener to the Rust kernel
%% over BrokerLink: a CONNECT accepted by the listener reaches a (fake)
%% kernel as BindConnection, and the kernel's SessionBinding comes back
%% to the client as CONNACK.
-module(indra_edge_sup_tests).

-include_lib("eunit/include/eunit.hrl").

-define(RECV_TIMEOUT, 5000).
-define(BIND_CONNECTION, 16#0010).
-define(SESSION_BINDING, 16#0011).

connect_reaches_kernel_through_supervisor_test() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {packet, raw},
                                     {active, false}, {reuseaddr, true}]),
    {ok, KernelPort} = inet:port(LSock),
    Parent = self(),
    Kernel = spawn_link(fun() -> fake_kernel(LSock, Parent) end),
    ok = application:set_env(indra_edge, kernel_port, KernelPort),
    ok = application:set_env(indra_edge, mqtt_port, 0),
    OldTrap = process_flag(trap_exit, true),
    {ok, Sup} = indra_edge_sup:start_link(),
    try
        {ok, MqttPort} = indra_listener:get_port(child(Sup, indra_listener)),
        {ok, Client} = gen_tcp:connect("127.0.0.1", MqttPort,
                                       [binary, {packet, raw}, {active, false}]),
        ClientId = <<"sup-wiring">>,
        Body = <<0, 4, "MQTT", 4, 2, 0, 60,
                 (byte_size(ClientId)):16, ClientId/binary>>,
        ok = gen_tcp:send(Client, <<16#10, (byte_size(Body)), Body/binary>>),
        receive
            {bind_connection, _ConnId} -> ok
        after ?RECV_TIMEOUT ->
            error(no_bind_connection_at_kernel)
        end,
        ?assertEqual({ok, <<16#20, 16#02, 16#00, 16#00>>},
                     gen_tcp:recv(Client, 4, ?RECV_TIMEOUT)),
        gen_tcp:close(Client)
    after
        exit(Sup, shutdown),
        receive
            {'EXIT', Sup, _} -> ok
        after ?RECV_TIMEOUT ->
            ok
        end,
        unlink(Kernel),
        exit(Kernel, kill),
        gen_tcp:close(LSock),
        application:unset_env(indra_edge, kernel_port),
        application:unset_env(indra_edge, mqtt_port),
        process_flag(trap_exit, OldTrap)
    end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

child(Sup, Id) ->
    {Id, Pid, _Type, _Modules} = lists:keyfind(Id, 1, supervisor:which_children(Sup)),
    Pid.

%% @private Fake Rust kernel: answers every BindConnection with an
%% accepting SessionBinding that mirrors the conn id and sequence number.
fake_kernel(LSock, Parent) ->
    {ok, Sock} = gen_tcp:accept(LSock, ?RECV_TIMEOUT),
    kernel_loop(Sock, Parent, <<>>).

kernel_loop(Sock, Parent, Buf) ->
    case indra_brokerlink:decode_frame(Buf) of
        {ok, #{opcode := ?BIND_CONNECTION, conn_id := ConnId, seq_no := Seq},
         _Meta, _Payload, Rest} ->
            Parent ! {bind_connection, ConnId},
            Binding = indra_brokerlink:encode_session_binding_meta(1, false, 0),
            Frame = indra_brokerlink:encode_frame(?SESSION_BINDING, ConnId, Seq,
                                                  Binding, <<>>),
            ok = gen_tcp:send(Sock, Frame),
            kernel_loop(Sock, Parent, Rest);
        {ok, _Header, _Meta, _Payload, Rest} ->
            kernel_loop(Sock, Parent, Rest);
        {more, _} ->
            case gen_tcp:recv(Sock, 0) of
                {ok, Data} -> kernel_loop(Sock, Parent, <<Buf/binary, Data/binary>>);
                {error, _} -> ok
            end;
        {error, Reason} ->
            exit({bad_frame, Reason})
    end.
