%% @doc In-process mock of the BrokerLink client for edge tests.
%%
%% Implements the same call interface the edge uses against
%% {@code indra_brokerlink} ({@code {send, Opcode, ConnId, SeqNo, Meta,
%% Payload}}) so connection tests can run without a live Rust core.
%% Records every sent frame (including the caller pid, which is the
%% `indra_conn` under test) for later assertion.
-module(mock_broker).

-behaviour(gen_server).

-export([start_link/0,
         stop/1,
         sent/1]).

%% gen_server callbacks.
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% @doc Start an unregistered mock broker.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link(?MODULE, [], []).

%% @doc Stop the mock.
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

%% @doc Return sent frames oldest-first. Each frame is a map with
%% {@code from}, {@code opcode}, {@code conn_id}, {@code seq_no},
%% {@code meta} and {@code payload}.
-spec sent(pid()) -> [map()].
sent(Pid) ->
    gen_server:call(Pid, get_frames).

init([]) ->
    {ok, #{frames => []}}.

handle_call({send, Opcode, ConnId, SeqNo, Meta, Payload}, {From, _Tag}, State) ->
    Frame = #{from => From,
              opcode => Opcode,
              conn_id => ConnId,
              seq_no => SeqNo,
              meta => Meta,
              payload => Payload},
    Frames = [Frame | maps:get(frames, State)],
    {reply, ok, State#{frames => Frames}};
handle_call(get_frames, _From, State) ->
    {reply, lists:reverse(maps:get(frames, State)), State};
handle_call(_Req, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
