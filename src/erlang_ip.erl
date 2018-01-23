%%%----------------------------------------------------------------------
%%% @author : kongqingquan <kqqsysu@gmail.com>
%%% @date   : 2015.11.07
%%% @desc   : 17monip解析模块
%%%----------------------------------------------------------------------

-module(erlang_ip).
-author('kongqingquan <kqqsysu@gmail.com>').

-include_lib("kernel/include/inet.hrl").

-export([load/0, find/1]).

%% ------------- DAT struct --------------
%%
%% | 4 bytes 数据长度 DataOffset |
%% | 256 * 4 ip首位对应的数据偏移 |
%% | DataOffset * 8 (4 bytes Ip, 3 bytes offset, 1 byte data len) |
%% | Data Address Info |
%%
%% ---------------------------------------

load() ->
    DbFile = filename:join(code:priv_dir(erlang_ip), "17monipdb.dat"),
    {ok,FileBin} = file:read_file(DbFile),
    catch ets:new(erlang_ip_file, [named_table, public, {read_concurrency, true}]),
    ets:insert(erlang_ip_file, {filebin, FileBin}),
    catch ets:new(erlang_ip_cache, [named_table, public]),
    ok.

find(Ip) when is_list(Ip) ->
    IpBin = iolist_to_binary(Ip),
    case ets:lookup(erlang_ip_cache, IpBin) of
        [{_, Result}] -> Result;
        _ ->
            case ets:lookup(erlang_ip_file, filebin) of
                [{_, FileBin}] ->
                    Result = case do_find(Ip, FileBin) of
                        false -> <<>>;
                        {ok, Address} -> Address
                    end,
                    ets:insert(erlang_ip_cache, {IpBin, Result}),
                    Result;
                _ -> {error, ip_database_not_loaded}
            end
    end;
find(Ip) when is_binary(Ip) ->
    find(binary_to_list(Ip)).

do_find(Ip, FileBin) when is_binary(FileBin) ->
    {ok,#hostent{h_addr_list = [_Ip |_]}} =  inet:gethostbyname(Ip),
    Ip2 = inet:ntoa(_Ip),

    [FirstIpStr | _] = IdList = string:tokens(Ip2,"."),
    LongIp = ntohl(IdList),
    FirstIp = to_integer(FirstIpStr),

    <<OffsetLen:32,DataBin/binary>> = FileBin,

    {_Bin1,Bin2} = erlang:split_binary(DataBin,FirstIp * 4),
    <<MinOffset:4/little-unsigned-integer-unit:8,MaxOffSet:4/little-unsigned-integer-unit:8,_/binary>> = Bin2,
    MaxOffSet2 =
        case FirstIpStr >= 255 of
            true -> OffsetLen;
            false -> MaxOffSet * 8 + 1024 + 4
        end,

    %% 截取区间内的数据
    {Bin3,_Bin4} = erlang:split_binary(FileBin,MaxOffSet2),
    {_Bin5,Bin6} = erlang:split_binary(Bin3, 1024 + 4 + MinOffset * 8),
    case find_data_index(Bin6,LongIp) of
        {ok,DataOffset,DataLen} ->
            {_Bin7,Bin8} = erlang:split_binary(FileBin,OffsetLen + DataOffset - 1024),
            {Address,_} = erlang:split_binary(Bin8,DataLen),
            {ok,Address};
        false -> false
    end.

find_data_index(IpData,LongIp)  ->
    Len = size(IpData) div 8,
    Len2 = Len div 2,
    case IpData of
        <<Bin1:Len2/binary-unit:8,IpInfo:8/binary-unit:8,Bin2>> ->
            <<A:8,B:8,C:8,D:8,_/binary>> = IpInfo,
            DataLongIp = ntohl([A,B,C,D]),
            case DataLongIp > LongIp of
                true ->
                    find_data_index(<<Bin1/binary,IpData/binary>>,LongIp);
                false ->
                    find_data_index(Bin2,LongIp)
            end;
        _ -> find_data_index2(IpData,LongIp)
    end.
find_data_index2(<<A:8,B:8,C:8,D:8,DataOffset:3/little-unsigned-unit:8,DataLen:8,Bin2/binary>>,LongIp) ->
    DataLongIp = ntohl([A,B,C,D]),
    case DataLongIp >= LongIp of
        true ->
            {ok,DataOffset,DataLen};
        false ->
            find_data_index2(Bin2,LongIp)
    end;
find_data_index2(_Bin,_LongIp) -> false.

ntohl([A,B,C,D]) ->
    (to_integer(A) bsl 24) + (to_integer(B) bsl 16) + (to_integer(C) bsl 8) + to_integer(D).

to_integer(Val) when is_integer(Val) -> Val;
to_integer(Val) when is_binary(Val) -> binary_to_integer(Val);
to_integer(Val) when is_list(Val) -> list_to_integer(Val).

