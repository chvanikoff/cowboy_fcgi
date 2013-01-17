-module(example).

-export([start/0]).

start() ->
	ok = application:load(ex_fcgi),
	ok = ensure_started([ex_fcgi, crypto, ranch, cowboy]),
	
	[$\n | T] = lists:reverse(os:cmd("pwd")),
	Pwd = lists:reverse(T),
	Fcgi_suite_data_dir = Pwd ++ "/test/fcgi_SUITE_data",

	io:format("~n"),
	FpmPath = os:find_executable("php-fpm"),
	DataDir = Fcgi_suite_data_dir,
	os:cmd("\"" ++ FpmPath ++ "\" -y \"" ++ DataDir ++ "\"/php-fpm.conf -p \"" ++ DataDir ++ "\""),
	ex_fcgi:start('php-fpm', localhost, 33000),
	Fcgi_opts = [{name, 'php-fpm'},
		{script_dir, DataDir}],
	Dispatch = [
		{'_', [
			{[<<"hello.php">>], cowboy_http_fcgi, Fcgi_opts}
		]}
	],
	{ok, _} = cowboy:start_http(http, 100,
		[{port, 8008}],
		[{env, [{dispatch, Dispatch}]}]
	).

%% ===================================================================
%% Internal functions
%% ===================================================================

ensure_started([]) -> ok;
ensure_started([App | Apps]) ->
	Msg = case application:start(App) of
		ok ->
			"started";
		{error, {already_started, App}} ->
			"was already started";
		Error ->
			io:format("Error starting ~p:~n~p~n", [App, Error]),
			throw(Error)
	end,
	io:format("~p " ++ Msg ++ "~n", [App]),
	ensure_started(Apps).
