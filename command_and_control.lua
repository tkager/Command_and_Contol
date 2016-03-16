
-- Command and Control v0.9
-- Writen by Thomas Kager
-- tkager@linux.com

-- Created 3/15/2016
-- Last modified 3/16/16

--[[

- Purpose
The purpose of this script is to pull HTTP transaction security and performance data from a packet trace and analyze for command control based upon the
examination of receiving a 404 and 200 code upon the same URI.

- Usage
tshark -r "(filename)" -2 -X lua_script:command_and_control.lua -q

This script is an extension of the http_expert script.

- Requirements
Requires Wireshark/Tshark 1.10 or later with LUA compiled. This can be determined through the "About Wireshark" menu option.
--]]

tap=Listener.new(nil, "http") -- Create Listener, with a Filter for HTTP traffic (only).

http = {} -- Create usrdata array http.

-- Field Extractors are used to map tshark fields to variables and typically behave as function calls

-- TCP Information/useful for tracking events that occur among the same connection.
tcp_stream=Field.new("tcp.stream")

-- Information collected/derived from HTTP request
http_request_time=Field.new("frame.time")
http_request_frame=Field.new("frame.number")
client=Field.new("ip.src")
server=Field.new("ip.dst")
http_request_method=Field.new("http.request.method")
http_request_version=Field.new("http.request.version")
http_user_agent=Field.new("http.user_agent")
http_host=Field.new("http.host")
http_request_uri=Field.new("http.request.uri")
http_data=Field.new("http") -- Esentially a Hex dump of the entire header field. Used to calculate the number of optional header fields.
http_request_header_fields=0 -- As this is a caculated field, there is no direct mapping to tshark field extractor. We need to create it but we will just initialize it to 0.
response=Field.new("frame.len")

-- Information collected from HTTP response
http_reply_frame=Field.new("frame.number")
http_request_in=Field.new("http.request_in")
http_response_code=Field.new("http.response.code")
http_cache_control=Field.new("http.cache_control")
http_time=Field.new("http.time")


function tap.draw() -- Wireshark/Tshark explicitly looks for tap.draw() after running through all packets.
-- Header Output. Needs to occur once before we iterate through the array(s) in the main loop.


function request_reply()

print("\nAll HTTP Requests")
io.write("request frame",",","request time",",","client",",","server",",","request method",",","request version",",","http host",",","request uri",",","user agent",",","request header fields",",","response frame",",","response code",",","response time",",","cache control")
io.write("\n") --- linespace after header.  This can occur within previous write operation.

-- Main Loop
for k,v in pairs (http) do
-- Optimal to combine these into a single IO write. Such a write can be extended across multiple lines, however this convention breaks prior to LUA 5.2.
io.write(tostring(k),",",tostring(http[k][http_request_time]),",",tostring(http[k][client]),",",tostring(http[k][server]),",",tostring(http[k][http_request_method]),",",tostring(http[k][http_request_version]),",",tostring(http[k][http_host]),",",tostring(http[k][http_request_uri]),",",tostring(http[k][http_user_agent]),",",tostring(http[k][http_request_header_fields]),",")
io.write(tostring(http[k][http_reply_frame]),",",tostring(http[k][http_response_code]),",",tostring(http[k][http_time]),",",tostring(http[k][http_cache_control]))
io.write("\n") --- linespace after row. This can also occur as part of one large write operation.
end

end -- request_reply


function bot()

bot = {}

for k,v in pairs (http) do

_client=tostring(http[k][client])
_uri=tostring(http[k][http_request_uri])
response=tostring(http[k][http_response_code])
str=tostring(http[k][tcp_stream])
header_len=tostring(http[k][http_request_header_fields])

-- print(str, _client, _uri, response, header_len)


	if  bot[str]== nil then
		bot[str]={} -- we need to create row
		bot[str]["client"]=_client -- create column
	end

	if  bot[str]["uri"] == nil then
		--- print(bot[_client][http_request_uri])
		bot[str]["uri"]={}
	end

	if 	bot[str]["uri"][_uri] == nil then
		bot[str]["uri"][_uri]={}
		-- bot[_client][http_request_uri] = uri
		-- print(str, bot[str]["client"], bot[str]["uri"][_uri])
		bot[str]["uri"][_uri]["header_len"]=header_len
	end




	if  bot[str]["uri"][_uri]["response"] == nil then
		bot[str]["uri"][_uri]["response"]=response

	else
		x=bot[str]["uri"][_uri]["response"]
		_, count = string.gsub(x, response, " ")
		if count == 0 then -- Check to determine whether the response  was found in the existing entry. If not, add it to the list.
				bot[str]["uri"][_uri]["response"]= x .. "," .. response
		end

		y=bot[str]["uri"][_uri]["header_len"]
		_, count = string.gsub(y, header_len, " ")
		if count == 0 then -- Check to determine whether the response  was found in the existing entry. If not, add it to the list.
				bot[str]["uri"][_uri]["header_len"]= y .. "," .. header_len
		end



	end

end -- end of for k,v


function debug_array(x)


	if type(x)=="table" then

		for k,v in pairs (x) do
			print("key = ", k, "value = ", v)
			debug_array(v)
		end
	else
		print(x, "leaf node")
	end
end

-- debug_array(bot)

print()
print("Potential Command and Control")
print("Stream", "\t", "Client", "\t", "      Return Code(s)", "    Header Field Count(s)", "        URI")

for a,b in pairs (bot) do

	for  c,d in pairs (b) do

		if c=="uri" then


			-- Detect Return 404 and 200 for identical request.
			for e,f in pairs (d) do
				x=tostring(bot[a]["uri"][e]["response"])
				_, yes_404 = string.gsub(x, 404, " ")
				_, yes_200 = string.gsub(x, 200, " ")

			if (yes_404 > 0 and yes_200 > 0) then
			print(tostring(a), "\t",  tostring(bot[a]["client"]), "\t", tostring(bot[a]["uri"][e]["response"]), "\t",  tostring(bot[a]["uri"][e]["header_len"]), "\t", tostring(e))
			end
		end

		end

	end


end


end -- end bot

--- Which output functions to run
request_reply()
bot()


end -- end tap.draw()


function tap.packet() -- Wireshark/Tshark explicitly looks for tap.packet(). It runs for each frame that matches listener filter.

if http_request_method() then -- If frame is an HTTP request, there are specific fields that we need to collect.

	request_frame=tostring(http_request_frame())
	http[request_frame]={}
	http[request_frame][http_request_time]=tostring(http_request_time()):gsub(',','')
	http[request_frame][client]=tostring(client())
	http[request_frame][server]=tostring(server())
	http[request_frame][http_request_method]=tostring(http_request_method())
	http[request_frame][http_request_version]=tostring(http_request_version())
	http[request_frame][http_host]=tostring(http_host())
	http[request_frame][http_request_uri]=tostring(http_request_uri())
	http[request_frame][tcp_stream]=tostring(tcp_stream())
	--- print(http[request_frame][tcp_stream])

	-- Determine Number of Request Header Fields.
	x=tostring(http_data())
	_, count = string.gsub(x, "0d:0a", " ") -- Count number of CR/LF, as these delineate header fields.
	_, double_white = string.gsub(x, "0d:0a:0d:0a", " ") -- Count occurrenes in which 2 CR/LF occur one after these other, as these will be counted as 2 header fields.
	http[request_frame][http_request_header_fields]=count - double_white - 1 -- Subtract multiple CR/LF occurrences from the CR/LF count. Also subtract 1, because there is an occurence between (method, URI, version) and the first header.

	-- Add user_agent if present within headers store the value, else populate with none. This is necessary as we will get an error if the header field doesn't exist.
	if http_user_agent() == nil then
		http[request_frame][http_user_agent]="none"
	else
		http[request_frame][http_user_agent]=tostring(http_user_agent())
	end

else if http_response_code() then -- If frame is an HTTP response, there are specific fields which we need to collect.
	request_in=tostring(http_request_in())
	http[request_in][http_reply_frame]=tostring(http_reply_frame())
	http[request_in][http_response_code]=tostring(http_response_code())
	http[request_in][http_time]=tostring(http_time())
	-- Check for cache control. If it doesn't exist, store none. Else store the value.
	if http_cache_control() == nil then
		http[request_in][http_cache_control]="none"
	else
		http[request_in][http_cache_control]=tostring(http_cache_control()):gsub(',','') --- We need to strip out any commas that may exist in cache control header, as this is a CSV.
	end

else -- Other frames (such as continutation frames) do not contain usable field values. We will break the script if we try and process them.
	end


end

end -- end of tap_packet()
