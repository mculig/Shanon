
-- Helpers Lua module with functions used by shanon.lua

--Module table
local M = {}

--Helper to get raw bytes
function M.getRaw(tvb, value)
	return tvb:range(value.offset,value.len):bytes():raw()
end

--Helper to get remaining data
function M.getRest(tvb, value)
	--Get all data past the last value. This is just data for us
	return tvb:range(value.offset+value.len):bytes():raw()
end

--Helper to get rest from specific offset
function M.getRestFromOffset(tvb, offset)
	--Get all the data past the offset
	return tvb:range(offset):bytes():raw()
end

--Helper to split strings
function M.split(inputString, delimiter)
	result = {}
	tableLength = 0
	for match in (inputString..delimiter):gmatch("(.-)"..delimiter) do
		table.insert(result, match)
		tableLength = tableLength + 1
	end
	return result, tableLength
end

--For logging

--Log types
M.logError = 1
local logErrorTag = "[ERROR]"
M.logInfo = 2
local logInfoTag = "[INFO]"
M.logWarn = 3
local logWarnTag = "[WARN]"

--Helper to write log file
function M.writeLog(logType, logString)
	logFile = io.open("shanon.log", "a+")
	timestamp = os.date("%c")
	if logType == M.logError then
		logFile:write(logErrorTag .. "[" .. timestamp .. "]" .. logString .. "\n")
	elseif logType == M.logInfo then
		logFile:write(logInfoTag .. "[" .. timestamp .. "]" .. logString .. "\n")
	elseif logType == M.logWarn then
		logFile:write(logWarnTag .. "[" .. timestamp .. "]" .. logString .. "\n")
	end
	io.close(logFile)
end

--Return the module table
return M