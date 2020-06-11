
-- Helpers Lua module with functions used by shanon.lua

--Module table
local M = {}

--Helper to get raw bytes
--When multiple of the same field are present the field extractor returns a table
--The relativeStackPosition value is used to determine which of the fields to get
--This can happen when multiple same options are present OR multiple of the same protocol
function M.getRaw(tvb, fieldExtractor, relativeStackPosition)
	local fieldInfo = { fieldExtractor() }
	if fieldInfo[relativeStackPosition] == nil then
		error("Error getting field " .. fieldExtractor.name .. " in the " .. relativeStackPosition .. ". instance of this protocol in the chain.")
	end
	return tvb:range(fieldInfo[relativeStackPosition].offset,fieldInfo[relativeStackPosition].len):bytes():raw()
end

--Get length bytes following a particular field
function M.getBytesAfterField(tvb, fieldExtractor, relativeStackPosition, length)
	local fieldInfo = { fieldExtractor() }
	if fieldInfo[relativeStackPosition] == nil then
		error("Error getting " .. length .. " bytes after field: " .. fieldExtractor.name .. " in the " .. relativeStackPosition .. ". instance of this protocol in the chain.")
	end
	return tvb:range(fieldInfo[relativeStackPosition].offset + fieldInfo[relativeStackPosition].len, length):bytes():raw()
end

--Get length bytes at an offset from a particular field
function M.getBytesAfterFieldWithOffset(tvb, fieldExtractor, relativeStackPosition, offset, length)
	local fieldInfo = { fieldExtractor() }
	if fieldInfo[relativeStackPosition] == nil then
		error("Error getting " .. length .. " bytes at offset " .. offset ..  " bytes from end of field: " .. fieldExtractor.name .. " in the " .. relativeStackPosition .. ". instance of this protocol in the chain.")
	end
	return tvb:range(fieldInfo[relativeStackPosition].offset + fieldInfo[relativeStackPosition].len + offset, length):bytes():raw()
end

--Helper to get remaining data
function M.getRest(tvb, fieldExtractor, relativeStackPosition)
	local fieldInfo = { fieldExtractor() }
	if fieldInfo[relativeStackPosition] == nil then
		error("Error getting remainder of payload after field: " .. fieldExtractor.name .. " in the " .. relativeStackPosition .. ". instance of this protocol in the chain.")
	end
	return tvb:range(fieldInfo[relativeStackPosition].offset + fieldInfo[relativeStackPosition].len):bytes():raw()
end

--Helper to get rest from specific offset
function M.getRestFromOffset(tvb, offset)
	--Get all the data past the offset
	return tvb:range(offset):bytes():raw()
end

--Helper to split strings
function M.split(inputString, delimiter)
	local result = {}
	local tableLength = 0
	for match in (inputString..delimiter):gmatch("(.-)"..delimiter) do
		table.insert(result, match)
		tableLength = tableLength + 1
	end
	return result, tableLength
end

--Helper to count occurences of protocol in table
function M.countOccurences(inputTable, tableSize, protocolName)
	local count = 0
	for i=1,tableSize do
		if inputTable[i] == protocolName then
			count = count + 1
		end
	end
	return count
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