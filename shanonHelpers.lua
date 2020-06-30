
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

--Get all fields of a type within the provided boundaries. If expectedCount is provided, throw error if count doesn't match
function M.getAllWithinBoundariesRaw(tvb, fieldExtractor, leftBoundary, rightBoundary, expectedCount)
	local fieldInfo = { fieldExtractor() }
	local count = 0
	local extractedValues = {}
	for j, value in ipairs(fieldInfo) do
		if value.offset > leftBoundary and value.offset <= rightBoundary then
			count = count + 1
			extractedValues[count] = M.getRaw(tvb, fieldExtractor, j)
		elseif value.offset > rightBoundary then 
			break
		end
	end

	if expectedCount ~= nil then
		if expectedCount ~= count then
			error("Error extracting field: " .. fieldExtractor.name .. "Expected " .. expectedCount .. " fields of this type but encountered " .. count)
		end
	end

	return count, extractedValues
end

--Get length bytes after each field of the provided type within boundaries
--If expectedCount is provided, throw error if count doesn't match
function M.getBytesAfterFieldWithinBoundariesRaw(tvb, fieldExtractor, leftBoundary, rightBoundary, length, expectedCount)
	local fieldInfo = { fieldExtractor() }
	local count = 0
	local extractedValues = {}
	for j, value in ipairs(fieldInfo) do
		local offset = value.offset + value.len
		if offset > leftBoundary and offset <= rightBoundary then
			count = count + 1
			extractedValues[count] = tvb:range(offset, length):bytes():raw()
		elseif offset > rightBoundary then 
			break
		end
	end

	if expectedCount ~= nil then
		if expectedCount ~= count then
			error("Error extracting bytes after field: " .. fieldExtractor.name .. "Expected " .. expectedCount .. " fields of this type but encountered " .. count)
		end
	end

	return count, extractedValues
end

--Get length bytes BEFORE each field of the provided type within boundaries
--If expectedCount is provided, throw error if count doesn't match
function M.getBytesBeforeFieldWithinBoundariesRaw(tvb, fieldExtractor, leftBoundary, rightBoundary, length, offset, expectedCount)
	local fieldInfo = { fieldExtractor() }
	local count = 0
	local extractedValues = {}
	for j, value in ipairs(fieldInfo) do
		local fieldStart = value.offset - offset
		if fieldStart > leftBoundary and fieldStart <= rightBoundary then
			count = count + 1
			extractedValues[count] = tvb:range(fieldStart, length):bytes():raw()
		elseif fieldStart > rightBoundary then 
			break
		end
	end

	if expectedCount ~= nil then
		if expectedCount ~= count then
			error("Error extracting bytes before field: " .. fieldExtractor.name .. "Expected " .. expectedCount .. " fields of this type but encountered " .. count)
		end
	end

	return count, extractedValues
end

--Get the 1st field within the provided boundaries and throw an error if more than 1
function M.getOnlyOneWithinBoundariesRaw(tvb, fieldExtractor, leftBoundary, rightBoundary)
	local count
	local fields

	count, fields = M.getAllWithinBoundariesRaw(tvb, fieldExtractor, leftBoundary, rightBoundary)

	if count > 1 then
		error("Error getting field: " .. fieldExtractor.name .. ". Expected 1, found: " .. count)
	end

	return fields[1]
end

--Get length bytes or all if length=nil remaining data after a single field within the provided boundaries. Throw an error if more than 1 field is present
function M.getBytesAfterOnlyOneWithinBoundaries(tvb, fieldExtractor, leftBoundary, rightBoundary, length)
	local fieldInfo = { fieldExtractor() }
	local count = 0
	local offsets = {}
	for j, value in ipairs(fieldInfo) do
		if value.offset > leftBoundary and value.offset <= rightBoundary then
			count = count + 1
			offsets[count] = value.offset + value.len
		elseif value.offset > rightBoundary then 
			break
		end
	end

	if count > 1 then
		error("Error getting bytes after field: " .. fieldExtractor.name .. ". Expected 1 field, found: " .. count)
	end

	if length ~= nil then
		return tvb:range(offsets[1], length):bytes():raw()
	else
		return tvb:range(offsets[1]):bytes():raw()
	end
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