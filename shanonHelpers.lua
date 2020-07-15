
-- Helpers Lua module with functions used by shanon.lua

--Module table
local M = {}

--We need our library here as well
local libAnonLua = require "libAnonLua"

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

--Warning that an anonymization policy is missing
function M.warnMissingPolicy(protocolName)
	M.writeLog(M.logWarn, "Anonymization policy for " .. protocolName .. " not found. Using default!")
end

--Warning that a specific policy option is missing and defaults will be used
function M.warnUsingDefaultOption(protocolName, fieldName, defaultValue)
	if type(defaultValue) ~= "string" then 
		defaultValue = "This default is a table and can not be printed neatly. Please look it up in the documentation!"
	end
		M.writeLog(M.logWarn, "Invalid or missing anonymization option \"" .. fieldName .. "\" for " .. protocolName .. "! Using default: " .. defaultValue) 
end

--Helper to generate a zero payload of a specific length
--Naive algorithm, but we don't predict having to do this for megabytes of infomation
function M.generateZeroPayload(lengthBytes)
	zeroByte = ByteArray.new("00"):raw()
	result = ""
	while(lengthBytes~=0) do
		result = result .. zeroByte
		lengthBytes = lengthBytes - 1
	end
	return result
end

--Helper to get the length of a string as a number of bytes
function M.getLengthAsBytes(string, byteCount, addToLength)

	local length = 0
	local zeroByte = ByteArray.new("00"):raw()

	if string ~= nil then 
		length = string:len()
	else
		length = 0
	end

	--If we need to add a fixed amount of bytes to length, such as when we have a known-lenght header being added on top of a payload
	if addToLength ~= nil then 
		length = length + addToLength
	end

	--Get length as a hex value
	local lengthHex = string.format("%x", length)

	--Check if the hex value has an even number of digits and add a 0 to the start if not
	if lengthHex:len() % 2 ~= 0 then 
		lengthHex = "0" .. lengthHex
	end

	--Length as an array of bytes
	local lengthBytes = ByteArray.new(lengthHex):raw()

	--Check if lengthBytes is long enough and if not add bytes to the start
	--If it's longer we have an error
	if lengthBytes:len() > byteCount then 
		error("Error recalculating length. Length takes up more bytes than the provided expected length. Bytes generated: " .. lengthBytes:len() .. "Bytes expected: " .. byteCount)
	else 
		local difference = byteCount - lengthBytes:len()
		while difference > 0 do
			lengthBytes = zeroByte .. lengthBytes
			difference = difference - 1
		end
	end

	return lengthBytes
end

--Helper to turn SetValue_number values into bytes
function M.getSetValueBytes(setValueString, byteCount)
	
	local zeroByte = ByteArray.new("00"):raw()

	--Split the setValueString into substrings
	local setValueParameters, parameterCount = M.split(setValueString, "_")

	local numberString = setValueParameters[2]

	local numberValue = tonumber(numberString)

	--Just a precaution. This should never happen because we validate the SetValue options with a lua expression when validating the config
	if numberValue == nil then
		numberValue = 0
		M.writeLog(M.logError, "Error in function getSetValueBytes in shanonHelpers. Function tonumber returned nil when converting string to number. This is a bug in Shanon itself.")
	end

	--Get number value as hex
	local numberValueHex = string.format("%x", numberValue)

	--Check if the hex value has an even number of digits and add a 0 to the start if not
	if numberValueHex:len() % 2 ~= 0 then 
		numberValueHex = "0" .. numberValueHex
	end

	--Number value as an array of bytes
	local numberValueBytes = ByteArray.new(numberValueHex):raw()

	--Check if we ended up with enough bytes
	if numberValueBytes:len() > byteCount then 
		error("Error converting SetValue option to byte array for insertion into protocol field. Conversion of numerical value produced " .. numberValueBytes:len() .. " bytes, but " .. byteCount .. "expected.")
	else 
		local difference = byteCount - numberValueBytes:len()
		while difference > 0 do
			numberValueBytes = zeroByte .. numberValueBytes
			difference = difference - 1
		end
	end

	return numberValueBytes
end

--Helpers for dealing with the config file

--Get the config file path
function M.configGetOutputPath(config)
	if config ~= nil and config.outputFile ~= nil then 
		return config.outputFile
	else
		M.writeLog(M.logWarn, "No output file path provided in config, file will be stored in same folder as Shanon with the prefix shanon_output_ and the current date and time.")
		return "shanon_output_" .. os.date("%d_%b_%Y_%H_%M") .. ".pcapng"
	end
end

--Get the CryptoPAN key file
function M.configGetCryptoPANKeyFile(config)
	if config ~=nil and config.cryptoPANKeyFile ~= nil then
		return config.cryptoPANKeyFile
	else 
		M.writeLog(M.logWarn, "No CryptoPAN key file path provided in config, file will be stored in same folder as Shanon with the prefix shanon_cyrptoPAN_key and the current date and time.")
		return "shanon_cryptoPAN_key_" .. os.date("%d_%b_%Y_%H_%M") .. ".key"
	end
end


--Parse a black marker string and return the direction and length
--This function does not validate the string so it needs to be validated first
function M.getBlackMarkerValues(blackMarkerString)

	--Split the black marker into substrings
	local blackMarkerParameters, parameterCount = M.split(blackMarkerString, "_")

	local blackMarkerDirection
	local blackMarkerLength

	if blackMarkerParameters[2] == "MSB" then 
		blackMarkerDirection = libAnonLua.black_marker_MSB
	else 
		blackMarkerDirection = libAnonLua.black_marker_LSB
	end

	blackMarkerLength = tonumber(blackMarkerParameters[3])

	return blackMarkerDirection, blackMarkerLength

end

--Return the module table
return M