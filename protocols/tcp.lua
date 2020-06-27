--Functions for TCP

--Our libraries
local libAnonLua = require "libAnonLua"
local shanonHelpers = require "shanonHelpers"

--Module table
local TCP={}

--Relative stack position is used to determine which of many possible instances of this protocol is being processed
relativeStackPosition = 1

TCP.srcport = Field.new("tcp.srcport")
TCP.dstport = Field.new("tcp.dstport")
TCP.seq = Field.new("tcp.seq")
TCP.ack = Field.new("tcp.ack")
TCP.offset_reserved_flags = Field.new("tcp.flags") --No clear byte boundary, tcp.flags captures the whole 2 bytes
TCP.window = Field.new("tcp.window_size")
TCP.checksum = Field.new("tcp.checksum")
TCP.urgent = Field.new("tcp.urgent_pointer")
TCP.payload = Field.new("tcp.payload") --The higher layer protocol data

--The TCP header length is part of the TCP.offset_reserved_flags block that is fetched from the tcp.flags field
--This field is separated here because it is used to fetch a number value used for calculating the boundaries
--of this instance of TCP for the purposes of processing TCP options in situations where there are multiple instances
--of TCP in a protocol chain
TCP.headerLength = Field.new("tcp.hdr_len")

--TCP Options
TCP.OPT = {}
TCP.OPT.Kind = Field.new("tcp.option_kind")
--End of Options and No Operation options just have a kind field
--We'll ignore them when processing, but may need to add some to the end for padding purposes
TCP.OPT.NOP = {}
TCP.OPT.NOP.Kind = ByteArray.new("01"):raw()
TCP.OPT.EOP = {}
TCP.OPT.EOP.Kind = ByteArray.new("00"):raw()
--Maximum Segment Size
TCP.OPT.MSS = {}
TCP.OPT.MSS.Length = ByteArray.new("04"):raw() --The length value of this option
TCP.OPT.MSS.MSS = Field.new("tcp.options.mss_val")
--Window Scale
TCP.OPT.WS = {}
TCP.OPT.WS.Length = ByteArray.new("03"):raw() --The length value of this option
TCP.OPT.WS.Shift = Field.new("tcp.options.wscale.shift")
--Timestamp
TCP.OPT.TS = {}
TCP.OPT.TS.Length = ByteArray.new("0A"):raw() -- The length value of this option
TCP.OPT.TS.TSVal = Field.new("tcp.options.timestamp.tsval")
TCP.OPT.TS.TSEcho = Field.new("tcp.options.timestamp.tsecr")
--SACK Permitted
TCP.OPT.SACKPERM = {}
--SACK Permitted is interesting because it has a length although it only has a kind field and
--thus doesn't need a length. Perhaps this was intended for future revisions, but right now it 
--looks like an oversight.
TCP.OPT.SACKPERM.Length = ByteArray.new("02"):raw() -- The length value of this option
--SACK
TCP.OPT.SACK = {}
TCP.OPT.SACK.BlockCount = 1 --Count of SACK blocks in the SACK
--SACK Length will have to be calculated based on 
TCP.OPT.SACK.LE = Field.new("tcp.options.sack_le") --Left edge of a SACK block
TCP.OPT.SACK.RE = Field.new("tcp.options.sack_re") --Right edge of a SACK block

function TCP.anonymize(tvb, protocolList, currentPosition, previousLayerHeader, anonymizationPolicy)
   
    
    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = TCP.relativeStackPosition
    TCP.relativeStackPosition = TCP.relativeStackPosition - 1

    --Get fields
    local tcpSrcPort = shanonHelpers.getRaw(tvb, TCP.srcport, relativeStackPosition)
    local tcpDstPort = shanonHelpers.getRaw(tvb, TCP.dstport, relativeStackPosition)
    local tcpSeq = shanonHelpers.getRaw(tvb, TCP.seq, relativeStackPosition)
    local tcpAck = shanonHelpers.getRaw(tvb, TCP.ack, relativeStackPosition)
    local tcpOffsetReservedFlags = shanonHelpers.getRaw(tvb, TCP.offset_reserved_flags, relativeStackPosition)
    local tcpWindow = shanonHelpers.getRaw(tvb, TCP.window, relativeStackPosition)
    local tcpChecksum = shanonHelpers.getRaw(tvb, TCP.checksum, relativeStackPosition)
    local tcpUrgent = shanonHelpers.getRaw(tvb, TCP.urgent, relativeStackPosition)

    --TODO: Get TCP payload if no lower layer data is provided

    --Anonymized fields. Logical separation so non-anonymized data never makes it into file
    local tcpSrcPortAnon
    local tcpDstPortAnon
    local tcpSeqAnon
    local tcpAckAnon
    local tcpOffsetReservedFlagsAnon
    local tcpWindowAnon
    local tcpChecksumAnon
    local tcpUrgentAnon
    
    --TODO: Payload anon 

    --Anonymize stuff here
    tcpSrcPortAnon = tcpSrcPort
    tcpDstPortAnon = tcpDstPort
    tcpSeqAnon = tcpSeq
    tcpAckAnon = tcpAck
    tcpOffsetReservedFlagsAnon = tcpOffsetReservedFlags
    tcpWindowAnon = tcpWindow
    tcpChecksumAnon = tcpChecksum
    tcpUrgentAnon = tcpUrgent

    --Handle options
    local tcpOffsetCalculated
    local tcpOptions
    tcpOffsetCalculated, tcpOptions = handleOptions(tvb, relativeStackPosition)

    --Get the original offset. These are raw bits
    local tcpOffsetOrg = tcpOffsetReservedFlags:sub(1,1)
    --Turn it into a number by getting the decimal equivalent
    local tcpOffsetOrgByte = tcpOffsetOrg:byte(1)
    --The rest of division by 16 is the lower 4 bits
    local tcpOffsetOrgByteLowerHalf = tcpOffsetOrgByte % 16 
    --Add tcpOffsetCalculated multiplied by 16, this shifts it 4 bits to the left
    local tcpOffsetValueFinal = tcpOffsetOrgByteLowerHalf + tcpOffsetCalculated * 16
    --Transform this into a single byte
    local tcpOffsetValueFinalByte = ByteArray.new(string.format("%02X", tcpOffsetValueFinal)):raw()
    --Replace the 1st byte of tcpOffsetReservedFlagsAnon with the new value
    tcpOffsetReservedFlagsAnon = tcpOffsetValueFinalByte .. tcpOffsetReservedFlagsAnon:sub(2)

    --Return the anonymization result
    local tcpHeader = tcpSrcPortAnon .. tcpDstPortAnon .. tcpSeqAnon .. tcpAckAnon .. tcpOffsetReservedFlagsAnon 
    tcpHeader = tcpHeader .. tcpWindowAnon .. tcpChecksumAnon .. tcpUrgentAnon .. tcpOptions

    return tcpHeader
end

function handleOptions(tvb, relativeStackPosition)

    --Get list of present options
    local tcpOptionKinds = { TCP.OPT.Kind() }

    --Get the start of this instance of TCP in the protocol chain
    local tcpSrcPorts = { TCP.srcport() }
    local tcpInstanceStart = tcpSrcPorts[relativeStackPosition].offset

    --Get the end of this instance of TCP in the protocol chain
    local tcpHeaderLengths = { TCP.headerLength() }
    local tcpInstanceHeaderLength = tcpHeaderLengths[relativeStackPosition].value
    --The last byte of this instance of TCP is HeaderLength - 1 away from the start value because it counts the start byte
    local tcpInstanceEnd = tcpInstanceStart + tcpInstanceHeaderLength - 1
    

    --This is where we dump the option data
    local optionData = "" 

    for i, kind in ipairs(tcpOptionKinds) do

        if kind.offset < tcpInstanceStart then
            --We're processing options before this instance of TCP, skip it
            --Do nothing here
        elseif kind.offset > tcpInstanceEnd then
            --We've reached an option beyond this instance of TCP, time to break the loop
            break
        elseif kind.value == 0 then
            --End of Options
            --Won't be processed
        elseif kind.value == 1 then
            --No Operation
            --Won't be processed
        elseif kind.value == 2 then
            --Maximum Segment Size

            --Get fields
            local mssKind = shanonHelpers.getRaw(tvb, TCP.OPT.Kind, i)
            local mssLength = TCP.OPT.MSS.Length
            
            --Check if value within offset and grab first one that is
            --We expect only one of each TCP option
            local mssValueCount
            local mssValues
            mssValueCount, mssValues = shanonHelpers.getAllWithinBoundariesRaw(tvb, TCP.OPT.MSS.MSS, tcpInstanceStart, tcpInstanceEnd)

            --There should be only 1 of this option. If there are more, we got a problem
            if mssValueCount > 1 then
                error("Error parsing TCP option Maximum Segment Size. Expected 1 option, but found " .. mssValueCount)
            end

            local mssValue = mssValues[1] --Only 1 value expected

            --Anonymized fields
            local mssKindAnon
            local mssLengthAnon
            local mssValueAnon

            --Anonymize fields
            mssKindAnon = mssKind
            mssLengthAnon = mssLength
            mssValueAnon = mssValue

            --Add to Option Data
            optionData = optionData .. mssKindAnon .. mssLengthAnon .. mssValueAnon

        elseif kind.value == 3 then
            --Window Scale
            
            --Get fields
            local wsKind = shanonHelpers.getRaw(tvb, TCP.OPT.Kind, i)
            local wsLength = TCP.OPT.WS.Length

            --Check if value within offset and grab first one that is
            --We expect only one of each TCP option
            local wsShiftCount
            local wsShiftValues
            wsShiftCount, wsShiftValues = shanonHelpers.getAllWithinBoundariesRaw(tvb, TCP.OPT.WS.Shift, tcpInstanceStart, tcpInstanceEnd)

            --There should only be one of this option. If there are more, we got a problem
            if wsShiftCount > 1 then
                error("Error parsing TCP option Window Scale. Expected 1 option, but found " .. wsShiftCount)
            end

            local wsShift = wsShiftValues[1] --Only 1 value expected

            --Anonymized fields
            local wsKindAnon
            local wsLengthAnon
            local wsShiftAnon

            --Anonymize fields
            wsKindAnon = wsKind
            wsLengthAnon = wsLength
            wsShiftAnon = wsShift

            --Add to Option Data
            optionData = optionData .. wsKindAnon .. wsLengthAnon .. wsShiftAnon

        elseif kind.value == 4 then
            --SACK Permitted
            
            --Get fields
            local spKind = shanonHelpers.getRaw(tvb, TCP.OPT.Kind, i)
            local spLength = TCP.OPT.SACKPERM.Length
            --SACK Permitted has a length field despite the option having no data
            --This seems to be an oversight in the RFC

            --Anonymized fields
            local spKindAnon
            local spLengthAnon

            --Anonymize fields
            spKindAnon = spKind
            spLengthAnon = spLength

            --Add to Option Data
            optionData = optionData .. spKindAnon .. spLengthAnon

        elseif kind.value == 5 then
            --SACK
            
            --Get fields
            local sackKind = shanonHelpers.getRaw(tvb, TCP.OPT.Kind, i)
            -- SACK Length will have to be calculated from the sack edges
            -- Getting the edges here requires some finesse
            local sackLECount
            local sackLE
            local sackRECount
            local sackRE

            local sackPayload = ""

            --Get all SACK left edges and right edges in this TCP header
            sackLECount, sackLE = shanonHelpers.getAllWithinBoundariesRaw(tvb, TCP.OPT.SACK.LE, tcpInstanceStart, tcpInstanceEnd)
            sackRECount, sackRE = shanonHelpers.getAllWithinBoundariesRaw(tvb, TCP.OPT.SACK.RE, tcpInstanceStart, tcpInstanceEnd)

            if sackLECount ~= sackRECount then
                error("Error parsing TCP option Selective Acknowledgment. Uneven number of left and right block edges. LE/RE: " .. sackLECount .. "/" .. sackRECount)
            end

            for i=1,sackLECount do
                --Anonymized fields
                local sackLEAnon
                local sackREAnon

                --Anonymize fields
                sackLEAnon = sackLE[i]
                sackREAnon = sackRE[i]

                --Add to payload
                sackPayload = sackPayload .. sackLEAnon .. sackREAnon
            end

            --Calculate length
            local sackLength = ByteArray.new(string.format("%02X", (sackPayload:len() + 2))):raw()

            --Anonymized fields
            local sackKindAnon
            local sackLengthAnon
            local sackPayloadAnon

            --Anonymize fields
            sackKindAnon = sackKind
            sackLengthAnon = sackLength
            sackPayloadAnon = sackPayload

            --Add to Option Data
            optionData = optionData .. sackKindAnon .. sackLengthAnon .. sackPayloadAnon


        elseif kind.value == 8 then
            --Timestamp
            
            --Get Fields
            local tsKind = shanonHelpers.getRaw(tvb, TCP.OPT.Kind, i)
            local tsLength = TCP.OPT.TS.Length

            --Get the option values within this header
            local tsValCount
            local tsValues
            tsValCount, tsValues = shanonHelpers.getAllWithinBoundariesRaw(tvb, TCP.OPT.TS.TSVal, tcpInstanceStart, tcpInstanceEnd)

            local tsEchoCount
            local tsEchoes
            tsEchoCount, tsEchoes = shanonHelpers.getAllWithinBoundariesRaw(tvb, TCP.OPT.TS.TSEcho, tcpInstanceStart, tcpInstanceEnd)

            --If multiple show up throw an error
            if tsValCount > 1 then
                error("Error parsing TCP option Timestamp. Expected 1 Timestamp Value, but found: " .. tsValCount)
            end

            if tsEchoCount > 1 then
                error("Error parsing TCP option Timestamp. Expected 1 Timestamp Echo Value, but found: " .. tsEchoCount)
            end

            --Get the expected single values
            local tsVal = tsValues[1]
            local tsEcho = tsEchoes[1]

            --Anonymized Fields
            local tsKindAnon
            local tsLengthAnon
            local tsValAnon
            local tsEchoAnon

            --Anonymize fields
            tsKindAnon = tsKind
            tsLengthAnon = tsLength
            tsValAnon = tsVal
            tsEchoAnon = tsEcho

            --Add to Option Data
            optionData = optionData .. tsKindAnon .. tsLengthAnon .. tsValAnon .. tsEchoAnon

        end

    end

    --Check that options are long enough for TCP Data Offset to be a round number
    --If not, add a EOP option and padding
    local optionsLength = optionData:len()
    local tcpLength = 20 + optionsLength --Add 20 bytes of TCP header
    local tcpRest = 4 - (tcpLength % 4)

    --Add No Option options
    while tcpRest > 1 do
        optionData = optionData .. TCP.OPT.NOP.Kind
        tcpRest = tcpRest - 1
    end
    --Add EOP option
    --Still needs an if because tcpRest might be 0 in which case neither of these options should execute
    if tcpRest == 1 then
        optionData = optionData .. TCP.OPT.EOP.Kind
    end

    --Return values: 
    --1) The value that should be in the Data Offset field based on a known TCP header length
    --2) The option data
    --Just returning what we calculated and put together shouldn't be a problem
    --If there are no options tcpDataOffset is 5 and optionData is an empty string

    local tcpDataOffset = (optionData:len() + 20) / 4

    return tcpDataOffset, optionData

end

--Return the module table
return TCP