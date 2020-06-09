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
TCP.offset_reserved_flags = Field.new("tcp.hdr_len") --No clear byte boundary  
TCP.window = Field.new("tcp.window_size")
TCP.checksum = Field.new("tcp.checksum")
TCP.urgent = Field.new("tcp.urgent_pointer")
--TODO: Support options

function TCP.anonymize(tvb, protocolList, currentPosition, previousLayerHeader, anonymizationPolicy)
   
    
    --Create a local relativeStackPosition and decrement the main
    --That way if any weird behaviour occurs the rest of execution isn't neccessarily compromised
    local relativeStackPosition = TCP.relativeStackPosition
    TCP.relativeStackPosition = TCP.relativeStackPosition - 1

    
end

--Return the module table
return TCP