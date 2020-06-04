--Json library
local dkjson = require "dkjson"

--LibAnonLua, our library
local libAnonLua = require "libAnonLua"

--Helper functions separated for readability
local shanonHelpers = require "shanonHelpers"

--Anonymization policy
--TODO: Parse a file with the policy
local anonymizationPolicy = nil

--Taps and fields for the various protocols being used

--Wireshark frame
local Tap_Frame = Listener.new("frame")
--Fields
local Field_frame_protocols = Field.new("frame.protocols")
local Field_frame_number = Field.new("frame.number")

-- Ethernet
local ethernet = require "protocols.ethernet"

--ARP
local arp = require "protocols.arp"

--IPv4
local ipv4 = require "protocols.ipv4"

--IPv6 
local ipv6 = require "protocols.ipv6"

--ICMP
local icmp = require "protocols.icmp"

--ICMPv6
local icmpv6 = require "protocols.icmpv6"

--local Tap_NDP = Listener.new("ndp")
--TODO: Solve NDP

--UDP
local udp = require "protocols.udp"

--TCP
local tcp = require "protocols.tcp"

--TODO: Change filesystem file names based on config
--TODO: Verify success or failure of operations and crash script accordingly
--Create the filesystem we'll be writing to
local filesystemPath ="test_anon.pcapng"
libAnonLua.create_filesystem(filesystemPath)
libAnonLua.add_interface(filesystemPath, libAnonLua.LINKTYPE_ETHERNET)

--Function to tap into every frame
function Tap_Frame.packet(pinfo, tvb, tapinfo)
    --TODO: Remove temporary prints
    print "Frame"


    -- Frame info
    local frameNumber = Field_frame_number()

    local anonymizedFrame = "" --Create an empty anonymized frame
    local anonymizerOutput -- To temporarily hold the output of a particular anonymizer

    --Get the protocol list
    local protocolList, protocolCount = shanonHelpers.split(tostring(Field_frame_protocols()), ":")

    --TODO: Remove temporary prints
    print(Field_frame_protocols()) 

    
    --Current position in protocol stack
    local currentPosition = protocolCount

    while currentPosition ~= 0 do
        --Reset anonymizerOutput to empty string
        anonymizerOutput = ""
        if protocolList[currentPosition] == "eth" then
            anonymizerOutput  = ethernet.anonymize(tvb, protocolList, currentPosition, anonymizationPolicy) 
        elseif protocolList[currentPosition] == "ethertype" then
            --Nothing needs to be done for this. 
            --ethertype is a faux protocol that just serves to inform that Ethernet II with a type field is in use
        elseif protocolList[currentPosition] == "ip" then
            anonymizerOutput = ipv4.anonymize(tvb, protocolList, anonymizationPolicy)
        elseif protocolList[currentPosition] == "ipv6" then
            anonymizerOutput = ipv6.anonymize(tvb, protocolList, anonymizationPolicy)
        elseif protocolList[currentPosition] == "arp" then
            anonymizerOutput = arp.anonymize(tvb, protocolList, anonymizationPolicy)
        elseif protocolList[currentPosition] == "icmp" then
            anonymizerOutput = icmp.anonymize(tvb, protocolList, anonymizationPolicy)
        elseif protocolList[currentPosition] == "icmpv6" then
            anonymizerOutput = icmpv6.anonymize(tvb, protocolList, anonymizationPolicy)
        elseif protocolList[currentPosition] == "tcp" then
            --TODO: Anonymizer
        elseif protocolList[currentPosition] == "udp" then
            anonymizerOutput = udp.anonymize(tvb, protocolList, anonymizationPolicy)
        else
            --If we encounter something unknown, we simply set the anonymized frame empty again
            anonymizedFrame = ""
            --An empty frame signals to anonymizer functions that higher layer protocols should be treated as data
        end

        --Add to front of anonymized frame
        anonymizedFrame = anonymizerOutput .. anonymizedFrame
        --Always decrement the current position
        currentPosition = currentPosition - 1; 
    end

    
    --At this point we will have parsed and anonymized all protocolsP
     --We can write the anonymized frame to the capture file
    if anonymizedFrame ~= "" then
        libAnonLua.write_packet(filesystemPath, anonymizedFrame, 0) --Optional third parameter: Timestamp
    else
        --If the frame is empty we don't write it. We log it.
        --TODO: Log this!
    end


end

function calculateChecksums()

end

function writeFrame()

end