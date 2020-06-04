--Functions for ICMPv6

--Module table
local ICMPv6={}

ICMPv6.type = Field.new("icmpv6.type")
ICMPv6.code = Field.new("icmpv6.code")
ICMPv6.checksum = Field.new("icmpv6.checksum")
--The rest of the fields will have to be processed individually, it seems
--This includes NDP

--Return the module table
return ICMPv6