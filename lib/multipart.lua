local find = string.find
local sub = string.sub
local re_match = ngx.re.match
local re_find = ngx.re.find

function ReadFileHelper(str)
	 if type(str)~='string' then return str end
	 local res = string.gsub(str, "\r", "")
	 res = string.gsub(res, "\n", "")
    return res
end


local _M = {}
local mt = { __index = _M }
local match_table = {}

local function get_boundary_infos(boundary)
   for i = 1, #boundary do
      local byte = boundary:byte(i)
      if byte == 44 or byte==59 then
         return boundary:sub(1, i - 1)
      end
   end
   return boundary
end

local function get_boundary(header)
   if type(header) == "table" then
       header = header[1]
   end
   
   local fr, to = find(header, "multipart/form-data; boundary=", 1, true)
   if not fr then
       return ""
   end
   local boundary=sub(header, to + 1)
   --参考:https://github.com/php/php-src/blob/3351daee6199872378af573ef4c5e1787ddb5396/main/rfc1867.c#L651
   if boundary:byte(1)==34 then 
      local end_fo = find(boundary, '"', 2, true)
      if end_fo then
         boundary = sub(boundary, 2, end_fo - 1)
      else 
         boundary=get_boundary_infos(boundary)
      end
   else 
      boundary=get_boundary_infos(boundary)
   end 
   return  boundary
end


function _M.new(body, content_type)
   if not content_type then
       return nil, "no Content-Type header specified"
   end
   local boundary = get_boundary(content_type)
   return setmetatable({
      start = 1,
      boundary = "--" .. boundary,
      boundary2 = "\r\n--" .. boundary,
      body = body,
   }, mt)
end


function _M.parse_part(self)
   local start = self.start
   local body = self.body
   if start == 1 then
      local fr, to = find(body, self.boundary, 1, true)
      if not fr then
         return nil
      end
      -- ignore the preamble
      start = to + 1
   end
   -- parse headers
   local fr, to = find(body, "\r\n\r\n", start, true)
   if not fr then
      self.start = start
      return nil, "missing header"
   end
   

   local header = sub(body, start, fr + 2)
   local header_data
   header_data =header
   
   start = to + 1

   -- parse the "name" parameter:
   match_table[1] = nil
   match_table[2] = nil
   local m, err = re_match(header,
           [[^Content-Disposition:.*?;\s*name\s*=\s*(?:"([^"]+)"|([-'\w]+))]],
                           "joim", nil, match_table)
   local name
   if m then
      name = m[1] or m[2]
   end
   m, err = re_match(header,
        [[^Content-Disposition:.*?;\s*filename\s*=\s*(?:"?([^"]+)"?|([-'\w]+))]],
                           "joim", nil, match_table)
   local filename
   if m then
      filename = m[1] or m[2]
   end
   local is_filename
   if not is_filename then
      is_filename = ReadFileHelper(header)
   end

   -- parse the MIME type:
   local fr, to = re_find(header, [[^Content-Type:\s*([^;\s]+)]], "joim",
                          nil, 1)
   local mime
   if fr then
      mime = sub(header, fr, to)
   end

   -- find delimiter:
   fr, to = find(body, self.boundary2, start, true)
   if not fr then
      self.start = start
      return nil
   end
   
   local part_body = sub(body, start, fr - 1)


   self.start = to + 3
   if filename==nil and re_find(header_data,"filename=") then 
       filename="is_filename"
   end 
   return part_body, name, mime, filename,is_filename,header_data
end

return _M