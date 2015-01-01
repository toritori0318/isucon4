local config
do
  local _obj_0 = require("lapis.config")
  config = _obj_0.config
end
config("development", function() end)
return config("production", function()
  port(8080)
  return mysql({
    backend("resty_mysql"),
    database = "isu4_qualifier",
    user = "root",
    password = "",
    host = "127.0.0.1",
    port = "3306"
  })
end)
