import config from require "lapis.config"

config "development", ->

config "production", ->
  port 8080
  -- num_workers 4
  -- lua_code_cache "on"
  mysql {
    backend "resty_mysql"
    database: "isu4_qualifier"
    user: "root"
    password: ""
    host: "127.0.0.1"
    port: "3306"
  }
