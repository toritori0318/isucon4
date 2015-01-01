local lapis = require("lapis")
local db = require("lapis.db")
local config
do
  local _obj_0 = require("lapis.config")
  config = _obj_0.config
end
local insert
do
  local _obj_0 = table
  insert = _obj_0.insert
end
local respond_to
do
  local _obj_0 = require("lapis.application")
  respond_to = _obj_0.respond_to
end
local inspect = require('inspect')
local resty_sha256 = require("resty.sha256")
local str = require("resty.string")
local user_lock_threshold = os.getenv("ISU4_USER_LOCK_THRESHOLD") or 3
local ip_ban_threshold = os.getenv("ISU4_IP_BAN_THRESHOLD") or 10
local calculate_password_hash
calculate_password_hash = function(password, salt)
  local sha256 = resty_sha256:new()
  sha256:update(password .. ':' .. salt)
  return str.to_hex(sha256:final())
end
local login_log
login_log = function(succeeded, login, user_id)
  user_id = user_id or ''
  local succeeded_flg = 0
  if succeeded then
    succeeded_flg = 1
  end
  local ip_address = ngx.var.http_x_forwarded_for or ngx.var.remote_addr
  local res = db.query("INSERT INTO login_log (`created_at`,`user_id`, `login`, `ip`, `succeeded`) VALUES (NOW(),?,?,?,?)", user_id, login, ip_address, succeeded_flg) or { }
end
local user_locked
user_locked = function(user)
  if not user then
    return
  end
  local user_id = user['id']
  local res = db.query("SELECT COUNT(1) AS failures FROM login_log WHERE user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0);", user_id, user_id) or { }
  local failures = tonumber(res[1]['failures']) or 0
  return user_lock_threshold <= failures
end
local ip_banned
ip_banned = function(login, password)
  local ip_address = ngx.var.http_x_forwarded_for or ngx.var.remote_addr
  local res = db.query("SELECT COUNT(1) AS failures FROM login_log WHERE ip = ? AND id > IFNULL((select id from login_log where ip = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)", ip_address, ip_address) or { }
  local failures = tonumber(res[1]['failures']) or 0
  return ip_ban_threshold <= failures
end
local attempt_login
attempt_login = function(login, password)
  local res = db.query("SELECT * FROM users WHERE login=?", login) or { }
  local user = res[1]
  if ip_banned() then
    if user then
      login_log(false, login, user['id'])
    else
      login_log(false, login)
    end
    return null, 'banned'
  end
  if user_locked(user) then
    login_log(false, login, user['id'])
    return null, 'locked'
  end
  if user and calculate_password_hash(password, user['salt']) == user['password_hash'] then
    login_log(true, login, user['id'])
    return user, null
  elseif user then
    login_log(false, login, user['id'])
    return null, 'wrong_password'
  else
    login_log(false, login)
    return null, 'wrong_login'
  end
end
local current_user
current_user = function(user_id)
  if not user_id then
    return
  end
  local res = db.query("SELECT * FROM users WHERE id=?", user_id) or { }
  local user = res[1]
  if user then
    return user
  else
    return
  end
end
local last_login
last_login = function(user_id)
  local user = current_user(user_id)
  if not user then
    return
  end
  local res = db.query("SELECT * FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2", user_id) or { }
  local maxn = table.maxn(res)
  local last = res[maxn]
  return last
end
local banned_ips
banned_ips = function()
  local threshold = ip_ban_threshold
  local not_succeeded = db.query("SELECT ip FROM (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?", threshold) or { }
  local ips = { }
  for i, row in ipairs(not_succeeded) do
    table.insert(ips, row['ip'])
  end
  local last_succeeds = db.query("SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip") or { }
  for i, row in ipairs(last_succeeds) do
    local ip = row['ip']
    local last_login_id = row['last_login_id']
    local res = db.query("SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id", ip, last_login_id) or { }
    local count = res[1]['cnt'] or 0
    if threshold <= tonumber(count) then
      table.insert(ips, row['ip'])
    end
  end
  return ips
end
local locked_users
locked_users = function()
  local threshold = user_lock_threshold
  local not_succeeded = db.query("SELECT user_id, login FROM (SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?", threshold) or { }
  local ips = { }
  for i, row in ipairs(not_succeeded) do
    table.insert(ips, row['login'])
  end
  local last_succeeds = db.query("SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id") or { }
  for i, row in ipairs(last_succeeds) do
    local user_id = row['user_id']
    local last_login_id = row['last_login_id']
    local res = db.query("SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id", user_id, last_login_id) or { }
    local count = res[1]['cnt'] or 0
    if threshold <= tonumber(count) then
      table.insert(ips, row['login'])
    end
  end
  return ips
end
local Isucon4
do
  local _parent_0 = lapis.Application
  local _base_0 = {
    [{
      index = "/"
    }] = function(self)
      return {
        render = "index",
        layout = "mylayout"
      }
    end,
    ["/login"] = respond_to({
      POST = function(self)
        local login = self.params.login
        local password = self.params.password
        local user, err = attempt_login(login, password)
        if user then
          self.session.user_id = user['id']
          return {
            redirect_to = self:url_for("mypage", {
              status = 301
            })
          }
        else
          if err == "locked" then
            self.session.flash = 'This account is locked.'
          elseif err == "banned" then
            self.session.flash = "You're banned."
          else
            self.session.flash = "Wrong username or password"
          end
          return {
            redirect_to = self:url_for("index", {
              status = 301
            })
          }
        end
      end
    }),
    [{
      mypage = "/mypage"
    }] = function(self)
      local user_id = self.session.user_id
      local user = current_user(user_id)
      if user then
        self.user = user
        self.last_login = last_login(user_id) or { }
        return {
          render = "mypage",
          layout = "mylayout"
        }
      else
        self.session.flash = 'You must be logged in'
        return {
          redirect_to = self:url_for("index", {
            status = 301
          })
        }
      end
    end,
    ["/report"] = function(self)
      return {
        json = {
          banned_ips = banned_ips(),
          locked_users = locked_users()
        }
      }
    end
  }
  _base_0.__index = _base_0
  setmetatable(_base_0, _parent_0.__base)
  local _class_0 = setmetatable({
    __init = function(self, ...)
      return _parent_0.__init(self, ...)
    end,
    __base = _base_0,
    __name = "Isucon4",
    __parent = _parent_0
  }, {
    __index = function(cls, name)
      local val = rawget(_base_0, name)
      if val == nil then
        return _parent_0[name]
      else
        return val
      end
    end,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  local self = _class_0
  self:enable("etlua")
  self:enable("etlua")
  if _parent_0.__inherited then
    _parent_0.__inherited(_parent_0, _class_0)
  end
  Isucon4 = _class_0
  return _class_0
end
