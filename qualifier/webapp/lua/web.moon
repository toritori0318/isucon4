lapis = require "lapis"
db = require "lapis.db"
import config from require "lapis.config"
import insert from table
import respond_to from require "lapis.application"

inspect = require('inspect')
resty_sha256 = require "resty.sha256"
str = require "resty.string"

user_lock_threshold = os.getenv("ISU4_USER_LOCK_THRESHOLD") or 3
ip_ban_threshold = os.getenv("ISU4_IP_BAN_THRESHOLD") or 10


calculate_password_hash = (password, salt) ->
  sha256 = resty_sha256\new()
  sha256\update(password .. ':' .. salt)
  return str.to_hex(sha256\final())


login_log = (succeeded, login, user_id) ->
  user_id = user_id or ''

  succeeded_flg = 0
  if succeeded
    succeeded_flg = 1
  ip_address = ngx.var.http_x_forwarded_for or ngx.var.remote_addr
  res = db.query("INSERT INTO login_log (`created_at`,`user_id`, `login`, `ip`, `succeeded`) VALUES (NOW(),?,?,?,?)", user_id, login, ip_address, succeeded_flg) or {}

user_locked = (user) ->
  if not user
    return

  user_id = user['id']
  res = db.query("SELECT COUNT(1) AS failures FROM login_log WHERE user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0);", user_id, user_id) or {}
  failures = tonumber(res[1]['failures']) or 0

  return user_lock_threshold <= failures


ip_banned = (login, password) ->
  ip_address = ngx.var.http_x_forwarded_for or ngx.var.remote_addr
  res = db.query("SELECT COUNT(1) AS failures FROM login_log WHERE ip = ? AND id > IFNULL((select id from login_log where ip = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)", ip_address, ip_address ) or {}

  failures = tonumber(res[1]['failures']) or 0
  return ip_ban_threshold <= failures


attempt_login = (login, password) ->

  res = db.query("SELECT * FROM users WHERE login=?", login) or {}
  user = res[1]

  if ip_banned()
    if user
      login_log(false, login, user['id'])
    else
      login_log(false, login)
    return null, 'banned'

  if user_locked(user)
    login_log(false, login, user['id'])
    return null, 'locked'

  if user and calculate_password_hash(password, user['salt']) == user['password_hash']
    login_log(true, login, user['id'])
    return user, null
  elseif user
    login_log(false, login, user['id'])
    return null, 'wrong_password'
  else
    login_log(false, login)
    return null, 'wrong_login'


current_user = (user_id) ->
  if not user_id
    return

  res = db.query("SELECT * FROM users WHERE id=?", user_id) or {}
  user = res[1]
  if user
    return user
  else
    return


last_login = (user_id) ->
  user = current_user(user_id)
  if not user
    return

  res = db.query("SELECT * FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2", user_id) or {}
  maxn = table.maxn(res)
  last = res[maxn]
  return last


banned_ips = () ->
  threshold = ip_ban_threshold

  not_succeeded = db.query("SELECT ip FROM (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?", threshold) or {}

  ips = {}
  for i, row in ipairs not_succeeded
    table.insert(ips, row['ip'])

  last_succeeds = db.query("SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip") or {}

  for i, row in ipairs last_succeeds
    ip = row['ip']
    last_login_id = row['last_login_id']
    res = db.query("SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id", ip, last_login_id) or {}

    count = res[1]['cnt'] or 0
    if threshold <= tonumber(count)
      table.insert(ips, row['ip'])

  return ips


locked_users = () ->
  threshold = user_lock_threshold

  not_succeeded = db.query("SELECT user_id, login FROM (SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?", threshold) or {}

  ips = {}
  for i, row in ipairs not_succeeded
    table.insert(ips, row['login'])

  last_succeeds = db.query("SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id") or {}

  for i, row in ipairs last_succeeds
    user_id = row['user_id']
    last_login_id = row['last_login_id']
    res = db.query("SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id", user_id, last_login_id) or {}

    count = res[1]['cnt'] or 0
    if threshold <= tonumber(count)
      table.insert(ips, row['login'])

  return ips


class Isucon4 extends lapis.Application
  @enable "etlua"
  [index: "/"]: =>
    render: "index", layout: "mylayout"

  "/login": respond_to {
    POST: =>
      login = @params.login
      password = @params.password
      user, err = attempt_login(login, password)
      if user
          @session.user_id = user['id']
          redirect_to: @url_for "mypage", status: 301

      else
          if err == "locked"
              @session.flash = 'This account is locked.'
          elseif err == "banned"
              @session.flash = "You're banned."
          else
              @session.flash = "Wrong username or password"
          redirect_to: @url_for "index", status: 301
  }

  @enable "etlua"
  [mypage: "/mypage"]: =>
    user_id = @session.user_id
    user = current_user(user_id)
    if user
        @user=user
        @last_login=last_login(user_id) or {}
        render: "mypage", layout: "mylayout"
    else
        @session.flash = 'You must be logged in'
        redirect_to: @url_for "index", status: 301

  "/report": =>
    json: {banned_ips: banned_ips(), locked_users: locked_users() }
