# After authenticating, we’re removing any session activation that may already
# exist, and creating a new session# activation. We generate our own random id
# (in User#activate_session) and store it in the auth_id key. There is already
# a session_id key, but the session gets renewed (and the session id changes)
# after authentication in order to avoid session fixation attacks. So it’s
# easier to just use our own id.

def session_key(scope)
  scope == :user ? "auth_id" : "auth_#{scope}_id"
end

Warden::Manager.after_set_user except: :fetch do |user, warden, options|
  if user.respond_to?(:deactivate_sessions)
    user.deactivate_sessions(warden.raw_session[session_key(options[:scope])])
    warden.raw_session[session_key(options[:scope])] = user.activate_session(ip: warden.request.ip,
                                                          user_agent: warden.request.user_agent)
  end
end

# After fetching a user from the session, we check that the session is marked
# as active for that user. If it’s not we log the user out.
Warden::Manager.after_fetch do |user, warden, options|
  if user.respond_to?(:session_active?) && !user.session_active?(warden.raw_session[session_key(options[:scope])])
    warden.logout
    throw :warden, message: :unauthenticated
  end
end

# When logging out, we deactivate the current session. This ensures that the
# session cookie can’t be reused afterwards.
Warden::Manager.before_logout do |user, warden, options|
  if user.respond_to?(:deactivate_sessions)
    user.deactivate_sessions(warden.raw_session[session_key(options[:scope])])
  end
end
