-- * Metronome IM *
--
-- This file is part of the Metronome XMPP server and is released under the
-- ISC License, please see the LICENSE file in this source package for more
-- information about copyright and licensing.
--
-- As per the sublicensing clause, this file is also MIT/X11 Licensed.
-- ** Copyright (c) 2010-2014, Kim Alvefur, Matthew Wild, Tobias Markmann, Waqas Hussain, Pavel Novotny


local datamanager = require "util.datamanager";
local log = require "util.logger".init("auth_custom_hashed");
local crypt = require "util.crypt";
local new_sasl = require "util.sasl".new;
local plain_test = module:require "sasl_aux".hashed_plain_test;
local scram_backend = module:require "sasl_aux".hashed_scram_backend;
local external_backend = module:require "sasl_aux".external_backend;
-- Default; can be set per-user
local iteration_count = 4096;

function new_default_provider(host)
	local provider = { name = "custom_hashed" };

	function provider.test_password(username, password)
    log("debug", "host '%s'  user '%s'  pass '%s'", host, username, password);
		local user = datamanager.user(username, host) or {};
    log("debug", "hash '%s'", user.hash);
		if password ~= nil and string.len(password) ~= 0 then
      if crypt(password, user.hash) == user.hash then
        return true;
      else
        return nil, "Auth failed. Provided password is incorrect.";
      end
    else
      return nil, "Auth failed. Provided password is empty.";
    end
	end

--	function provider.set_password(username, password)
--		local account = datamanager.load(username, host, "accounts");
--		if account then
--			account.salt = account.salt or generate_uuid();
--			account.iteration_count = account.iteration_count or iteration_count;
--			local valid, stored_key, server_key = getAuthenticationDatabaseSHA1(password, account.salt, account.iteration_count);
--			local stored_key_hex = to_hex(stored_key);
--			local server_key_hex = to_hex(server_key);
--
--			account.stored_key = stored_key_hex
--			account.server_key = server_key_hex
--
--			account.password = nil;
--			return datamanager.store(username, host, "accounts", account);
--		end
--		return nil, "Account not available.";
--	end

	function provider.user_exists(username)
		local account = datamanager.user(username, host);
		if not account then
			log("debug", "account not found for username '%s' at host '%s'", username, module.host);
			return nil, "Auth failed. Invalid username";
		end
		return true;
	end

--	function provider.create_user(username, password)
--		if password == nil then
--			return datamanager.store(username, host, "accounts", {});
--		end
--		local salt = generate_uuid();
--		local valid, stored_key, server_key = getAuthenticationDatabaseSHA1(password, salt, iteration_count);
--		local stored_key_hex = to_hex(stored_key);
--		local server_key_hex = to_hex(server_key);
--		return datamanager.store(username, host, "accounts", {stored_key = stored_key_hex, server_key = server_key_hex, salt = salt, iteration_count = iteration_count});
--	end

	function provider.delete_user(username)
		return datamanager.purge(username, host);
	end

	function provider.get_sasl_handler(session)
		local testpass_authentication_profile = {
			plain_test = plain_test,
			scram_sha_1 = scram_backend,
			external = session.secure and external_backend,
			host = module.host,
			session = session
		};
		return new_sasl(module.host, testpass_authentication_profile);
	end

	return provider;
end

module:add_item("auth-provider", new_hashpass_provider(module.host));
