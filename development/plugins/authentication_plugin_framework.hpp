#ifndef AUTHENTICATION_PLUGIN_BASE
#define AUTHENTICATION_PLUGIN_BASE

// =-=-=-=-=-=-=-
// irods includes
#include "rodsDef.h"
#include "msParam.h"
#include "rcConnect.h"
#include "authRequest.h"
#include "authResponse.h"
#include "authCheck.h"
#include "miscServerFunct.hpp"
#include "authPluginRequest.h"
#include "authenticate.h"
#include "rsAuthCheck.hpp"
#include "rsAuthRequest.hpp"

#include "irods_auth_manager.hpp"
#include "irods_auth_factory.hpp"
#include "irods_auth_plugin.hpp"
#include "irods_auth_constants.hpp"
#include "irods_native_auth_object.hpp"
#include "irods_stacktrace.hpp"
#include "irods_kvp_string_parser.hpp"

// =-=-=-=-=-=-=-
// stl includes
#include <sstream>
#include <string>
#include <iostream>
#include <termios.h>
#include <unistd.h>

#include <openssl/md5.h>

#include "json.hpp"

using json = nlohmann::json;

namespace {
    auto to_json(bytesBuf_t* b)
    {
        return json::parse({(char*)b->buf, (char*)b->buf+b->len});
    } // to_json



    auto to_bbuf(const json& j)
    {
        auto s = j.dump();
        auto b = new bytesBuf_t;
        b->buf = new char[s.size()+1];
        b->len = s.size();
        rstrcpy((char*)b->buf, s.c_str(), s.size()+1);

        return b;
    }


    auto request(rcComm_t* comm, const json& msg)
    {
        auto str = msg.dump();

        bytesBuf_t inp;
        inp.buf = (void*)str.c_str();
        inp.len = str.size();

        bytesBuf_t* resp{};
        auto err = procApiRequest(comm, 110000, (void*)&inp, NULL, (void**)&resp, NULL );

        if (err < 0) {
            THROW(err, "failed to perform request");
        }

        return json::parse({(char*)resp->buf, (char*)resp->buf+resp->len});

    } // request



    template<typename T>
    auto get(const std::string& n, const json& p)
    {
        if(!p.contains(n)) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                boost::format("authentication request missing [%s] parameter")
                % n);
        }

        return p.at(n).get<T>();
    } // get



    auto verify(const json& p, std::vector<std::string> n)
    {
        for(auto&& x : n) {
            if(!p.contains(x)) {
                return std::make_tuple(false, x);
            }
        }

        return std::make_tuple(true, std::string{});
    } // verify


    void throw_if_missing(const std::string& n, const json& j)
    {
        if(!j.contains(n)) {
                THROW(
                    SYS_INVALID_INPUT_PARAM,
                    boost::format("missing [%s] in authentication flow")
                    % n);
        }
    } // throw_if_missing

} // namespace

namespace irods::experimental {
    static const std::string AUTHENTICATION_FLOW_COMPLETE{"authentication_flow_complete"};

    class authentication_base : public irods::plugin_base {

    public:
        #define OPERATION(C, F) std::function<json(C*, const json&)>([&](C* c, const json& j) -> json {return F(c, j);})

        authentication_base() : plugin_base("authentication_framework_plugin", "empty_context_string")
        {
            add_operation(AUTH_CLIENT_START, OPERATION(rcComm_t, auth_client_start));
        } // ctor

        virtual json auth_client_start(rcComm_t* comm, const json& req) = 0;

        template<typename COMM_T>
        void add_operation(const std::string& n, std::function<json(COMM_T*, const json&)> f)
        {
            if(operations_.find(n) != operations_.end()) {
                THROW(SYS_INTERNAL_ERR, boost::format("operation already exists [%s]") % n);
            }

            if(n.empty()) {
                THROW(SYS_INVALID_INPUT_PARAM, boost::format("operation name is empty [%s]") % n);
            }

            operations_[n] = f;
        } // add_operation

        template<typename COMM_T>
        json call(COMM_T* comm, const std::string& n, const json& req)
        {
            auto itr = operations_.find(n);
            if(itr == operations_.end()) {
                THROW(SYS_INVALID_INPUT_PARAM,
                      boost::format("call operation :: missing operation[%s]") % n);
            }

            using fcn_t = std::function<json(COMM_T*, const json&)>;
            auto op = boost::any_cast<fcn_t&>(operations_[n]);

            return op(comm, req);

        } // call

    }; // class authentication_base



    auto resolve_authentication_plugin(const std::string& scheme, const std::string& type)
    {
        using plugin_type = irods::experimental::authentication_base;

        std::string lower{scheme};
        std::transform(lower.begin(),
                       lower.end(),
                       lower.begin(),
                       ::tolower );

        auto name = scheme+"_"+type;

        plugin_type* plugin{};
        auto err = irods::load_plugin<plugin_type>(
                        plugin,
                        name,
                        irods::PLUGIN_TYPE_AUTHENTICATION,
                        "irods::experimental::authentication_base",
                        "empty_context" );
        if(!err.ok()) {
            THROW(err.code(), err.result());
        }

        return plugin;

    } // resolve_authentication_plugin



    void authenticate_client(rcComm_t* comm, const rodsEnv& env)
    {
        // example native authentication scheme: irods-authentication_plugin-native
        std::string scheme{env.rodsAuthScheme};

        // TODO:: make some decisions about auth scheme?

        auto auth = resolve_authentication_plugin(scheme, "client");

        std::string next_operation{irods::AUTH_CLIENT_START};

        json req{}, resp{};

        req["scheme"] = scheme;
        req["next_operation"] = next_operation;

        while(true) {
            resp = auth->call(comm, next_operation, req);

            if(comm->loggedIn) {
                break;
            }

            throw_if_missing("next_operation", resp);

            next_operation = get<std::string>("next_operation", resp);
            if(next_operation.empty() || AUTHENTICATION_FLOW_COMPLETE == next_operation) {
                THROW(CAT_INVALID_AUTHENTICATION,
                      "authentication flow completed without success");
            }

            req = resp;
        }

    } // authenticate_client

} // namespace irods::experimental

#endif // AUTHENTICATION_PLUGIN_BASE
