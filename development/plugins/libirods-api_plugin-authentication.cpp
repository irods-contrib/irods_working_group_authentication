#include "apiHandler.hpp"

#include "authentication_plugin_framework.hpp"

#include "client_api_whitelist.hpp"

#include "json.hpp"

namespace {
    bool parameters_are_invalid(rsComm_t* comm, bytesBuf_t* bb_req)
    {
        if(!comm || !bb_req || bb_req->len == 0) {
            rodsLog(LOG_ERROR, "authentication - one or more null parameters");
            return true;
        }

        return false;
    } // parameters_are_invalid



    int authenticate(rsComm_t* comm, bytesBuf_t* bb_req, bytesBuf_t** bb_resp)
    {
        namespace ie = irods::experimental;

        if(parameters_are_invalid(comm, bb_req)) {
            return SYS_INVALID_INPUT_PARAM;
        }

        try {
            auto req  = to_json(bb_req);
            auto auth = ie::resolve_authentication_plugin(
                                get<std::string>("scheme", req), "server");
            auto opr  = get<std::string>("next_operation", req);
            auto resp = auth->call(comm, opr, req);

            *bb_resp = to_bbuf(resp);
        }
        catch(const irods::exception& e) {
            rodsLog(LOG_ERROR, e.what());
            // TODO :: add error to rError
            return e.code();
        }

        return 0;

    } // authenticate



    int call_authenticate(
          irods::api_entry* api
        , rsComm_t*         comm
        , bytesBuf_t*       inp
        , bytesBuf_t**      out)
    {
        return api->call_handler<bytesBuf_t*, bytesBuf_t**>(comm, inp, out);
    }

#ifdef RODS_SERVER
    #define CALL_AUTHENTICATE call_authenticate
#else
    #define CALL_AUTHENTICATE NULL
#endif

    static const uint32_t AUTHENTICATION_APN{110000};

} // namespace

extern "C" {
    irods::api_entry* plugin_factory(const std::string&, const std::string&)
    {
        #ifdef RODS_SERVER
        irods::client_api_whitelist::instance().add(AUTHENTICATION_APN);
        #endif

        // =-=-=-=-=-=-=-
        // create a api def object
        irods::apidef_t def{AUTHENTICATION_APN, // api number
                            RODS_API_VERSION,   // api version
                            NO_USER_AUTH,       // client auth
                            NO_USER_AUTH,       // proxy auth
                            "BytesBuf_PI", 0,   // in PI / bs flag
                            "BytesBuf_PI", 0,   // out PI / bs flag
                            std::function<int(rsComm_t*, bytesBuf_t*, bytesBuf_t**)>(authenticate), // operation
                            "api_authenticate", // operation name
                            0,                  // null clear fcn
                            (funcPtr)CALL_AUTHENTICATE};
        return new irods::api_entry(def);
    } // plugin_factory

}; // extern "C"
