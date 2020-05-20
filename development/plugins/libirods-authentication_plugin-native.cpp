
#include "authentication_plugin_framework.hpp"

#include "base64.h"

int get64RandomBytes( char *buf );
void setSessionSignatureClientside( char* _sig );
void _rsSetAuthRequestGetChallenge( const char* _c );

#ifdef RODS_SERVER
static irods::error check_proxy_user_privileges(rsComm_t *comm, int proxy_priv ) {
    if (strcmp(comm->proxyUser.userName, comm->clientUser.userName) != 0) {
        /* remote privileged user can only do things on behalf of users from
         * the same zone */
        if(proxy_priv >= LOCAL_PRIV_USER_AUTH ||
            (proxy_priv >= REMOTE_PRIV_USER_AUTH &&
             strcmp(comm->proxyUser.rodsZone,
                   comm->clientUser.rodsZone) == 0)) {
            return ERROR(SYS_PROXYUSER_NO_PRIV,
                         boost::str(boost::format(
                         "proxy user: [%s] with %d no priv to auth client user: [%s].")
                         % comm->proxyUser.userName
                         % proxy_priv
                         % comm->clientUser.userName));
            }
    }

    return SUCCESS();
}
#endif


namespace irods {
class native_authentication : public irods::experimental::authentication_base {
    public:
        native_authentication()
        {
            add_operation(AUTH_ESTABLISH_CONTEXT,
                std::function<json(rcComm_t*, const json&)>(
                [&](rcComm_t* c, const json& j) -> json {
                return native_auth_establish_context(c,j);}));
            add_operation(AUTH_CLIENT_AUTH_REQUEST,
                std::function<json(rcComm_t*, const json&)>(
                [&](rcComm_t* c, const json& j) -> json {
                return native_auth_client_request(c,j);}));
            add_operation(AUTH_CLIENT_AUTH_RESPONSE,
                std::function<json(rcComm_t*, const json&)>(
                [&](rcComm_t* c, const json& j) -> json {
                return native_auth_client_response(c,j);}));
            #ifdef RODS_SERVER
            add_operation(AUTH_AGENT_START,
                std::function<json(rsComm_t*, const json&)>(
                [&](rsComm_t* c, const json& j) -> json {
                return native_auth_agent_start(c,j);}));
            add_operation(AUTH_AGENT_AUTH_REQUEST,
                std::function<json(rsComm_t*, const json&)>(
                [&](rsComm_t* c, const json& j) -> json {
                return native_auth_agent_request(c,j);}));
            add_operation(AUTH_AGENT_AUTH_RESPONSE,
                std::function<json(rsComm_t*, const json&)>(
                [&](rsComm_t* c, const json& j) -> json {
                return native_auth_agent_response(c,j);}));
            add_operation(AUTH_AGENT_AUTH_VERIFY,
                std::function<json(rsComm_t*, const json&)>(
                [&](rsComm_t* c, const json& j) -> json {
                return native_auth_agent_verify(c,j);}));
            #endif
        } // ctor

    private:
        json auth_client_start(rcComm_t* comm, const json& req)
        {
            json resp{req};
            resp["next_operation"] = AUTH_CLIENT_AUTH_REQUEST;
            resp["user_name"] = comm->proxyUser.userName;
            resp["zone_name"] = comm->proxyUser.rodsZone;

            return resp;
        } // auth_client_start

        json native_auth_establish_context(rcComm_t* comm, const json& req)
        {
            json resp{req};

            if(auto [e, n] = verify(req, {"user_name","request_result"}); !e) {
                THROW(SYS_INVALID_INPUT_PARAM,
                      boost::format("%s is missing %s in request")
                      % __FUNCTION__
                      % n);
            }

            char md5_buf[ CHALLENGE_LEN + MAX_PASSWORD_LEN + 2 ];
            memset( md5_buf, 0, sizeof( md5_buf ) );

            auto request_result = req.at("request_result").get<std::string>();
            request_result.resize(CHALLENGE_LEN);
            rstrcpy(md5_buf, request_result.c_str(), CHALLENGE_LEN+2);

            setSessionSignatureClientside(md5_buf);

            int need_password = 0;
            if (req.at("user_name") == ANONYMOUS_USER) {
                md5_buf[CHALLENGE_LEN + 1] = '\0';
                need_password = 0;
            }
            else {
                need_password = obfGetPw(md5_buf + CHALLENGE_LEN);
            }

            if (0 != need_password) {
                struct termios tty;
                memset( &tty, 0, sizeof( tty ) );
                tcgetattr( STDIN_FILENO, &tty );
                tcflag_t oldflag = tty.c_lflag;
                tty.c_lflag &= ~ECHO;
                int error = tcsetattr( STDIN_FILENO, TCSANOW, &tty );
                int errsv = errno;

                if (error) {
                    std::cout << "WARNING: Error "
                              << errsv
                              << " disabling echo mode. Password will be displayed in plaintext.\n";
                }
                printf( "Enter your current iRODS password:" );
                std::string password{};
                getline(std::cin, password);
                rstrcpy(md5_buf + CHALLENGE_LEN, password.c_str(), MAX_PASSWORD_LEN);
                tty.c_lflag = oldflag;
                if (tcsetattr(STDIN_FILENO, TCSANOW, &tty)) {
                    printf( "Error reinstating echo mode." );
                }
            } // if need_password

            MD5_CTX context;
            MD5_Init( &context );
            MD5_Update(&context, (unsigned char*)md5_buf, CHALLENGE_LEN + MAX_PASSWORD_LEN);

            char digest[RESPONSE_LEN + 2];
            MD5_Final((unsigned char*)digest, &context);

            for (int i = 0; i < RESPONSE_LEN; ++i) {
                if (digest[i] == '\0') {
                    digest[i]++;
                }
            }

            unsigned char out[RESPONSE_LEN*2];
            unsigned long out_len{RESPONSE_LEN*2};
            auto err = base64_encode((unsigned char*)digest, RESPONSE_LEN, out, &out_len);
            if(err < 0) {
                THROW(err, "base64 encoding of digest failed.");
            }

            resp["digest"] = std::string{(char*)out};
            resp["next_operation"] = AUTH_CLIENT_AUTH_RESPONSE;

            return resp;

        } // native_auth_establish_context

        json native_auth_client_request(rcComm_t* comm, const json& req)
        {
            json svr_req{req};
            svr_req["next_operation"] = AUTH_AGENT_AUTH_REQUEST;
            auto resp = request(comm, svr_req);

            resp["next_operation"] = AUTH_ESTABLISH_CONTEXT;

            return resp;

        } // native_auth_client_request


        #ifdef RODS_SERVER
        json native_auth_agent_request(rsComm_t* comm, const json& req)
        {
            json resp{req};

            char buf[ CHALLENGE_LEN + 2 ];
            get64RandomBytes( buf );

            resp["request_result"] = buf;

            _rsSetAuthRequestGetChallenge(buf);

            if (comm->auth_scheme) {
                free(comm->auth_scheme);
            }

            comm->auth_scheme = strdup(AUTH_NATIVE_SCHEME.c_str());

            return resp;

        } // native_auth_agent_request
        #endif


        json native_auth_client_response(rcComm_t* comm, const json& req)
        {
            namespace ie = irods::experimental;

            if(auto [e, n] = verify(req, {"digest","user_name","zone_name"}); !e) {
                THROW(SYS_INVALID_INPUT_PARAM,
                      boost::format("%s is missing %s in request")
                      % __FUNCTION__
                      % n);
            }

            json svr_req{req};
            svr_req["next_operation"] = AUTH_AGENT_AUTH_RESPONSE;
            auto resp = request(comm, svr_req);

            comm->loggedIn = 1;

            resp["next_operation"] = ie::AUTHENTICATION_FLOW_COMPLETE;

            return resp;

        } // native_auth_client_response


        #ifdef RODS_SERVER
        json native_auth_agent_response(rsComm_t* comm, const json& req)
        {
            if(auto [e, n] = verify(req, {"digest", "zone_name", "user_name"}); !e) {
                THROW(SYS_INVALID_INPUT_PARAM,
                      boost::format("%s is missing %s in request")
                      % __FUNCTION__
                      % n);
            }

            int status;
            authCheckInp_t authCheckInp;
            authCheckOut_t *authCheckOut = NULL;
            rodsServerHost_t *rodsServerHost;

            // need to do NoLogin because it could get into inf loop for cross zone auth
            auto zone_name{get<std::string>("zone_name", req)};
            status = getAndConnRcatHostNoLogin(comm, MASTER_RCAT, (char*)zone_name.c_str(), &rodsServerHost);
            if ( status < 0 ) {
                THROW(status, "Connecting to rcat host failed.");
            }

            memset( &authCheckInp, 0, sizeof( authCheckInp ) );
            authCheckInp.challenge = _rsAuthRequestGetChallenge();

            auto response = (char*)malloc(RESPONSE_LEN + 1);
            response[RESPONSE_LEN] = 0;

            unsigned long out_len{RESPONSE_LEN};
            std::string to_decode{get<std::string>("digest", req)};
            auto err = base64_decode((unsigned char*)to_decode.c_str(), to_decode.size(), (unsigned char*)response, &out_len);
            if(err < 0) {
                THROW(err, "base64 encoding of digest failed.");
            }

            authCheckInp.response = response;
            authCheckInp.username = (char*)req.at("user_name").get<std::string>().c_str();

            if (LOCAL_HOST == rodsServerHost->localFlag) {
                status = rsAuthCheck(comm, &authCheckInp, &authCheckOut);
            }
            else {
                status = rcAuthCheck(rodsServerHost->conn, &authCheckInp, &authCheckOut);
                /* not likely we need this connection again */
                rcDisconnect( rodsServerHost->conn );
                rodsServerHost->conn = NULL;
            }

            free(response);

            json resp{req};

            if ( status >= 0 && NULL != authCheckOut ) {
                if ( rodsServerHost->localFlag != LOCAL_HOST ) {
                    if ( authCheckOut->serverResponse == NULL ) {
                        rodsLog( LOG_NOTICE, "Warning, cannot authenticate remote server, no serverResponse field" );
                        THROW(REMOTE_SERVER_AUTH_NOT_PROVIDED, "Authentication disallowed. no serverResponse field.");
                    }
                    else {
                        if ( *authCheckOut->serverResponse == '\0' ) {
                            rodsLog( LOG_NOTICE, "Warning, cannot authenticate remote server, serverResponse field is empty" );
                            THROW( REMOTE_SERVER_AUTH_EMPTY, "Authentication disallowed, empty serverResponse.");
                        }
                        else {
                            char serverId[MAX_PASSWORD_LEN + 2];
                            char md5Buf[CHALLENGE_LEN + MAX_PASSWORD_LEN + 2];
                            char username2[NAME_LEN + 2];
                            char userZone[NAME_LEN + 2];
                            memset( md5Buf, 0, sizeof( md5Buf ) );
                            rstrcpy( md5Buf, authCheckInp.challenge, CHALLENGE_LEN );
                            parseUserName(req.at("user_name").get<std::string>().c_str(), username2, userZone );
                            getZoneServerId( userZone, serverId );

                            if('\0' == serverId[0]) {
                                rodsLog(LOG_NOTICE, "rsAuthResponse: Warning, cannot authenticate the remote server, no RemoteZoneSID defined in server_config.json", status);
                                THROW( REMOTE_SERVER_SID_NOT_DEFINED, "Authentication disallowed, no RemoteZoneSID defined");
                            }
                            else {
                                char digest[RESPONSE_LEN + 2];
                                rstrcpy(md5Buf + CHALLENGE_LEN, serverId, sizeof(serverId));
                                obfMakeOneWayHash(
                                    HASH_TYPE_DEFAULT,
                                    ( unsigned char* )md5Buf,
                                    CHALLENGE_LEN + MAX_PASSWORD_LEN,
                                    ( unsigned char* )digest );

                                for (int i = 0; i < RESPONSE_LEN; i++) {
                                    if ( digest[i] == '\0' ) {
                                        digest[i]++;
                                    }  /* make sure 'string' doesn't end early*/
                                }
                                char* cp = authCheckOut->serverResponse;
                                int OK = 1;
                                for (int i = 0; i < RESPONSE_LEN; i++) {
                                    if ( *cp++ != digest[i] ) {
                                        OK = 0;
                                    }
                                }
                                rodsLog( LOG_DEBUG, "serverResponse is OK/Not: %d", OK );
                                if ( 0 == OK ) {
                                    THROW(REMOTE_SERVER_AUTHENTICATION_FAILURE, "Authentication disallowed, server response incorrect.");
                                }
                            }
                        }
                    }
                }

                /* Set the clientUser zone if it is null. */
                if ('\0' == comm->clientUser.rodsZone[0]) {
                    zoneInfo_t* tmpZoneInfo{};
                    status = getLocalZoneInfo( &tmpZoneInfo );
                    if ( status < 0 ) {
                        THROW(status, "getLocalZoneInfo failed.");
                    }
                    else {
                        rstrcpy(comm->clientUser.rodsZone, tmpZoneInfo->zoneName, NAME_LEN);
                    }
                }

                /* have to modify privLevel if the icat is a foreign icat because
                 * a local user in a foreign zone is not a local user in this zone
                 * and vice versa for a remote user
                 */
                if (rodsServerHost->rcatEnabled == REMOTE_ICAT ) {
                    /* proxy is easy because rodsServerHost is based on proxy user */
                    if ( authCheckOut->privLevel == LOCAL_PRIV_USER_AUTH ) {
                        authCheckOut->privLevel = REMOTE_PRIV_USER_AUTH;
                    }
                    else if ( authCheckOut->privLevel == LOCAL_USER_AUTH ) {
                        authCheckOut->privLevel = REMOTE_USER_AUTH;
                    }

                    /* adjust client user */
                    if ( 0 == strcmp(comm->proxyUser.userName, comm->clientUser.userName ) ) {
                        authCheckOut->clientPrivLevel = authCheckOut->privLevel;
                    }
                    else {
                        zoneInfo_t *tmpZoneInfo;
                        status = getLocalZoneInfo( &tmpZoneInfo );
                        if ( status < 0 ) {
                            THROW(status, "getLocalZoneInfo failed.");
                        }
                        else {
                            if ( 0 == strcmp( tmpZoneInfo->zoneName, comm->clientUser.rodsZone ) ) {
                                /* client is from local zone */
                                if ( REMOTE_PRIV_USER_AUTH == authCheckOut->clientPrivLevel ) {
                                    authCheckOut->clientPrivLevel = LOCAL_PRIV_USER_AUTH;
                                }
                                else if ( REMOTE_USER_AUTH == authCheckOut->clientPrivLevel ) {
                                    authCheckOut->clientPrivLevel = LOCAL_USER_AUTH;
                                }
                            }
                            else {
                                /* client is from remote zone */
                                if ( LOCAL_PRIV_USER_AUTH == authCheckOut->clientPrivLevel ) {
                                    authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                                }
                                else if ( LOCAL_USER_AUTH == authCheckOut->clientPrivLevel ) {
                                    authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                                }
                            }
                        }
                    }
                }
                else if ( 0 == strcmp(comm->proxyUser.userName,  comm->clientUser.userName ) ) {
                    authCheckOut->clientPrivLevel = authCheckOut->privLevel;
                }

                auto ret = check_proxy_user_privileges(comm, authCheckOut->privLevel );
                if ( !ret.ok() ) {
                    THROW(ret.code(), "Check proxy user privileges failed.");
                }

                rodsLog(LOG_DEBUG,
                        "rsAuthResponse set proxy authFlag to %d, client authFlag to %d, user:%s proxy:%s client:%s",
                        authCheckOut->privLevel,
                        authCheckOut->clientPrivLevel,
                        authCheckInp.username,
                        comm->proxyUser.userName,
                        comm->clientUser.userName );

                if ( strcmp(comm->proxyUser.userName, comm->clientUser.userName ) != 0 ) {
                    comm->proxyUser.authInfo.authFlag = authCheckOut->privLevel;
                    comm->clientUser.authInfo.authFlag = authCheckOut->clientPrivLevel;
                }
                else {          /* proxyUser and clientUser are the same */
                    comm->proxyUser.authInfo.authFlag =
                        comm->clientUser.authInfo.authFlag = authCheckOut->privLevel;
                }
            }
            else {
                THROW(status, "rcAuthCheck failed.");
            }

            if ( authCheckOut != NULL ) {
                if ( authCheckOut->serverResponse != NULL ) {
                    free( authCheckOut->serverResponse );
                }
                free( authCheckOut );
            }

            return resp;

        } // native_auth_agent_response

        // =-=-=-=-=-=-=-
        // stub for ops that the native plug does
        // not need to support
        json native_auth_agent_verify(rsComm_t*, const json&)
        {
            return {};
        } // native_auth_agent_verify


        // =-=-=-=-=-=-=-
        // stub for ops that the native plug does
        // not need to support
        json native_auth_agent_start(rsComm_t*, const json&)
        {
            return {};
        } // native_auth_agent_start
        #endif

}; // class native_authentication
} // namespace irods

extern "C"
irods::native_authentication* plugin_factory(const std::string&, const std::string&) {
    return new irods::native_authentication{};
}

