#include "irods_client_api_table.hpp"
#include "irods_pack_table.hpp"
#include "rodsClient.h"
#include "parseCommandLine.h"
#include "rodsPath.h"
#include "lsUtil.h"
#include "irods_buffer_encryption.hpp"
#include <string>
#include <iostream>

#pragma clang diagnostic ignored "-Wunused-function"
#include "authentication_plugin_framework.hpp"

int main(int argc, char* argv[])
{
    signal( SIGPIPE, SIG_IGN );

    if (NULL != argv && NULL != argv[0]) {
        /* set SP_OPTION to argv[0] so it can be passed to server */
        char child[MAX_NAME_LEN], parent[MAX_NAME_LEN];
        *child = '\0';
        splitPathByKey(argv[0], parent, MAX_NAME_LEN, child, MAX_NAME_LEN, '/');
        if (*child != '\0') {
            mySetenvStr(SP_OPTION, child);
        }
    }

    rodsEnv env;
    auto status = getRodsEnv( &env );
    if (status < 0) {
        rodsLogError(LOG_ERROR, status, "main: getRodsEnv error. ");
        exit(1);
    }

    rErrMsg_t err_msg;
    auto comm = rcConnect(
                    env.rodsHost,
                    env.rodsPort,
                    env.rodsUserName,
                    env.rodsZone,
                    0, &err_msg );
    if (nullptr == comm) {
        exit(2);
    }

    irods::pack_entry_table& pk_tbl = irods::get_pack_table();
    irods::api_entry_table& api_tbl = irods::get_client_api_table();
    init_api_table( api_tbl, pk_tbl );

    if (strcmp(env.rodsUserName, PUBLIC_USER_NAME ) != 0) {
        try {
            irods::experimental::authenticate_client(comm, env);
        }
        catch(const irods::exception& e) {
            std::cerr << e.what() << "\n";
            rcDisconnect(comm);
            exit(7);
        }
    }

    std::cout << "authenticated.\n";

    rcDisconnect(comm);

    return 0;
} // main
