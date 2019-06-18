#include <thread>

#include <libwebsockets.h>

#include <Proxy/Proxy.h>
#include <Agent/Agent.h>

int main(int , char*[])
{
    std::thread serverThread(
        [] () {
            Proxy();
        }
    );

    std::this_thread::sleep_for(std::chrono::seconds(1));

    lwsl_notice("------ Agent ------\n");
    Agent();

    if(serverThread.joinable())
        serverThread.join();

    return 0;
}
