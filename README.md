Proxy:  
[![Proxy Snap Status](https://build.snapcraft.io/badge/RSATom/janus-signalling-proxy-snap.svg)](https://build.snapcraft.io/user/RSATom/janus-signalling-proxy-snap)  
Agent:  
[![Agent Snap Status](https://build.snapcraft.io/badge/RSATom/janus-signalling-proxy-agent-snap.svg)](https://build.snapcraft.io/user/RSATom/janus-signalling-proxy-agent-snap)
# janus-signalling-proxy
Intended to proxy WebSockets transport messages to Janus WebRTC Server instance behind NAT.

Consists from Proxy application to run on some public available hosting and Agent application to run on Janus side to make connectivity to Proxy. Uses WebSockets transport for all connections. Agent always connects to proxy by secure WebSockets channel and authenticates by selfsigned sertificate.
