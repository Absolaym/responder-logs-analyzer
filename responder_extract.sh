cat /opt/tools/Responder/logs/Responder-Session.log | grep Hash | cut -d ":" -f4- | cut -d " " -f2 | grep -v '\$' > /workspace/hashes/responder_users.hashes
