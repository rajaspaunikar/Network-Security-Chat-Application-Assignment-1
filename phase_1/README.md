Challenges Faced
1. New line automatically getting added in the buffer message and then into the map while storing the username with their socket fds. So while laster looking up that username using the map_name.find() we couldn't match the name. Introduced trim function to tackle it.

2. recv can accumulate data of multiple send and cana't determine when a message ends and the other starts , though the messsages are in order. We can send a prefix length while sending message stating the number of chracters in the message.

3. Even after fixing this , there may be a race condition where if one person sends their header with length N and concurrently other thread sends a message with length M then they will match