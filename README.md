######    ######       #      ##            ##     ##   ######
#    #    #           # #     #  #          # #   # #   #
######    ###        #####    #   #         #   #   #   ###
#  #      #         #     #   #    #        #       #   #
#   #     #         #     #   #  #          #       #   #
#    #    ######    #     #   ##            #       #   ######

This is simple web IDPS application built with Python and HTML/CSS that automatically detects and blocks suspicious network traffic, such as rapid page requests (DDoS attempt) and repeated bad login attempts (Brute Force Attack).

1) How Request Tracking and Rate limiting works? idps_firewall
- Every incomming HTTP request passes through *@app.before_request* hook before reaching any route.
- IP Check, it checks if your IP address is currently stored in *blocked_ips*. If blocked, access is denied immediately with 403 Forbidden response.
- Traffic tracking, it logs request timestamps in request_history.
- DDoS Prevention, If an IP sends more than MAX requests (5 requests) within 10 seconds, the IDPS flags it as a rate limit and blocks the IP for *block_time* (30 seconds).

2) Brute Force Protection (Login)
- Login checking, on submission of the login form(POST request), the system checks credentials against the hardcoded standard (admin/@dmin273)
- Attempt tracking, failed logins append timestamps to *failed_login_attempts* for that specific IP.
- Brute-Force Threshold, if an IP exceeds *max_failed_logins* (3 failed attempts) within *failed_login_window* (30 seconds), the idps triggers a block for 30 seconds and logs a Brute Force Attack Detected alert.
- To a successful login clears the failed attempt count for that IP.

3) Dashboard and Audit Logging
- Accessible only when logged in via session *logged_in*
- Displays real-time metrics including total active blocked IPs and a reverse-chronological list of security logs like "Logins, logouts, failed attempts and blocks"

Procedure for running the application
- Install flask (using installed BASH)
  pip install flask
- start the server using cmd (COMMAND PROMPT)
  python app.py
- Access to Browser
  type in browser: http://127.0.0.1:5000/
    - Username: admin
    - Password: @dmin273

How to test the IDPS
- open browser then type http://127.0.0.1:5000/ as it automatically directs to login page
- then rapidly or repeat 6 times by refreshing the login page within 10 seconds
- You will receive a 403 Forbidden page and it will audit log indicating your IP address on IDPS application.
