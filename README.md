# TLS-session-resumption
Test TLS session resumption for a given URL.

This script thoroughly test a server's support for TLS Session Resumption for both TLS 1.2 and TLS 1.3 protocols.

It provides a reliable way to check resumption capabilities, circumventing the known issues with the standard OpenSSL s_client -reconnect command for TLS 1.3 by implementing a robust, two-step Pre-Shared Key (PSK) ticket exchange verification.

*** Features ***
- Dual Protocol Check: Tests resumption for both TLS 1.2 (using the -reconnect command) and TLS 1.3 (using the two-step -sess_out and -sess_in method).
- TLS 1.3 Reliability: Accurately confirms TLS 1.3 stateless session reuse (PSK) by verifying the exchange and successful loading of a session ticket.
- Detailed Output: Provides clear metrics, including initial/final session IDs (for TLS 1.2), PSK ticket status, and confirmation details for a successful resumed connection.

## License Notification
```
Copyright 2024 (Current Year) [Your Name/Organization Here]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
