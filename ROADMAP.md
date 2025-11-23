# HelloBird Roadmap

This document outlines the future development plans for the HelloBird application.

## Phase 1: Core Functionality (Complete)

- [x] Web-based UI for CamXploit
- [x] Real-time scanning output
- [x] Stream viewing with FFmpeg and HLS.js
- [x] CIDR network range scanning
- [x] AI-powered contextual analysis of video streams

## Phase 2: Enhanced Reporting and Usability

- **Automated Data Correlation & Reporting:** Evolve the output from a simple text log to a structured report. This will involve parsing the `CamXploit.py` output and presenting it in a more organized and user-friendly format.
- **Session Persistence & History:** Save scan results and allow users to view previous reports. This will likely involve adding a simple database to the application.
- **Improved UI/UX:** Enhance the user interface to provide a more intuitive and polished experience. This could include features such as sorting and filtering of scan results, and a more advanced video player.

## Phase 3: Advanced Features

- **Automated Exploitation:** Add the ability to automatically exploit known vulnerabilities in CCTV cameras. This would be a powerful feature, but it would also need to be implemented responsibly and with the appropriate safeguards.
- **Stealth & Evasion:** Introduce options to make scanning less detectable. This could include features for randomizing port scan order, throttling connection rates to avoid tripping firewalls, and rotating User-Agent strings.
- **Integration with Other Tools:** Integrate HelloBird with other security tools, such as Shodan, Censys, and Metasploit. This would allow for a more comprehensive and powerful security auditing workflow.

## Phase 4: Scalability and Performance

- **Asynchronous Scanning:** Re-architect the backend to use an asynchronous framework, such as FastAPI or Quart. This would allow for a more scalable and performant application that can handle a large number of concurrent scans.
- **Distributed Scanning:** Add the ability to distribute scans across multiple machines. This would be useful for scanning large networks or for performing scans from multiple geographic locations.
- **Optimized Video Streaming:** Further optimize the video streaming pipeline to reduce latency and improve performance. This could involve using a more efficient streaming protocol, such as WebRTC, or by implementing a more advanced adaptive bitrate streaming algorithm.
