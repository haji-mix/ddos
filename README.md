
# Botnet Rest API

This project is a Botnet Rest API built using Express.js, designed for stress testing and DDoS attack simulations. It uses a combination of proxies, fake user agents, and various HTTP headers to simulate traffic to a target URL.

## Features

- Start and stop DDoS attacks on specified URLs.
- Use proxies to anonymize requests.
- Randomize headers and user agents to mimic real user behavior.
- Save and load attack state to resume attacks after a restart.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/haji-mix/ddos
    cd ddos
    ```

2. Install dependencies:
    ```sh
    npm install
    ```

3. Create necessary files:
    - `attackState.json`: To store the state of the attack.
    - `proxy.txt`: To store a list of proxies.
    - `ua.txt`: To store a list of user agents.

## Usage

### Starting the Server

To start the server, run:
```sh
node index.js
```

The server will start on a random port between 1024 and 65535 or the port specified in the environment variable `PORT`.

### API Endpoints

#### Start Stress Test

- **Endpoint**: `/stresser`
- **Method**: `GET`
- **Query Parameters**:
  - `url` (required): The target URL to attack (must start with `http://` or `https://`).
  - `duration` (optional): Duration of the attack in hours (default is 1 hour).

- **Example**:
    ```sh
    curl "http://localhost:<port>/stresser?url=https://example.com&duration=2"
    ```

## Configuration

- **Proxies**: Add proxies to `proxy.txt` in the format `protocol:ip:port`.
- **User Agents**: Add user agents to `ua.txt`, one per line.

## Successful Attack Proof

![Successful Attack on Example1](https://i.imgur.com/iBxIBkW.jpeg)

![Successful Attack on Example2](https://i.imgur.com/r8uPGWa.jpeg)

![Successful Attack on Example3](https://i.imgur.com/OURqG1k.jpeg)

## Code Overview

### Main Modules

- **Express.js**: Used for creating the server and handling API requests.
- **axios**: Used for making HTTP requests.
- **fs**: Used for file operations.
- **path**: Used for handling file paths.
- **socks-proxy-agent** and **https-proxy-agent**: Used for proxying requests.
- **gradient-string**: Used for colorful console output.
- **fakeState.js**: Custom module for generating fake state data.

### Key Functions

- **ensureStateFileExists**: Ensures the state file exists, creating it if necessary.
- **saveState**: Saves the current state to the state file.
- **loadState**: Loads the state from the state file.
- **getRandomElement**: Returns a random element from an array.
- **sanitizeUA**: Sanitizes user agents to remove non-ASCII characters.
- **userAgents**: Loads user agents from `ua.txt`.
- **loadProxies**: Loads proxies from `proxy.txt`.
- **performAttack**: Performs the attack by making POST and GET requests to the target URL.
- **updateState**: Periodically saves the attack state.
- **startAttack**: Initiates the attack with the specified URL and duration.

## Security Notice

This project is for educational purposes only. Unauthorized use of this software to perform DDoS attacks on websites you do not own or have permission to test is illegal and unethical. Use this tool responsibly and only on systems you have explicit permission to test.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Contact

For any questions or support, please contact [haji-mix](https://github.com/haji-mix).

