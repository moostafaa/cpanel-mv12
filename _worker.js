// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

const proxyIPs = ['cdn.xn--b6gac.eu.org', 'cdn-all.xn--b6gac.eu.org', 'workers.cloudflare.cyou'];

// if you want to use ipv6 or single proxyIP, please add comment at this line and remove comment at the next line
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
// use single proxyIP instead of random
// let proxyIP = 'cdn.xn--b6gac.eu.org';
// ipv6 proxyIP example remove comment to use
// let proxyIP = "[2a01:4f8:c2c:123f:64:5:6810:c55a]"

let dohURL = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg='; // https://cloudflare-dns.com/dns-query or https://dns.google/dns-query

if (!isValidUUID(userID)) {
    throw new Error('uuid is invalid');
}

export default {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{UUID: string, PROXYIP: string, DNS_RESOLVER_URL: string, NODE_ID: int, API_HOST: string, API_TOKEN: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        // uuid_validator(request);
        try {
            userID = env.UUID || userID;
            proxyIP = env.PROXYIP || proxyIP;
            dohURL = env.DNS_RESOLVER_URL || dohURL;
            let userID_Path = userID;
            if (userID.includes(',')) {
                userID_Path = userID.split(',')[0];
            }
            const upgradeHeader = request.headers.get('Upgrade');
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                const url = new URL(request.url);
                switch (url.pathname) {
                    case `/cf`: {
                        return new Response(JSON.stringify(request.cf, null, 4), {
                            status: 200,
                            headers: {
                                "Content-Type": "application/json;charset=utf-8",
                            },
                        });
                    }
                    case `/${userID_Path}`: {
                        const vlessConfig = getVLESSConfig(userID, request.headers.get('Host'));
                        return new Response(`${vlessConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html; charset=utf-8",
                            }
                        });
                    };
                    case `/sub/${userID_Path}`: {
                        const url = new URL(request.url);
                        const searchParams = url.searchParams;
                        const vlessSubConfig = createVLESSSub(userID, request.headers.get('Host'));
                        // Construct and return response object
                        return new Response(btoa(vlessSubConfig), {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            }
                        });
                    };
                    case `/bestip/${userID_Path}`: {
                        const headers = request.headers;
                        const url = `https://sub.xf.free.hr/auto?host=${request.headers.get('Host')}&uuid=${userID}&path=/`;
                        const bestSubConfig = await fetch(url, { headers: headers });
                        return bestSubConfig;
                    };
                    default:
                        const regex = /^\/reverse\/([^\/]+)\/(.+)$/;
                        const match = url.pathname.match(regex);
                        if (match) {
                            const hashValue = match[1];
                            const otherParts = match[2];

                            const baseUrl = hashDictionary[hashValue];

                            if (baseUrl) {
                                let url = new URL(`${baseUrl}/${otherParts}`);
                                let method = request.method;
                                let request_headers = request.headers;
                                let new_request_headers = new Headers(request_headers);

                                new_request_headers.set('Host', url.hostname);
                                new_request_headers.set('Referer', url.protocol + '//' + url_hostname);

                                let original_response = await this.fetch(url.href, {
                                    method: method,
                                    headers: new_request_headers
                                });

                                let original_response_clone = original_response.clone();
                                let original_text = null;
                                let response_headers = original_response.headers;
                                let new_response_headers = new Headers(response_headers);
                                let status = original_response.status;

                                new_response_headers.set('Cache-Control', 'no-store');
                                new_response_headers.set('access-control-allow-origin', '*');
                                new_response_headers.set('access-control-allow-credentials', true);
                                new_response_headers.delete('content-security-policy');
                                new_response_headers.delete('content-security-policy-report-only');
                                new_response_headers.delete('clear-site-data');
                                if (new_response_headers.get("x-pjax-url")) {
                                    new_response_headers.set("x-pjax-url", response_headers.get("x-pjax-url").replace("//" + upstream_domain, "//" + url_hostname));
                                }
                                const content_type = new_response_headers.get('content-type');
                                original_text = original_response_clone.body;

                                response = new Response(original_text, {
                                    status,
                                    headers: new_response_headers
                                });

                                return response;
                            }
                        }

                        // return new Response('Not found', { status: 404 });
                        // For any other path, reverse proxy to 'ramdom website' and return the original response, caching it in the process
                        const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
                        const newHeaders = new Headers(request.headers);
                        newHeaders.set('cf-connecting-ip', '1.2.3.4');
                        newHeaders.set('x-forwarded-for', '1.2.3.4');
                        newHeaders.set('x-real-ip', '1.2.3.4');
                        newHeaders.set('referer', 'https://www.google.com/search?q=edtunnel');
                        // Use fetch to proxy the request to 15 different domains
                        const proxyUrl = 'https://' + randomHostname + url.pathname + url.search;
                        let modifiedRequest = new Request(proxyUrl, {
                            method: request.method,
                            headers: newHeaders,
                            body: request.body,
                            redirect: 'manual',
                        });
                        const proxyResponse = await fetch(modifiedRequest, { redirect: 'manual' });
                        // Check for 302 or 301 redirect status and return an error response
                        if ([301, 302].includes(proxyResponse.status)) {
                            return new Response(`Redirects to ${randomHostname} are not allowed.`, {
                                status: 403,
                                statusText: 'Forbidden',
                            });
                        }
                        // Return the response from the proxy server
                        return proxyResponse;
                }
            } else {
                return await vlessOverWSHandler(request);
            }
        } catch (err) {
			/** @type {Error} */ let e = err;
            return new Response(e.toString());
        }
    },
};


export async function uuid_validator(request) {
    const hostname = request.headers.get('Host');
    const currentDate = new Date();

    const subdomain = hostname.split('.')[0];
    const year = currentDate.getFullYear();
    const month = String(currentDate.getMonth() + 1).padStart(2, '0');
    const day = String(currentDate.getDate()).padStart(2, '0');

    const formattedDate = `${year}-${month}-${day}`;

    // const daliy_sub = formattedDate + subdomain
    const hashHex = await hashHex_f(subdomain);
    // subdomain string contains timestamps utc and uuid string TODO.
    console.log(hashHex, subdomain, formattedDate);
}

export async function hashHex_f(string) {
    const encoder = new TextEncoder();
    const data = encoder.encode(string);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

/**
 * Handles VLESS over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the VLESS header.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
async function vlessOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    let currentDate = new Date();
    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
        console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || '');
    };
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    /** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let isDns = false;

    // ws --> remote
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter()
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const {
                hasError,
                message,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                vlessVersion = new Uint8Array([0, 0]),
                isUDP,
            } = processVlessHeader(chunk, userID);
            address = addressRemote;
            portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;
            if (hasError) {
                // controller.error(message);
                throw new Error(message); // cf seems has bug, controller.error will not end stream
            }

            // If UDP and not DNS port, close it
            if (isUDP && portRemote !== 53) {
                throw new Error('UDP proxy only enabled for DNS which is port 53');
                // cf seems has bug, controller.error will not end stream
            }

            if (isUDP && portRemote === 53) {
                isDns = true;
            }

            // ["version", "附加信息长度 N"]
            const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            // TODO: support udp here when cf runtime has udp support
            if (isDns) {
                const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }
            handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
        },
        close() {
            log(`readableWebSocketStream is close`);
        },
        abort(reason) {
            log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream pipeTo error', err);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket 
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader The VLESS response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {

    /**
     * Connects to a given address and port and writes data to the socket.
     * @param {string} address The address to connect to.
     * @param {number} port The port to connect to.
     * @returns {Promise<import("@cloudflare/workers-types").Socket>} A Promise that resolves to the connected socket.
     */
    async function connectAndWrite(address, port) {
        /** @type {import("@cloudflare/workers-types").Socket} */
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData); // first write, nomal is tls client hello
        writer.releaseLock();
        return tcpSocket;
    }

    /**
     * Retries connecting to the remote address and port if the Cloudflare socket has no incoming data.
     * @returns {Promise<void>} A Promise that resolves when the retry is complete.
     */
    async function retry() {
        const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote)
        tcpSocket.closed.catch(error => {
            console.log('retry tcpSocket closed error', error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);

    // when remoteSocket is ready, pass to websocket
    // remote--> ws
    remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 * Creates a readable stream from a WebSocket server, allowing for data to be read from the WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer The WebSocket server to create the readable stream from.
 * @param {string} earlyDataHeader The header containing early data for WebSocket 0-RTT.
 * @param {(info: string)=> void} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the WebSocket.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                const message = event.data;
                controller.enqueue(message);
            });

            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                controller.close();
            });

            webSocketServer.addEventListener('error', (err) => {
                log('webSocketServer has error');
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) {
            // if ws can stop read if stream is full, we can implement backpressure
            // https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },

        cancel(reason) {
            log(`ReadableStream was canceled, due to ${reason}`)
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * Processes the VLESS header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} vlessBuffer The VLESS header buffer to process.
 * @param {string} userID The user ID to validate against the UUID in the VLESS header.
 * @returns {{
 *  hasError: boolean,
 *  message?: string,
 *  addressRemote?: string,
 *  addressType?: number,
 *  portRemote?: number,
 *  rawDataIndex?: number,
 *  vlessVersion?: Uint8Array,
 *  isUDP?: boolean
 * }} An object with the relevant information extracted from the VLESS header buffer.
 */
function processVlessHeader(vlessBuffer, userID) {
    if (vlessBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }

    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    let isValidUser = false;
    let isUDP = false;
    const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);
    // check if userID is valid uuid or uuids split by , and contains userID in it otherwise return error message to console
    const uuids = userID.includes(',') ? userID.split(",") : [userID];
    // uuid_validator(hostName, slicedBufferString);


    // isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim());
    isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();

    console.log(`userID: ${slicedBufferString}`);

    if (!isValidUser) {
        return {
            hasError: true,
            message: 'invalid user',
        };
    }

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    //skip opt for now

    const command = new Uint8Array(
        vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
    )[0];

    // 0x01 TCP
    // 0x02 UDP
    // 0x03 MUX
    if (command === 1) {
        isUDP = false;
    } else if (command === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    const portIndex = 18 + optLength + 1;
    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
    // port is big-Endian in raw data etc 80 == 0x005d
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(
        vlessBuffer.slice(addressIndex, addressIndex + 1)
    );

    // 1--> ipv4  addressLength =4
    // 2--> domain name addressLength=addressBuffer[1]
    // 3--> ipv6  addressLength =16
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';
    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join('.');
            break;
        case 2:
            addressLength = new Uint8Array(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
            )[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(
                vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            // seems no need add [] for ipv6
            break;
        default:
            return {
                hasError: true,
                message: `invild  addressType is ${addressType}`,
            };
    }
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        vlessVersion: version,
        isUDP,
    };
}


/**
 * Converts a remote socket to a WebSocket connection.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to convert.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to connect to.
 * @param {ArrayBuffer | null} vlessResponseHeader The VLESS response header.
 * @param {(() => Promise<void>) | null} retry The function to retry the connection if it fails.
 * @param {(info: string) => void} log The logging function.
 * @returns {Promise<void>} A Promise that resolves when the conversion is complete.
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
    // remote--> ws
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let vlessHeader = vlessResponseHeader;
    let hasIncomingData = false; // check if remoteSocket has incoming data
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {
                },
                /**
                 * 
                 * @param {Uint8Array} chunk 
                 * @param {*} controller 
                 */
                async write(chunk, controller) {
                    hasIncomingData = true;
                    remoteChunkCount++;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error(
                            'webSocket.readyState is not open, maybe close'
                        );
                    }
                    if (vlessHeader) {
                        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
                        vlessHeader = null;
                    } else {
                        // console.log(`remoteSocketToWS send chunk ${chunk.byteLength}`);
                        // seems no need rate limit this, CF seems fix this??..
                        // if (remoteChunkCount > 20000) {
                        // 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
                        // 	await delay(1);
                        // }
                        webSocket.send(chunk);
                    }
                },
                close() {
                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                    // safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
                },
                abort(reason) {
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            console.error(
                `remoteSocketToWS has exception `,
                error.stack || error
            );
            safeCloseWebSocket(webSocket);
        });

    // seems is cf connect socket have error,
    // 1. Socket.closed will have error
    // 2. Socket.readable will be close without any data coming
    if (hasIncomingData === false && retry) {
        log(`retry`)
        retry();
    }
}

/**
 * Decodes a base64 string into an ArrayBuffer.
 * @param {string} base64Str The base64 string to decode.
 * @returns {{earlyData: ArrayBuffer|null, error: Error|null}} An object containing the decoded ArrayBuffer or null if there was an error, and any error that occurred during decoding or null if there was no error.
 */
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: null, error: null };
    }
    try {
        // go use modified Base64 for URL rfc4648 which js atob not support
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

/**
 * Checks if a given string is a valid UUID.
 * Note: This is not a real UUID validation.
 * @param {string} uuid The string to validate as a UUID.
 * @returns {boolean} True if the string is a valid UUID, false otherwise.
 */
function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Closes a WebSocket connection safely without throwing exceptions.
 * @param {import("@cloudflare/workers-types").WebSocket} socket The WebSocket connection to close.
 */
function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error('safeCloseWebSocket error', error);
    }
}

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw TypeError("Stringified UUID is invalid");
    }
    return uuid;
}


/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} vlessResponseHeader The VLESS response header.
 * @param {(string) => void} log The logging function.
 * @returns {{write: (chunk: Uint8Array) => void}} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {

    let isVlessHeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) {

        },
        transform(chunk, controller) {
            // udp message 2 byte is the the length of udp data
            // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(
                    chunk.slice(index + 2, index + 2 + udpPakcetLength)
                );
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {
        }
    });

    // only handle dns udp for now
    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch(dohURL, // dns server url
                {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/dns-message',
                    },
                    body: chunk,
                })
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                log(`doh success and dns message length is ${udpSize}`);
                if (isVlessHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    isVlessHeaderSent = true;
                }
            }
        }
    })).catch((error) => {
        log('dns udp has error' + error)
    });

    const writer = transformStream.writable.getWriter();

    return {
        /**
         * 
         * @param {Uint8Array} chunk 
         */
        write(chunk) {
            writer.write(chunk);
        }
    };
}

/**
 *
 * @param {string} userID - single or comma separated userIDs
 * @param {string | null} hostName
 * @returns {string}
 */
function getVLESSConfig(userIDs, hostName) {
    const commonUrlPart = `:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`;
    const hashSeparator = "################################################################";

    // Split the userIDs into an array
    const userIDArray = userIDs.split(",");

    // Prepare output string for each userID
    const output = userIDArray.map((userID) => {
        const vlessMain = `vless://${userID}@${hostName}${commonUrlPart}`;
        const vlessSec = `vless://${userID}@${proxyIP}${commonUrlPart}`;
        return `<h2>UUID: ${userID}</h2>${hashSeparator}\nv2ray default ip
---------------------------------------------------------------
${vlessMain}
<button onclick='copyToClipboard("${vlessMain}")'><i class="fa fa-clipboard"></i> Copy vlessMain</button>
---------------------------------------------------------------
v2ray with bestip
---------------------------------------------------------------
${vlessSec}
<button onclick='copyToClipboard("${vlessSec}")'><i class="fa fa-clipboard"></i> Copy vlessSec</button>
---------------------------------------------------------------`;
    }).join('\n');
    const sublink = `https://${hostName}/sub/${userIDArray[0]}?format=clash`
    const subbestip = `https://${hostName}/bestip/${userIDArray[0]}`;
    const clash_link = `https://api.v1.mk/sub?target=clash&url=${encodeURIComponent(sublink)}&insert=false&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
    // Prepare header string
    const header = `
<p align='center'><img src='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' alt='图片描述' style='margin-bottom: -50px;'>
<b style='font-size: 15px;'>Welcome! This function generates configuration for VLESS protocol. If you found this useful, please check our GitHub project for more:</b>
<b style='font-size: 15px;'>欢迎！这是生成 VLESS 协议的配置。如果您发现这个项目很好用，请查看我们的 GitHub 项目给我一个star：</b>
<a href='https://github.com/3Kmfi6HP/EDtunnel' target='_blank'>EDtunnel - https://github.com/3Kmfi6HP/EDtunnel</a>
<iframe src='https://ghbtns.com/github-btn.html?user=USERNAME&repo=REPOSITORY&type=star&count=true&size=large' frameborder='0' scrolling='0' width='170' height='30' title='GitHub'></iframe>
<a href='//${hostName}/sub/${userIDArray[0]}' target='_blank'>VLESS 节点订阅连接</a>
<a href='clash://install-config?url=${encodeURIComponent(`https://${hostName}/sub/${userIDArray[0]}?format=clash`)}}' target='_blank'>Clash for Windows 节点订阅连接</a>
<a href='${clash_link}' target='_blank'>Clash 节点订阅连接</a>
<a href='${subbestip}' target='_blank'>优选IP自动节点订阅</a>
<a href='clash://install-config?url=${encodeURIComponent(subbestip)}' target='_blank'>Clash优选IP自动</a>
<a href='sing-box://import-remote-profile?url=${encodeURIComponent(subbestip)}' target='_blank'>singbox优选IP自动</a>
<a href='sn://subscription?url=${encodeURIComponent(subbestip)}' target='_blank'>nekobox优选IP自动</a>
<a href='v2rayng://install-config?url=${encodeURIComponent(subbestip)}' target='_blank'>v2rayNG优选IP自动</a></p>`;

    // HTML Head with CSS and FontAwesome library
    const htmlHead = `
  <head>
	<title>EDtunnel: VLESS configuration</title>
	<meta name='description' content='This is a tool for generating VLESS protocol configurations. Give us a star on GitHub https://github.com/3Kmfi6HP/EDtunnel if you found it useful!'>
	<meta name='keywords' content='EDtunnel, cloudflare pages, cloudflare worker, severless'>
	<meta name='viewport' content='width=device-width, initial-scale=1'>
	<meta property='og:site_name' content='EDtunnel: VLESS configuration' />
	<meta property='og:type' content='website' />
	<meta property='og:title' content='EDtunnel - VLESS configuration and subscribe output' />
	<meta property='og:description' content='Use cloudflare pages and worker severless to implement vless protocol' />
	<meta property='og:url' content='https://${hostName}/' />
	<meta property='og:image' content='https://api.qrserver.com/v1/create-qr-code/?size=500x500&data=${encodeURIComponent(`vless://${userIDs.split(",")[0]}@${hostName}${commonUrlPart}`)}' />
	<meta name='twitter:card' content='summary_large_image' />
	<meta name='twitter:title' content='EDtunnel - VLESS configuration and subscribe output' />
	<meta name='twitter:description' content='Use cloudflare pages and worker severless to implement vless protocol' />
	<meta name='twitter:url' content='https://${hostName}/' />
	<meta name='twitter:image' content='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' />
	<meta property='og:image:width' content='1500' />
	<meta property='og:image:height' content='1500' />

	<style>
	body {
	  font-family: Arial, sans-serif;
	  background-color: #f0f0f0;
	  color: #333;
	  padding: 10px;
	}

	a {
	  color: #1a0dab;
	  text-decoration: none;
	}
	img {
	  max-width: 100%;
	  height: auto;
	}

	pre {
	  white-space: pre-wrap;
	  word-wrap: break-word;
	  background-color: #fff;
	  border: 1px solid #ddd;
	  padding: 15px;
	  margin: 10px 0;
	}
	/* Dark mode */
	@media (prefers-color-scheme: dark) {
	  body {
		background-color: #333;
		color: #f0f0f0;
	  }

	  a {
		color: #9db4ff;
	  }

	  pre {
		background-color: #282a36;
		border-color: #6272a4;
	  }
	}
	</style>

	<!-- Add FontAwesome library -->
	<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css'>
  </head>
  `;

    // Join output with newlines, wrap inside <html> and <body>
    return `
  <html>
  ${htmlHead}
  <body>
  <pre style='background-color: transparent; border: none;'>${header}</pre>
  <pre>${output}</pre>
  </body>
  <script>
	function copyToClipboard(text) {
	  navigator.clipboard.writeText(text)
		.then(() => {
		  alert("Copied to clipboard");
		})
		.catch((err) => {
		  console.error("Failed to copy to clipboard:", err);
		});
	}
  </script>
  </html>`;
}

const portSet_http = new Set([80, 8080, 8880, 2052, 2086, 2095, 2082]);
const portSet_https = new Set([443, 8443, 2053, 2096, 2087, 2083]);

function createVLESSSub(userID_Path, hostName) {
    const userIDArray = userID_Path.includes(',') ? userID_Path.split(',') : [userID_Path];
    const commonUrlPart_http = `?encryption=none&security=none&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`;
    const commonUrlPart_https = `?encryption=none&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#`;

    const output = userIDArray.flatMap((userID) => {
        const httpConfigurations = Array.from(portSet_http).flatMap((port) => {
            if (!hostName.includes('pages.dev')) {
                const urlPart = `${hostName}-HTTP-${port}`;
                const vlessMainHttp = `vless://${userID}@${hostName}:${port}${commonUrlPart_http}${urlPart}`;
                return proxyIPs.flatMap((proxyIP) => {
                    const vlessSecHttp = `vless://${userID}@${proxyIP}:${port}${commonUrlPart_http}${urlPart}-${proxyIP}-EDtunnel`;
                    return [vlessMainHttp, vlessSecHttp];
                });
            }
            return [];
        });

        const httpsConfigurations = Array.from(portSet_https).flatMap((port) => {
            const urlPart = `${hostName}-HTTPS-${port}`;
            const vlessMainHttps = `vless://${userID}@${hostName}:${port}${commonUrlPart_https}${urlPart}`;
            return proxyIPs.flatMap((proxyIP) => {
                const vlessSecHttps = `vless://${userID}@${proxyIP}:${port}${commonUrlPart_https}${urlPart}-${proxyIP}-EDtunnel`;
                return [vlessMainHttps, vlessSecHttps];
            });
        });

        return [...httpConfigurations, ...httpsConfigurations];
    });

    return output.join('\n');
}

const hashDictionary = {
    "RAnquxAMWB534XV/Slj/7g==": "https://stream.persiantv1.com/ptv1/playlist1",
    "3vxLCPNMwK/dyohagf8fAg==": "https://hls.yourtime.live/hls",
    "Pz5pCUx+aVcHUGqQE3CC4g==": "https://bozztv.com/1gbw5/tintv2/tintv2",
    "V1glDT3hRMuJA1PGkTMkgA==": "https://597f64b67707a.streamlock.net/alkerazatv.org/alkerazatv.smil",
    "+Q8TBIDIVh6w2FwemWGobw==": "https://2nbyjjx7y53k-hls-live.5centscdn.com/atvweb/d23299de099088e7444868cd0814f1c7.sdp",
    "Xgi77nHKryyvtXqVqJ3uWA==": "http://iptv.arianaafgtv.com/ariana",
    "JjqeGz81oYbe5pIGcCipAw==": "https://d10rltuy0iweup.cloudfront.net/ATNNAT/myStream",
    "FJQF1h608DEJys1iBhzD4A==": "https://d10rltuy0iweup.cloudfront.net/ATNNEWS/myStream",
    "ixuz6Cueq9YRVw2bbBICPA==": "https://familyhls.avatv.live/hls",
    "77+O5o70ch4rFmWShhioog==": "https://avaserieshls.wns.live/hls",
    "C2LKfP1SOAKUkySwUkuNQg==": "https://livestream.5centscdn.com/cls040318/b0d2763968fd0bdd2dc0d44ba2abf9ce.sdp",
    "gxCiTrCbovy2dD80ChUr1A==": "https://vs-cmaf-pushb-ww-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_persian_tv",
    "FM0wQ/SFi84zRlOM2DYQhQ==": "https://vid1.caltexmusic.com/hls",
    "bpdZ34Cdr7skyYmbDz9AYQ==": "https://api.new.livestream.com/accounts/27146356/events/8209491",
    "Tn99iq1WmRz/yjLZVk9+5Q==": "https://vsn1-cdn-phx.icastcenter.com/EBC1/EBC1",
    "wKGcN2ls42W8mWKeWUAPlw==": "http://cdn1.live.irib.ir:1935/epg-live/smil:fars",
    "Ww1I6TuKcKzuFYkA0w+rBQ==": "http://topfi.ios.internapcdn.net/topfi/live_1/Test",
    "nKr5wPvTmziSGJAYOo6hVg==": "http://216.66.42.47:7777",
    "Ll2Zfhloa314PCGCOS4jMg==": "http://cdn1.live.irib.ir:1935/epg-live/smil:golestan",
    "/ykoNujKKsJmqxMN0YOpMg==": "https://live.hastitv.com/hls",
    "JZryodBROhramcZ2lw2CvA==": "https://streamer1.connectto.com/HIGHVISION_WEB_1205/tracks-v1a1",
    "PPX5/n82IQ2Zwq/GjTvH7g==": "https://60ba7ef02e687.streamlock.net/ICNET2/ngrp:icnet_all",
    "cX0R07lZk+F07owThNEOtQ==": "http://51.210.199.7/hls",
    "FYYoCTPhtGktkCo/pU8SoA==": "https://shls-mbcpersia-prod-dub.shahid.net/out/v1/bdc7cd0d990e4c54808632a52c396946",
    "VlEkFHbH1JoaLwaXzBSvSw==": "https://live.presstv.ir/ifilmlive/smil:ifilmtv.smil",
    "Wu1CipjlUAcS19nnZc1LIw==": "https://live1.presstv.ir/live",
    "a6ebKyitjA08T+MG2paMww==": "http://51.210.199.57/hls",
    "DymL3xJHpKbtgFY2RWgRKQ==": "https://dev-live.livetvstream.co.uk/LS-63503-4",
    "/5esN++J5a00Vi6AuBZzRg==": "https://dacastmmd.mmdlive.lldns.net/dacastmmd/f05d55e42dc746c8bd36edafbace7cc1",
    "6PrpN756k5BYV8DcIUawww==": "http://cdn1.live.irib.ir:1935/epg-live/smil:jahanbin",
    "TuMN4kXoy1xtrLjkEnLqTQ==": "http://51.210.199.37/hls",
    "nX//jcqhSjeMHArZYbUQAQ==": "https://live.kalemehtv.tv/live/ngrp:kalemeh_all",
    "vnvROzIGrbxsHPFCQPShLQ==": "https://dh4wkqcyy8768.cloudfront.net",
    "5I66PWA6QD9xCeda6kV15A==": "https://livefa.marjaeyattv.com/mtv_fa",
    "FYYoCTPhtGktkCo/pU8SoA==": "https://shls-mbcpersia-prod-dub.shahid.net/out/v1/bdc7cd0d990e4c54808632a52c396946",
    "nRcfqoc0oCxb2ypw2w4SdQ==": "http://204.11.235.251:1935/live_transcoder/ngrp:mohabat.stream_all",
    "c34yJe+Qp2CaCBMy8u2+wA==": "http://media.mohabat.tv:1935/live_transcoder/ngrp:mohabat.stream_all",
    "fefbxJE8ncl9freCwW/hDQ==": "http://51.210.227.130/hls",
    "OIysZ2vW61XnbELqyd76zA==": "https://iptv.negahtv.com/negahtv/playlist2",
    "EoexjF+DXt66MaGc7YS70A==": "http://51.210.199.38/hls",
    "ndx0/R7HUnhThgmq0KlAwg==": "https://live2.parnian.tv/hls",
    "jTVg2NlR/ZaW7AMS8elpbA==": "https://livestream.5centscdn.com/cls032817/18e2bf34e2035dbabf48ee2db66405ce.sdp",
    "LsRZZ5wTd0FP9bnLFBSKQg==": "https://uni01rtmp.tulix.tv/kensecure/pjtv.stream",
    "U8pAGLv9SzwKoPqOW3/Msw==": "http://g5nl6xx5lpq6-hls-live.5centscdn.com/live1234/2621b29e501b445fabf227b086123b70.sdp",
    "SYyHPX9bvxn3yj36dm4C2g==": "https://uni6rtmp.tulix.tv/ucur1/Payvand",
    "ZRuGM1asrs8uvk9/lokc/Q==": "http://iptv.tapesh.tv/tapesh",
    "3IwUv0FqzucBXR4Y+3m3VQ==": "http://51.210.227.135/hls",
    "y3E02dLTcOkS7EHlO6fXyg==": "https://cinehls.persiana.live/hls",
    "8+d5QVZlyHiOpRW6UDHL0A==": "https://comedyhls.persiana.live/hls",
    "i3tDngcp/QVvVnR23CS1gQ==": "http://51.210.199.23/hls",
    "TJMNSUmIA1Gpx3urCPKWtg==": "https://familyhls.persiana.live/hls",
    "AUPitzb8n2iWlQKHTSAvmA==": "http://51.210.199.13/hls",
    "+oCu8PDFcgyILjGHgdxzlg==": "http://51.210.199.25/hls",
    "NFUp9I6sTq7q1cRiKoJHZw==": "https://play.bazbin.xyz/live/AP%20Persiana%20Science",
    "OXQ0+CEbCsImFy0X07DRxA==": "https://irhls.persiana.live/hls",
    "ScAkWQn9xdvZmppkZmGVhA==": "https://junhls.persiana.live/hls",
    "yRMloIG7e5kwQ+es3Y3KkQ==": "https://korhls.persiana.live/hls",
    "ds79QX6XB5nL2JBddDiAVw==": "https://musichls.persiana.live/hls",
    "T1N3RDQ5wa1g9RxMyB6Ekw==": "https://noshls.persiana.live/hls",
    "z5Pio+imbfEnP//Zj9KXWg==": "http://51.210.199.21/hls",
    "ehwhHKlBAvP5WJui5HgRcA==": "http://51.210.199.59/hls",
    "o9CgN6/IITbnJQyL2ja1Tw==": "https://scihls.persiana.live/hls",
    "rOO6JINbDxMO3xaEg3POPw==": "https://euhls.persiana.live/hls",
    "wF9hxpj9Mtkv/9Oy8K73WQ==": "https://divanhls.wns.live/hls",
    "unyhQRPCqSCsu5M3lQwLGg==": "https://onehls.persiana.live/hls",
    "ZZEdmaDCS7R+hgRDPlPHUw==": "https://twohls.persiana.live/hls",
    "RJycywSEhgJLxuc0h372MA==": "https://persiana-rap.icdndhcp.com/hls",
    "Eds9Mfz0rIs1JpRACyBohA==": "https://af.ayas.ir/hls2",
    "Eds9Mfz0rIs1JpRACyBohA==": "https://af.ayas.ir/hls2",
    "Eds9Mfz0rIs1JpRACyBohA==": "https://af.ayas.ir/hls2",
    "yqELW9wGv8+rPhApIaCQDw==": "https://hd.90minlive.online/live/gemacademy",
    "k2I5JnTwxaDRN724L+OOlA==": "https://hd.90minlive.online/live/gemboll",
    "//RSdG8x+azTw2RCkd3tUg==": "https://hd.90minlive.online/live/gemclass",
    "QDmmSt53VS3NiztK8v6g/g==": "https://gg.hls2.xyz/live/IR+-+GEM+Comedy",
    "1OnUx8/wTBlxO07/RF2GVw==": "https://hd.90minlive.online/live/gemdrama",
    "hoW/OsQN+CT1si8RlxXZhw==": "https://gg.hls2.xyz/live/IR+-+GEM+Drama+Plus",
    "y8FdL8vQYEM7sDCLFTdlGw==": "https://hd.90minlive.online/live/gemfilm",
    "C9H6QjjLZedxzjPESwKgNA==": "https://hd.90minlive.online/live/gemfit",
    "1fYJ4c53dnRASjm2CiY6xw==": "https://hd.90minlive.online/live/gemfood",
    "/HucvAZ2GAzIYcE3MSnc3Q==": "https://hd.90minlive.online/live/gemjunior",
    "GiBCRqG8AEbm4+ALW1tKRQ==": "https://hd.90minlive.online/live/gemkids",
    "eIhZtrqm3lPaievHQlBahw==": "https://gg.hls2.xyz/live/IR+-+GEM+LATINO+TV",
    "UYVt+mcjyUGOos2TIZr2Tw==": "https://hd.90minlive.online/live/gemlife",
    "7Zx8NnfLrTuBcuRAxwS8EQ==": "https://gg.hls2.xyz/live/IR+-+Gem+Nature",
    "Zeo/M5g+oHxMlYXhZzLjPg==": "https://gg.hls2.xyz/live/IR+-+GEM+Property",
    "WGo8F7gZcgAJboTyO0x4hQ==": "https://gg.hls2.xyz/live/IR+-+GEM+Series+Plus",
    "LZ5PL6UO+X2OCkNjd6JZXw==": "https://hd.90minlive.online/live/gemtravel",
    "lndaKeXJePcjwsa/xyBlUw==": "https://hd.90minlive.online/live/gemtv",
    "zMArqWcD33r5IdzpzxKCZQ==": "https://gg.hls2.xyz/live/IR+-+GEM+TV+Plus",
    "5nF3E8ajsGoj50Vgapnq2g==": "https://hls.pmchd.live/hls",
    "HqJJ5K1CunTlqLhuS+oJ+A==": "http://51.210.199.29/hls",
    "pM9HcQn7I+Yutvpodb1ozw==": "http://cdn1.live.irib.ir:1935/epg-live/smil:qazvin",
    "+1p9MT2qA+oKF2PspKeaxg==": "https://stream.rjtv.stream/live/smil:rjtv.smil",
    "KXpxRRPVuD+aEDGBPzBmxw==": "http://cdn1.live.irib.ir:1935/epg-live/smil:sahand",
    "hD7gRIWt/Mw6CdL5U0vWWw==": "https://iptv.salaamtv.org/salaam",
    "S0jr45OLKvbd0+Cg1v7zMg==": "https://svs.itworkscdn.net/sat7parslive/sat7pars.smil",
    "aSAVLUTVNf5tSc5fDTNiOA==": "http://51.210.199.30/hls",
    "BocB9q1bYumiWiPwBEEZcA==": "http://51.254.225.26/hls",
    "3IwUv0FqzucBXR4Y+3m3VQ==": "http://51.210.227.135/hls",
    "7N/q44vyYILvQuWZVGwfOQ==": "https://GLWizHSTB36.glwiz.com:443",
    "ZRuGM1asrs8uvk9/lokc/Q==": "http://iptv.tapesh.tv/tapesh",
    "6IDttRtKH3B82TaEkE/NQA==": "http://rtmp.abnsat.com/hls",
    "CurVR8eqEahg/kuAU1wrsw==": "http://51.210.199.3/hls",
    "NBGHOmICi3H6XpbwpAqv1g==": "http://51.210.199.2/hls",
    "446QVKYcPV3CrZzULSlDXQ==": "https://live.snn.ir/hls/snn",
    "lU21DfM5cB05iyl7Rryg+Q==": "http://208.113.204.104:8123/live/tapesh-live-stream",
    "+PqnztAbNVOOMWvdVYtSKw==": "https://api.new.livestream.com/accounts/27460990/events/8266913",
    "Rh1OxOA9TJMx5SEbzxkvYg==": "https://bozztv.com/1gbw5/tintv/tintv",
    "tMAlh/CfUIUmffSc08OhCw==": "http://avrstream.com:1935/live/towheedtv",
    "b3+kMJAR2KdqvFXhMWFTEQ==": "https://alpha.tv.online.tm/hls",
    "b3+kMJAR2KdqvFXhMWFTEQ==": "https://alpha.tv.online.tm/hls",
    "DUo5a1MH0dBcc37FiCAVvw==": "http://cdn1.live.irib.ir:1935/channel-live/smil:varzesh",
    "bLfyGx6qr1fzprv2/QhHgA==": "http://51.210.199.8/hls",
    "rvwgYWTgGuEFtojXGDtULg==": "http://51.210.199.9/hls",
    "Zt+ZCQeCNaFMqLuUTJCu0g==": "https://live.livestreamtv.ca/azstar/amlst:azstar",
    "P4FyDCAlsnKpdr5NXh6msg==": "https://live-hls-web-ajd.getaj.net/AJD",
    "I5mOfvvQKV8k5Sz/SafF7w==": "https://live-hls-v3-aje.getaj.net/AJE-V3",
    "l3RUyFL0gfOgpat/C3XvLA==": "http://cdn10-alvinchannel.yayin.com.tr/alvinchannel/alvinchannel",
    "ebZ7ibKYT6RmiE3oUCn5Cw==": "http://85.132.81.184:8080/arb24/live1",
    "dSX96KzWi4Zx4JWkHXVT2g==": "http://149.255.152.199",
    "49a9UuOJNr5n/TrNBDHNFw==": "https://artesimulcast.akamaized.net/hls/live/2030993/artelive_de",
    "OMTh7VRZ6wDUuwDb3e8plw==": "http://85.132.81.184:8080/atv",
    "40vW3xo3Za0U/io/wDuziw==": "http://85.132.81.184:8080/atv-2",
    "YtGY32zpfyFOTnc1tnXi9w==": "http://85.132.81.184:8080/atv-4",
    "cvSRkrkrKQp5fpNTuaCRrA==": "https://edge1.socialsmart.tv/aznews/smil",
    "eHnqmzUWXojZlHJIrc+1WA==": "http://okkotv-live.cdnvideo.ru/channel",
    "y55Haq3u1nTMFHYP/mK/Pg==": "https://5c7b683162943.streamlock.net/live/ngrp:bahraininternational_all",
    "+AxGsqTJqCipJYur4mjcKA==": "https://b1world.beritasatumedia.com/Beritasatu",
    "96ti4sbdkN2m079Q5PcklQ==": "https://bloomberg.com/media-manifest/streams",
    "96ti4sbdkN2m079Q5PcklQ==": "https://bloomberg.com/media-manifest/streams",
    "5b5rfY2xtEQpOE0CdiZAoA==": "http://194.163.179.246/slovenci/djeciji",
    "Wkyj8w3VitW3WADrmHeSIQ==": "https://cdn.appv.jagobd.com:444/c3VydmVyX8RpbEU9Mi8xNy8yMDE0GIDU6RgzQ6NTAgdEoaeFzbF92YWxIZTO0U0ezN1IzMyfvcGVMZEJCTEFWeVN3PTOmdFsaWRtaW51aiPhnPTI/btvbd-office-sg.stream",
    "tKNZnPJ74QY3RNm0/A0D0Q==": "http://116.199.5.51:8114/00000000",
    "zjWtAfoB/tX8OGLszq/Tbw==": "http://39.135.138.59:18890/PLTV/88888910/224/3221225645",
    "+j534UCdCZea+dQJfUDLdQ==": "https://news.cgtn.com/resource/live/french",
    "p/8j843fR7xlGPy/h/JiFg==": "https://news.cgtn.com/resource/live/russian",
    "2MAOCOezFf6T/mzO1v1LUA==": "https://classicarts.akamaized.net/hls/live/1024257/CAS",
    "Y2zgVK1sbpcAW3f9CwZ7gQ==": "https://d2e1asnsl7br7b.cloudfront.net/7782e205e72f43aeb4a48ec97f66ebbe",
    "r8GxVE4eVOvfOD+WODaMnA==": "https://cnn-cnninternational-1-de.samsung.wurl.com/manifest",
    "V4s9/IJFjcaagu7kSQsgSw==": "https://dai.google.com/linear/hls/event/xuMJ1vhQQDGjEWlxK9Qh4w",
    "NXkklf+lcnNEVjXKGMiltg==": "https://dwamdstream102.akamaized.net/hls/live/2015525/dwstream102",
    "mAoEdxCDh9uyAVqj65S9BA==": "https://euc-live.fl.freecaster.net/live/eucom",
    "mAoEdxCDh9uyAVqj65S9BA==": "https://euc-live.fl.freecaster.net/live/eucom",
    "hY505vzqV4jd4hM5FpxNmA==": "http://85.132.53.162:1935/live/eltv",
    "YgdPV6QbjPoV4SiBC5vFIA==": "https://ert-live-bcbs15228.siliconweb.com/media/ert_world",
    "4u7/XAMcC7XaWCge9cM8qQ==": "https://multimedia.eitb.eus/live-content/eitbbasque-hls",
    "Yutqo46JgM+HGA0JZzSV9g==": "http://178.33.224.197:1935/euroindiemusic/euroindiemusic",
    "JWLk7V7I10ctpXGB4ZrHng==": "https://euronews.alteox.app/hls",
    "JWLk7V7I10ctpXGB4ZrHng==": "https://euronews.alteox.app/hls",
    "JWLk7V7I10ctpXGB4ZrHng==": "https://euronews.alteox.app/hls",
    "JWLk7V7I10ctpXGB4ZrHng==": "https://euronews.alteox.app/hls",
    "JWLk7V7I10ctpXGB4ZrHng==": "https://euronews.alteox.app/hls",
    "GJo2mJs03dfC1tResnbujQ==": "https://cdn3.wowza.com/1/T2NXeHF6UGlGbHY3/WFluRldQ/hls/live",
    "HY2PM7HRqKiBYbHeW4EPUw==": "https://fashiontv-fashiontv-1-eu.rakuten.wurl.tv",
    "AYu4coeA/9fTxTrmrTc7Ag==": "https://shls-fight-sports-ak.akamaized.net/out/v1/ee7e6475b12e484bbfa5c31461ad4306",
    "bkloxYP8eXtCs92H8dr7PQ==": "http://seb.sason.top/ptv",
    "b0/l1tSMedNve3sEjEFFUg==": "http://europa-crtvg.flumotion.com",
    "If8jCYSEXmiExq3yOdCMuw==": "http://109.205.166.68/server124/idman_az",
    "J7bV1npzLD1bSt3edUEPig==": "https://insighttv-vizio.amagi.tv",
    "usTG+eNM3uB6f+j4e4ZFhQ==": "https://livecdn.fptplay.net/sdb/kbs_hls.smil",
    "pt7MDZPmVVgAI1Qp4jbAMg==": "http://85.132.81.184:8080/arbkepez/live",
    "2of2ap0iRiD2e+gyxXCP/g==": "https://mavtv-mavtvglobal-1-eu.rakuten.wurl.tv",
    "74cZU/OWnaVvGJX5+sAUPw==": "https://edge.medcom.id/live-edge/smil:mgnch.smil",
    "JvidO6+g58vcG5W+anJT8Q==": "https://live.mnb.mn/live/mnb_world.stream",
    "QPymE5oySPwlyJmeEWB2uw==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/60817e1aa6997500072d0d6d",
    "REPAUpvrg3gMz4QJRePp1g==": "http://cdn10-mugantv.yayin.com.tr/mugantv/mugantv",
    "GitFx8IrZ/W8vqRmn9du6A==": "https://uplynkcontent.sinclairstoryline.com/channel",
    "KaegJEBG37NPw1Tz0jQHBg==": "https://thainews.prd.go.th/lv/live/ch1_L_L.sdp",
    "L5QnY7bEO20HQkOQOeek6A==": "https://ndrint.akamaized.net/hls/live/2020766/ndr_int",
    "VN+udTWeJepO8iDw5RxZuw==": "https://nhkwlive-ojp.akamaized.net/hls/live/2003459/nhkwlive-ojp-en",
    "kdpcnWqrzCn/d5Gu0l7FAQ==": "https://cdn.appv.jagobd.com:444/c3VydmVyX8RpbEU9Mi8xNy8yMDE0GIDU6RgzQ6NTAgdEoaeFzbF92YWxIZTO0U0ezN1IzMyfvcGVMZEJCTEFWeVN3PTOmdFsaWRtaW51aiPhnPTI/ntvuk00332211.stream",
    "QYy3CGJ8PDCNgAwNAv008w==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/60d3583ef310610007fb02b1",
    "OHURMQ20c3XG1d9rjnlX+A==": "https://qebele.tv/live/stream",
    "1981x7cgJBtE/g1YSXCofw==": "https://rbmn-live.akamaized.net/hls/live/590964/BoRB-AT",
    "yB7ai0qGiVRsjmzcVAkC3Q==": "https://strm.yandex.ru/kal/rtd_hd",
    "WAMts5YHum0fPUgLabvVkA==": "https://rt-esp.rttv.com/live/rtesp",
    "JumcDpUS7rW1DnXec2SxRA==": "https://cdn-telkomsel-01.akamaized.net/Content/DASH/Live/channel(9ce3f094-4044-467e-84b7-b684a49571d5)",
    "8ZJOT0Fu9KXH2OO71TzHNw==": "https://d2xeo83q8fcni6.cloudfront.net/v1/master/9d062541f2ff39b5c0f48b743c6411d25f62fc25/SkiTV-SportsTribal",
    "vC0TBBT5ICp/Z5p7oMl5Yw==": "https://sofy-ger-samsung.amagi.tv",
    "MB5jf7RqaL6l8DbInZjP+A==": "https://dai.google.com/linear/hls/event/YoBM0ae5Q62TPdrfFHS4RQ",
    "ITZ54bhacykdOOy12bercg==": "https://3abn-live.akamaized.net/hls/live/2010544/International",
    "/FPo45IS3/fRT+gPcxiO5g==": "https://api.trtworld.com/livestream/v1/WcM3Oa2LHD9iUjWDSRUI335NkMWVTUV351H56dqC",
    "Pz09D9cqyHJvQ5nevq5Nfg==": "https://directes-tv-int.ccma.cat/live-origin/tvi-hls",
    "5tzMei9tk4l9C7r3ye/xrA==": "http://online.tvm.co.mz:1935/live/smil:Channel2.smil",
    "V0abrzOtmdDRHmnDYQ208w==": "https://cdnapi.kaltura.com/p/2503451/sp/250345100/playManifest/entryId/1_gb6tjmle/protocol/https/format/applehttp",
    "2A/kU7Vijkxl7e49+2eA1A==": "https://jukin-weatherspy-2-eu.rakuten.wurl.tv",
    "N4hLefilD/Dw7LpEiiVj8w==": "http://210.210.155.37/uq2663/h/h91",
    "k5cANuOUJiysRlmEWy5yZQ==": "https://d3w4n3hhseniak.cloudfront.net/v1/master/9d062541f2ff39b5c0f48b743c6411d25f62fc25/WPT-SportsTribal",
    "JNzZv3uuMfI6jCAVBFzKXg==": "https://livevideo01.wkyc.com/hls/live/2015504/newscasts",
    "7QrQzTAFwBopayKynXFrcQ==": "https://csm-e-boxplus.tls1.yospace.com/csm/extlive/boxplus01,boxhits-alldev.m3u8?spotxc1=195996&spotxc2=190878&yo.up=https://boxtv.secure.footprint.net/boxhits",
    "+Vjfe8kiif9X43HjO50s3w==": "http://158.69.124.9:1935/5aabtv/5aabtv",
    "P9Q5SzeRY71HbrC6Ob1P5A==": "https://livevideo01.12newsnow.com/hls/live/2017379/newscasts",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "G1x6ei8OKhNxvJcPHUW7Rw==": "https://d15690s323oesy.cloudfront.net/v1/master/9d062541f2ff39b5c0f48b743c6411d25f62fc25/UDU-Plex2",
    "24ELM9r/fh8pMGBZbiteuw==": "https://30a-tv.com",
    "3P2UqNhbYpGaNk8EDla7Hg==": "https://30a-tv.com/feeds/xodglobal",
    "24ELM9r/fh8pMGBZbiteuw==": "https://30a-tv.com",
    "24ELM9r/fh8pMGBZbiteuw==": "https://30a-tv.com",
    "24ELM9r/fh8pMGBZbiteuw==": "https://30a-tv.com",
    "/mZf0cp3SlWKs+uyWONWPQ==": "http://100automoto.tv:1935/bgtv1/autotv",
    "yRqAGNyBi0BRhIo+EHxwsA==": "http://hlsdpi-cdn-chqtx02.totalstream.net/dpilive/247retro/ret/dai",
    "Zu/payMwEwRuJaNeKHC+RQ==": "https://streamer1.connectto.com/AABC_WEB_1201",
    "i9DhmeWXrah8Wo+o1jf9pA==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/AACTelevision",
    "ImI1rEvKwudEkK6crpe+dA==": "https://d2rwx6gwduugne.cloudfront.net/v1/master/77872db67918a151b697b5fbc23151e5765767dc/cmg_PROD_cmg-tv-10010_183ec1c7-4183-4661-803b-3ed282ffb625_LE/in/cmg-wsbtvnow-hls-v3",
    "ERq/AupIa+9i3lKrUhYfHw==": "http://cms-wowza.lunabyte.io/wbrz-live-1/_definst_/smil:wbrz-live.smil",
    "0KlTJVmuMDxRZ9TqkwNNOg==": "https://livevideo01.kiiitv.com/hls/live/2017378/newscasts",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "5ZctMvzZDdzpIFmtupqlCw==": "https://content.uplynk.com",
    "EmZkIKUucmBa5P8uP0tPvQ==": "https://livevideo01.weareiowa.com/hls/live/2011593/newscasts",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "cl2efnEBV+imh4+Iswsc/Q==": "https://content.uplynk.com/channel/ext/2118d9222a87420ab69223af9cfa0a0f",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "5ZctMvzZDdzpIFmtupqlCw==": "https://content.uplynk.com",
    "I+wpmghbTI0d14+x9Ltp6w==": "https://livevideo01.wfaa.com/hls/live/2014541/newscasts",
    "bvZQ65mvFE0tL7anDSqejA==": "https://livevideo01.wqad.com/hls/live/2011657/newscasts",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "OoiNSzbMEnGjujQoJrsS0g==": "https://d3qm7vzp07vxse.cloudfront.net/v1/master/77872db67918a151b697b5fbc23151e5765767dc/cmg_PROD_cmg-tv-10070_fe1f5f6c-cd0b-4993-a4a4-6db66be4f313_LE/in/cmg-wftvtv-hls-v3",
    "ORolVGpresek9lXnP5Bnaw==": "https://livevideo01.abc10.com/hls/live/2014547/newscasts",
    "1uN41j+MMPXVuFypCy8wRA==": "https://livevideo01.whas11.com/hls/live/2016284/newscasts",
    "cBzRst2hPltfehsgGUVREw==": "https://livevideo01.wzzm13.com/hls/live/2016280/newscasts",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "8upsIvXH0pz1IuwKfatGng==": "https://livevideo01.13newsnow.com/hls/live/2014545/newscasts",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "jlkxmsqwpkG8+nBMd0Ddxg==": "https://livevideo01.wnep.com/hls/live/2011655/newscasts",
    "+bgLDG5PDtfVC1xN7JiEtA==": "https://livevideo01.kvue.com/hls/live/2016282/newscasts",
    "3uULXkxaEYqFskhu/+sTWA==": "https://livevideo01.localmemphis.com/hls/live/2011654/newscasts",
    "sG3YONP7DT+Zgg+01CzTKg==": "https://16live00.akamaized.net/ABC_EAST",
    "f2zKranQC5DMSntmZQ3S8g==": "https://c.mjh.nz",
    "f2zKranQC5DMSntmZQ3S8g==": "https://c.mjh.nz",
    "YjBm1+klM797JJ7zsuwJWA==": "https://abc-iview-mediapackagestreams-2.akamaized.net/out/v1/6e1cc6d25ec0480ea099a5399d73bc4b",
    "p2SUUeuA9JbCe6cUfBGdqQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-abcnews/CDN",
    "7Fk3EreiPFMi6jDky58Prg==": "https://abcnews-streams.akamaized.net/hls/live/2023560/abcnews1",
    "QCIQS+cjpxrSMlvqGAP4jw==": "https://abcnews-streams.akamaized.net/hls/live/2023561/abcnews2",
    "UHGbeFOIc9dkT7ogksQuFA==": "https://abcnews-streams.akamaized.net/hls/live/2023562/abcnews3",
    "SBWC99jzlt3trBPmpRoz9A==": "https://abcnews-streams.akamaized.net/hls/live/2023563/abcnews4",
    "68Fm8kYKlA0cb3sspsVRAQ==": "https://abcnews-streams.akamaized.net/hls/live/2023564/abcnews5",
    "bdmWhAN3jcZsM8ZkwZNruw==": "https://abcnews-streams.akamaized.net/hls/live/2023565/abcnews6",
    "sMMPjkwyBmNq2JaTKanWtg==": "https://abcnews-streams.akamaized.net/hls/live/2023566/abcnews7",
    "So92IbqqnyPKyZXaQMdN8Q==": "https://abcnews-streams.akamaized.net/hls/live/2023567/abcnews8",
    "tDqN3wTufPyGSMZlwkXfOA==": "https://abcnews-streams.akamaized.net/hls/live/2023568/abcnews9",
    "XdthyPW3Udp2bd5bKy4z8g==": "https://abcnews-streams.akamaized.net/hls/live/2023569/abcnews10",
    "RHUGektTWk/uc53PFvz/DA==": "https://content.uplynk.com/channel/ext/72750b711f704e4a94b5cfe6dc99f5e1",
    "f2zKranQC5DMSntmZQ3S8g==": "https://c.mjh.nz",
    "f2zKranQC5DMSntmZQ3S8g==": "https://c.mjh.nz",
    "Ddkx4L1A7ajoDyQTN+IHfA==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.twitch.tv",
    "6IDttRtKH3B82TaEkE/NQA==": "http://rtmp.abnsat.com/hls",
    "OjLAtttYaF+v1Oaz4G5IMA==": "https://abplivetv.akamaized.net/hls/live/2043010/hindi",
    "oRXBK6BUAANm4hQMtUrO/w==": "https://admdn1.cdn.mangomolo.com/adsports1/smil:adsports1.stream.smil",
    "3JKrOWyxLB5se/swa54Y+w==": "https://admdn5.cdn.mangomolo.com/adsports2/smil:adsports2.stream.smil",
    "IVIjlOkhyfwWbI0q01xj6g==": "https://admdn4ta.cdn.mgmlcdn.com/adsports4/smil:adsports4.stream.smil",
    "NvgI18hxXbOr/+CDxdKA2A==": "https://a.jsrdn.com/broadcast/542cb2ce3c/+0000",
    "E54OmWnBnDj/ac2cs2lh8g==": "https://dacastmmd.mmdlive.lldns.net/dacastmmd/66dfbe35ca1a418c87e3cf18ca46bd57",
    "BJSSIIqqxZjWlnU702YisQ==": "https://ampmedia.secure.footprint.net/egress/bhandler/ampmedia/streama",
    "wKDahFOvzADldQi++IfNKw==": "https://ampmedia.secure.footprint.net/egress/bhandler/ampmedia/streamb",
    "MbNzr7uRsJFxeJuCrvso4Q==": "https://reflect-access-sacramento.cablecast.tv/live-7/live",
    "0cBEftglceivcr5DmIlxuA==": "https://reflect-access-sacramento.cablecast.tv/live-8/live",
    "xR7EvF+PlGBDGxvuUNY1NA==": "https://reflect-tuolumne.cablecast.tv/live-3/live",
    "Jii/Ibh7RQbOn93CC7Ekrw==": "https://amg00684-accuweather-accuweather-rokuus-0endj.amagi.tv",
    "ShaRccl8Bos/hxcHzwZ2Jg==": "http://31.220.41.88:8081/live/us-cinemaxaction.stream",
    "YaTWFiMwXtpnxLirtCpgkg==": "https://adultswim-vodlive.cdn.turner.com/live/aqua-teen",
    "nc9h8Xv4oRZTI6lgGBcs7g==": "http://adultswim-vodlive.cdn.turner.com/live/black-jesus",
    "GKTYlqjfDDeLTo1f6BP2HQ==": "https://adultswim-vodlive.cdn.turner.com/live/channel-5",
    "6JyyE5YNdHiRTtoB+NYhXg==": "http://adultswim-vodlive.cdn.turner.com/live/DREAM-CORP-LLC",
    "GAAuC9QK6lSH1HwrFtk2xw==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023183/aseast/noslate",
    "hWgpkbhRQ+8cvQns87TOdA==": "https://adultswim-vodlive.cdn.turner.com/live/infomercials",
    "dlJsBqehLYRnHBZu08Q0Jw==": "https://adultswim-vodlive.cdn.turner.com/live/lsotl",
    "1uA6ClaU+MU6fvOf+woOFQ==": "http://adultswim-vodlive.cdn.turner.com/live/metalocalypse",
    "a/eaAaNhM7/CU9+NR5EV9Q==": "https://adultswim-vodlive.cdn.turner.com/live/off-the-air",
    "z9Nj7DTfi8Pm/gG8EpPyhw==": "https://adultswim-vodlive.cdn.turner.com/live/robot-chicken",
    "SJkLsheM5bgXwZF/xalb/g==": "https://adultswim-vodlive.cdn.turner.com/live/samurai-jack",
    "Qj/7VPq0wuFxT9wjOUvXkQ==": "http://adultswim-vodlive.cdn.turner.com/live/eric-andre",
    "4+ebFtjyrdPjG/NQCQUh6Q==": "https://adultswim-vodlive.cdn.turner.com/live/venture-bros",
    "wRxEgwjlx7s6gjhtqwCL5Q==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023185/aswest/noslate",
    "7XSPKKYToDEymM652eMuOw==": "https://adultswim-vodlive.cdn.turner.com/live/ypf",
    "o93bfhrodskE5shyJB4arA==": "https://gizmeon.s.llnwi.net/channellivev3/live",
    "AW1dAHz/rQHisNDmHPsVzg==": "http://africatv.live.net.sa:1935/live/africatv3",
    "Izj4OtMHwN7iQafFWY5ixQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/africanews",
    "zSm9kCXl0Y+bWckts4ogNw==": "https://stream.ecable.tv/afrobeats",
    "nHUdkzWSXQTo7h3aL/9zMg==": "https://dai.google.com/linear/hls/event/18_lZXPySFa5_GRVEbOX_A",
    "yTtS+11WHg150E3rK05sQA==": "https://5b622f07944df.streamlock.net/aghapykids.tv/aghapykids2",
    "1KgF0cXLUVvE8Z9PYAnydw==": "http://109.123.126.14:1935/live/livestream1.sdp",
    "Izhfkw5c5GbTNac2A4xMHg==": "https://cdnamd-hls-globecast.akamaized.net/live/ramdisk/akaal_tv/hls1_smart_akaal",
    "1o06wBSSl6AcY7wPAu89ZA==": "https://castus-vod-dev.s3.amazonaws.com/vod_clients/akaku/live/ch1",
    "2QXwEOKK+CxO1bt+hLYNvw==": "https://castus-vod-dev.s3.amazonaws.com/vod_clients/akaku/live/ch2",
    "Icu013pQ8IveYgwF3uJa8Q==": "https://castus-vod-dev.s3.amazonaws.com/vod_clients/akaku/live/ch3",
    "fMJ0wIqJ4QjYSqJji1J4xQ==": "https://broadcast.blivenyc.com/speed/broadcast/22",
    "W9ki4EJMsAGkswhB6fB0gw==": "https://broadcast.blivenyc.com/speed/broadcast/71",
    "Dx6SDx+RE+oUZ7FhgtO0sg==": "https://broadcast.blivenyc.com/speed/broadcast/29",
    "tnJDX6iNB2USaB1vxtoXOg==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.dailymotion.com/video",
    "RIDmgzzTyRuX4ckg2QjV7Q==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/aljazeeraenglish",
    "3QbHAGky0d6j7txMb4yxPA==": "https://stream.al-mahdi.tv/hls",
    "HWOSIP0XbOdrXGfs2v1zuw==": "https://althingi-live.secure.footprint.net/althingi/live",
    "+ASbDae4QUkY9qr34TKTxg==": "https://uni01rtmp.tulix.tv/amazingdtv/amazingdtv",
    "xjPe/kfVp6tjFnmIt+AGLg==": "https://bcovlive-a.akamaihd.net/ebf15ff84e98490e8b00209ed77c77f5/us-east-1/6240731308001",
    "kRLGQJf8tj/D2hGu8bu7Iw==": "https://bcovlive-a.akamaihd.net/bdbdca51c15243fbaca92fd54c42d45a/us-east-1/6245817279001",
    "9gv2Zn3UEx6//3fQOKp35Q==": "https://okkotv-live.cdnvideo.ru/channel",
    "Se2A9jF0+94r2/sTVj9mPg==": "https://uni01rtmp.tulix.tv/americateve1/americateve1",
    "8G/JHLq+gz22ia722GIKCw==": "https://dai.google.com/linear/hls/event/-A9339ixSzydnZQZHd1u2A",
    "HY59eX0Wvm4uUamUHwRdoQ==": "https://p1media-americasvoice-1.roku.wurl.com/manifest",
    "181wexkPT6t8RL9WOxYdJw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxamericanclassics/CDN",
    "H7m7mu7rujx1VKFV/8jxOQ==": "http://170.178.189.66:1935/live/Stream1",
    "vbIPrtfW7DoNgPPa4cFeGA==": "https://tdameritrade-vizio.amagi.tv",
    "FaE9xnqlO1gvfSb4lw+BcA==": "https://2-fss-2.streamhoster.com/pl_138/201660-1270634-1",
    "lHi/Ro2QOtJmORLkAse9pA==": "https://streamer1.connectto.com/AMGA_WEB_1202",
    "8u5fn7ZLhMh60pxPQwsutA==": "http://210.210.155.37/dr9445/h/h02",
    "7e0vMtaoS6FmYnSVKjUo3A==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxarchitecturaldigest/CDN",
    "hd6uOjdjhFWtXLM0b0CIWQ==": "http://amdlive-ch01.ctnd.com.edgesuite.net/arirang_1ch/smil:arirang_1ch.smil",
    "LA219V4c7xWtnDO7LwsQRg==": "https://news.ashttp9.visionip.tv/live/visiontvuk-news-arise-tv-hsslive-25f-16x9-SD",
    "T0P1RX/mmofo74bSoSBE1g==": "https://arktelevision.org/hlslive/test",
    "uCLo7haJ17mgn9HNTtoukA==": "https://ketsdt.lls.pbs.org/out/v1/03c094dbd7874a4a8c3fe9fb10081bdb",
    "/LruKMsK7QInkRnluE9ZuQ==": "https://agp-nimble.streamguys1.com/AGCC/AGCC",
    "7IdoFhrwWxBT1FGppM4YrA==": "https://ed1ov.live.opencaster.com/GzyysAAvEhht",
    "P/2Ab+kRqGM6PDWQnOwgGA==": "http://104.238.221.63:9138/stream/live",
    "P/2Ab+kRqGM6PDWQnOwgGA==": "http://104.238.221.63:9138/stream/live",
    "P/2Ab+kRqGM6PDWQnOwgGA==": "http://104.238.221.63:9138/stream/live",
    "th6R7ZOSuDYb1iYkXoKHAw==": "http://172.96.160.37:9138/stream/live",
    "th6R7ZOSuDYb1iYkXoKHAw==": "http://172.96.160.37:9138/stream/live",
    "bxgkmr+jIyWgU7riSArzKA==": "http://172.96.140.34:9138/stream/live",
    "2PIIFpR8/yjghiLnA4mtVQ==": "http://media4.tripsmarter.com:1935/LiveTV/ACVBHD",
    "3NJxAiEo1vj2RNYkjV2Gaw==": "https://uni01rtmp.tulix.tv/watc57/watc57",
    "PhSeRoqn/dEThOxCcxQNqw==": "https://uni01rtmp.tulix.tv/watc57-2/watc57-2",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "R+82R1Z13SZPzXrYJUWUMw==": "https://reflect-aurora.cablecast.tv/live-8/live",
    "u+/m9mGinAK5QAY0bjU2jA==": "https://bk7l2pn7dx53-hls-live.5centscdn.com/austamil/fe01ce2a7fbac8fafaed7c982a04e229.sdp",
    "Wt2V5T22mbWJizrelj2vWA==": "https://d9quh89lh7dtw.cloudfront.net/public-output",
    "FWPUWVQbM+JH6eFgbrP8OA==": "https://streamone.simpaisa.com:8443/pitvlive1/awaztv.smil",
    "u2RtlHu3KXkBFC0Q4Jb0KA==": "http://n1.klowdtv.net/live1/awe_720p",
    "FyKmrENUhl3lnsmDZioujg==": "https://aweencore-vizio.amagi.tv",
    "J41f5+qycQJRqrOYrGmIyA==": "https://dikcfc9915kp8.cloudfront.net/hls/1080p",
    "/M3X8xDNPAXp1xSoOsph6g==": "https://2nbyjjx7y53k-hls-live.5centscdn.com/cls040318/b0d2763968fd0bdd2dc0d44ba2abf9ce.sdp",
    "1TiC/yLk7V2VYiI3RBV7mA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxbaeble/CDN",
    "y55Haq3u1nTMFHYP/mK/Pg==": "https://5c7b683162943.streamlock.net/live/ngrp:bahraininternational_all",
    "i9SHE2V5x2npHyUs8PqlJw==": "https://vblive-c.viebit.com/072e341f-100d-4da1-9c18-65370ebf35c6",
    "PJGvwCqbZrxOgVfKu4j1iA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxbatterypop/CDN",
    "VDvyTen+6t5pNTF8gegsXQ==": "https://vs-cmaf-pushb-uk.live.fastly.md.bbci.co.uk/x=3/i=urn:bbc:pips:service:bbc_alba",
    "c2OSXNTXEakZm4N+9Nc0RQ==": "https://bcovlive-a.akamaihd.net/c9bf201b06694453bb29282f97191f58/us-east-1/6240731308001",
    "ThNp9Mnf1hFetaGp2bmJSw==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_four_hd",
    "R5wKAyBXVeJigUO1ri2vGA==": "https://vs-cmaf-pushb-uk.live.fastly.md.bbci.co.uk/x=3/i=urn:bbc:pips:service:bbc_four_hd",
    "e7CZV65RRrz9+wLAe73N/Q==": "https://cdnuk001.broadcastcdn.net/KUK-BBCNEWSHD",
    "D47OsYoPsNMe6FEK3PCJDQ==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_cambridge",
    "AO212DXWMfsIGeHRBw+0bQ==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_channel_islands",
    "9RTjXcYq+WPGavgJ6gjikQ==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_east",
    "KzdyJB1VB1x2XIeSJ01Q2g==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_east_midlands",
    "eW5yY6y1sgnJ24ZMcVWsng==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_east_yorkshire",
    "uBpPabVL1E9JpfpK+AMN/w==": "http://w4.12all.tv:4000/play/bbc1",
    "4VNpVfWFuKU9YveoC61ZpA==": "https://vs-hls-push-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_london",
    "rEUAJDW1OC5LH3a/Ibilbg==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_north_east",
    "T9m+ayMu23EhAmfKazjmUA==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_north_west",
    "82LZUCTY7qS2kDhVpSj7/g==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_northern_ireland_hd",
    "oFbBIyiBAM/lsa5mT/kf1g==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_northern_ireland_hd/t=3840/v=pv14/b=5070016",
    "fu0zKkZxHTemtqjDRp0sVQ==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_oxford",
    "EiA6n0P5OZrGslcrmLYCnQ==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_scotland_hd",
    "fRXe60829qWi0VtIYMHKKA==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_scotland_hd/t=3840/v=pv14/b=5070016",
    "ZrGd9z5/BdLQaqmmNZwoVw==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_south",
    "tn1CtPoLG2HKvHfNW3koRA==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_south_east",
    "BhleXDd3iR9Ny9n0xbchcg==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_south_west",
    "zG2ESL8abzm45xmVxb0prg==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_wales_hd",
    "exVy2bKEDCkqyhiluAQVng==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_wales_hd/t=3840/v=pv14/b=5070016",
    "NLRe/Pi7mYt5OTDvQUc41g==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_west",
    "Sxm1sPcjEEtPTBZRPPIMPA==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_west_midlands",
    "rL6cmFQw0XBJLtar28BASg==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_one_yorks",
    "q1W4iRjoEa1OuCnt1NYXZQ==": "https://vs-cmaf-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_parliament",
    "qH7DX0ERyfJbye0CoqvBVA==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_01/sport_stream_01.isml",
    "hSVEk2DJeoeczvzzf47vmg==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_02/sport_stream_02.isml",
    "h+I59rMxhCGcT7T6Yx6nQw==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_03/sport_stream_03.isml",
    "9uBGfHVnqntioWvBAn/KHw==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_04/sport_stream_04.isml",
    "TjbMuTWBbaSKUB0lGHQFsw==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_05/sport_stream_05.isml",
    "i4uqRaBljvnOBS4bM/oatQ==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_06/sport_stream_06.isml",
    "/fMKLej7R8OmEvWwUbH+Ew==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_07/sport_stream_07.isml",
    "HCsVK7NijhxxZc7+du0xBQ==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_08/sport_stream_08.isml",
    "DIPWIuC2zj9ZF3GLqYj90g==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_09/sport_stream_09.isml",
    "DdhIiQIfkI2NR/yPzTPYtw==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_10/sport_stream_10.isml",
    "dhLTebx6gc4+hS3nvmkbxQ==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_11/sport_stream_11.isml",
    "zJGw/QPR4U1UgK1S+DacfA==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_12/sport_stream_12.isml",
    "h9ivnAFkP0eXq8br+lo1ww==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_13/sport_stream_13.isml",
    "AuMq7gp69RICyan8ym5uEA==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_14/sport_stream_14.isml",
    "iY6fPBjpBA5xJ4IervtmoQ==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_15/sport_stream_15.isml",
    "RlIeWZrNXIWIu15ucIjTkQ==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_16/sport_stream_16.isml",
    "bzvy9IXjhaltZpSm5CppJA==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_17/sport_stream_17.isml",
    "MnKsoljPGJzoclRa62ez/Q==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_18/sport_stream_18.isml",
    "TQ1S2yXpAYqgCJ6CZgdrMw==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_19/sport_stream_19.isml",
    "4FSVp5u+BNXx/mo9vbzwAQ==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_20/sport_stream_20.isml",
    "e+HDsjljhXxJdnCYugURpg==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_21/sport_stream_21.isml",
    "SQStOfDwwx4oxk416Vwqnw==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_22/sport_stream_22.isml",
    "LLReLgz3D/oDZ842B7WdMA==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_23/sport_stream_23.isml",
    "kvmjDTpdl9rzJXHWHgO2rQ==": "https://ve-dash-uk-live.akamaized.net/pool_901/live/uk/sport_stream_24/sport_stream_24.isml",
    "kq+7+SwhrSqYePw9NAQ7Nw==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_scotland_hd",
    "F89Ou5kHudW8A2Gbkf0W4Q==": "https://vs-cmaf-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_scotland_hd",
    "x6+CSl/J93wl9SoPlgOiaw==": "https://vs-cmaf-pushb-uk.live.fastly.md.bbci.co.uk/x=3/i=urn:bbc:pips:service:bbc_three_hd",
    "AbQdfIICYygQn45NwSqB7Q==": "http://start.agmediachandigarh.com/gaundapunjab/tv",
    "/mkBxUVqj7vqrSMEwDv/Yw==": "https://vs-hls-push-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_two_hd",
    "pFs6ReqUTOb+dmrEqpEXjA==": "http://w4.12all.tv:4000/play/bbc2",
    "qZinRYo21fJ/7s1yF0rJJg==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_two_northern_ireland_hd",
    "cjn/75XN/UOnR8FrCdAUnw==": "https://vs-hls-pushb-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_two_northern_ireland_hd/t=3840/v=pv14/b=5070016",
    "Ke0jVkdTmZXC15EXP8cS+g==": "https://vs-hls-push-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:bbc_two_wales_digital",
    "cR1k2wjJZBDyYr7WGjqw1g==": "https://ve-uhd-push-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:uhd_stream_01",
    "8X8JYmenrLp3u6HeAFDDgw==": "https://ve-uhd-push-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:uhd_stream_02",
    "2gggZdnjuW2/rabvLWPPgA==": "https://ve-uhd-push-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:uhd_stream_03",
    "/P3ooHprTHBEbzIzr0xjIQ==": "https://ve-uhd-push-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:uhd_stream_04",
    "fN7YfpYMaq1e1R/z1RtSaA==": "https://ve-uhd-push-uk-live.akamaized.net/x=3/i=urn:bbc:pips:service:uhd_stream_05",
    "X/NaHJGpntCXPUDwp5z/sg==": "http://stream04.amp.csulb.edu:1935/Beach_TV/smil:BeachTV.smil",
    "W+Gk385KAnHB7Y9Um5xJ+A==": "http://media4.tripsmarter.com:1935/LiveTV/DTVHD",
    "IC2ADiJhG6SfSBiQ7MjTEQ==": "https://5ed325193d4e1.streamlock.net:444/LiveTV/KTVHD",
    "FhqI6tFBB2NyFgMK7ceJ1g==": "http://media4.tripsmarter.com:1935/LiveTV/MTVHD",
    "+A94DFBv+3OlwrxSZnNmPg==": "http://media4.tripsmarter.com:1935/LiveTV/BTVHD",
    "jQaKZDaWIS4pFVwUhYyWMg==": "https://a7b60a6853d843dd9105acfa8d6e74c7.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Samsung-gb_BeanoTV",
    "4zvGJOucc3iV0C6NGrGQBw==": "https://cdn3.wowza.com/5/ZWQ1K2NYTmpFbGsr/BEK-WOWZA-1/smil:BEKPRIMEeast.smil",
    "UvWHQHEF3mgpyOVrYfOKQg==": "https://cdn3.wowza.com/5/ZWQ1K2NYTmpFbGsr/BEK-WOWZA-1/smil:BEKPRIMEW.smil",
    "dXMmIkti9wbe4j+QbCDeKw==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/channel/UCtj2xA6lW9BPE4BxnhxQQkw",
    "+AxGsqTJqCipJYur4mjcKA==": "https://b1world.beritasatumedia.com/Beritasatu",
    "KhoGJ1sWqfGBJqRcJGgY0g==": "https://uni5rtmp.tulix.tv/betterhealth/betterhealth",
    "/8fDbFihyCuMtKS+OOHAhQ==": "https://uni5rtmp.tulix.tv/betternature/betternature",
    "JpEmSXGXN2DPlQ8ByIFJLA==": "https://uni5rtmp.tulix.tv/betterlife/betterlife",
    "lEcRvfQhDx0t20YU7FdHbg==": "https://cdn3.wowza.com/5/V2Y2VmhqMEFDTUkx/beverlyhills/G0072_006",
    "m/MHNGK/2cCzUl5ZRP6dkA==": "https://cdn3.wowza.com/5/V2Y2VmhqMEFDTUkx/beverlyhills/G0072_007",
    "dS+dMmmNvDahRF6ui8Ny+w==": "http://stream.iphonewebtown.com:1935/bibleexplorations/bexplorationsmobile.stream",
    "5lHPNt3mTlakNBVehRQHwg==": "https://biglife.sinclair.wurl.com/manifest",
    "DFdAypdkOk/A4YwxnVCSqQ==": "https://thegateway.app/BizAndYou/BizTV",
    "Kut6edzVGRO+SAzts0rESA==": "http://redbox-blacknewschannel-xumo.amagi.tv",
    "pEua5x9zgKuAvP32LqyzRQ==": "https://theblaze4.akamaized.net/hls/live/699982/theblaze/cm-dvr",
    "RLFcOV9exQewX1KOqBhIrA==": "https://bloodydisgusting-ingest-roku-us.cinedigm.com",
    "Tx4ve1ldOIP39tBUt7bRdw==": "https://bloomberg-quicktake-1-fi.samsung.wurl.com/manifest",
    "96ti4sbdkN2m079Q5PcklQ==": "https://bloomberg.com/media-manifest/streams",
    "96ti4sbdkN2m079Q5PcklQ==": "https://bloomberg.com/media-manifest/streams",
    "96ti4sbdkN2m079Q5PcklQ==": "https://bloomberg.com/media-manifest/streams",
    "96ti4sbdkN2m079Q5PcklQ==": "https://bloomberg.com/media-manifest/streams",
    "96ti4sbdkN2m079Q5PcklQ==": "https://bloomberg.com/media-manifest/streams",
    "8tHO2L44rJvCEQDaBRI9Rg==": "https://bloomberg-bloomberg-3-br.samsung.wurl.com/manifest",
    "96ti4sbdkN2m079Q5PcklQ==": "https://bloomberg.com/media-manifest/streams",
    "96ti4sbdkN2m079Q5PcklQ==": "https://bloomberg.com/media-manifest/streams",
    "jPAGSQJDe0TVbQKCGJVJ1A==": "https://bc20d7c2a7b14dd0ae827a2e3eb99116.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Samsung-gb_Bloomberg",
    "+PU/tlOW37Gk/8HLXEccEg==": "https://reflect-batv.cablecast.tv/live-3/live",
    "jzmJFpKJ0M2J62TOnE7PJg==": "https://reflect-batv.cablecast.tv/live-5/live",
    "IC6rvnqWB43NmaKz9lfU+Q==": "https://1189614805.rsc.cdn77.org/hls",
    "pxJpYYySP7/G/tETWT/FpQ==": "https://rebroadcast.mytvtogo.net/mytvtogo/blugrassmusic",
    "hLp+ol4IrXnvP1oi8uDqFA==": "https://s3-us-west-2.amazonaws.com/bolton.castus-vod/live/ch2",
    "8QBwYnRtXDSaKGw0nuqXug==": "https://s3-us-west-2.amazonaws.com/bolton.castus-vod/live/ch3",
    "DUFN8Gb0qaRJif5X+8m/bg==": "https://s3-us-west-2.amazonaws.com/bolton.castus-vod/live/ch1",
    "dRL65RYjp9g69TQe9I2Mmw==": "https://bonappetit-samsung.amagi.tv",
    "P/2Ab+kRqGM6PDWQnOwgGA==": "http://104.238.221.63:9138/stream/live",
    "5b5rfY2xtEQpOE0CdiZAoA==": "http://194.163.179.246/slovenci/djeciji",
    "/NQe0THA4TygfWpuN4cf9A==": "https://5e6cea03e25b6.streamlock.net/live/BOUNCE.stream",
    "bRF9xKHzDBKBvo4zYUL6VQ==": "https://c217322ca48e4d1e98ab33fe41a5ed01.mediatailor.us-east-1.amazonaws.com/v1/master/04fd913bb278d8775298c26fdca9d9841f37601f/Samsung_BounceXL",
    "XTuJKT0Y/KTusyFajlufZQ==": "https://csm-e-boxplus.tls1.yospace.com/csm/extlive/boxplus01,boxhits-alldev.m3u8?yo.up=http://boxtv-origin-elb.cds1.yospace.com/uploads/boxhits",
    "LZRQwULYLWfSlm+Q5Lcz5Q==": "https://brat-rakuten.amagi.tv",
    "KY1VPNXPUwG8BUM/ZM+bpw==": "https://livestreamdirect-breezetv.mediaworks.nz",
    "HCd73/K6Me6lq1+iOdv3Yw==": "https://cdn3.wowza.com/5/cXdyRHF0Z3kxN0k2/brevardfl/G2111_002",
    "yS4Cnhru9ej2VbOhOJhrtg==": "https://api.visionip.tv/live/ASHTTP/visiontvuk-international-britishmuslimtv-hsslive-25f-16x9-MB",
    "nBvLg77RiV1Nz3DJK8FRAA==": "https://bspoketv.s.llnwi.net/streams/322",
    "I8A4z/H26U9yAON9zDATzw==": "https://edge-f.swagit.com/live/buenaparkca/smil:std-4x3-1-a",
    "9i9H50/kOYbNOIMw5svqXw==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c953819932c837b49397345",
    "k21ULYJTwnj/QAeejCKQTg==": "https://stitcheraws.unreel.me/wse-node01.powr.com/live/5bf220fad5eeee0f5a40941a",
    "8HZFYRtfDdsUF80aV/Dwig==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c95396f932c837b49397360",
    "uKyZu4D7FTYZd0xthN1ckg==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5e7559e8a46b495a2283c5e8",
    "afk3hHt5+FFBYxv/OaAzqA==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5bf225aed5eeee0f5a4094bd",
    "w04XwVnTkNBL8B/XdapipQ==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5bf22518d5eeee0f5a409486",
    "GzGSsEJy86DwPba9HkXdcQ==": "https://0813a4e76b5d404a97a4070b8e087bc4.mediatailor.us-east-1.amazonaws.com/v1/master/82ded7a88773aef3d6dd1fedce15ba2d57eb6bca/wse_powr_com_5f8609d9d6344257cbfb6ee4",
    "7fszQyjhWGFUzDIzWSMfYQ==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5bf22225d5eeee0f5a40941d",
    "VeeH4f4NAyNiTHoRxXZd9Q==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5e2624990145130f25474620",
    "AGvMfUQe0+GSWkzjSPaehw==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c953836932c837b49397355",
    "FUv2i3XlH4HrdjcZyeJQUQ==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5e2625030145130f25474622",
    "huh0XrL2E85YdH2JxzZ36Q==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5bf22526d5eeee0f5a4094b8",
    "r8MHKjUf8NZPI5/Yhq54jA==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c95385c932c837b49397356",
    "vJlH56TQC5CezGMuPCy70Q==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5bf22549d5eeee0f5a4094ba",
    "iYYilm95w2GvXASfBqHvAA==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5e2625700145130f25474624",
    "IVNwPhCHl6ENYJCenRdhEA==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5bf22681932c8304fc453418",
    "OcuUBeAdgo3IH67XiybPuQ==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5bf2256ed5eeee0f5a4094bb",
    "iWcK0vB/8kfTgEW1iL3pfQ==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c95387b932c837b49397357",
    "xo+N0z1E2vMPEakMFu0m6Q==": "https://stitcheraws.unreel.me/wse-node01.powr.com/live/5b284f40d5eeee07522b775e",
    "+JVP/rhkdh3OHopZNzlYdA==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c7dff0f932c8368bdbfd5fd",
    "LRYtChxsJ8ORoe3JnKWHmg==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c95388f932c837b4939735a",
    "g7WSbaWzhDiDCaZZbxi44g==": "https://b29da26d9a17436eafe339c08e488f33.mediatailor.us-east-1.amazonaws.com/v1/master/82ded7a88773aef3d6dd1fedce15ba2d57eb6bca/wse_powr_com_5f8609010d552957bf5aa546",
    "VeJoPMezeiMzpR0eRBArCA==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5e2625af5748670f12a3bee9",
    "aDh4xgVORPj7CfkmVyfFBg==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c9538a5932c837b4939735b",
    "SejECdoWSbYZszVG8Aq4kg==": "https://2459f78c2f5d42c996bb24407b76877a.mediatailor.us-east-1.amazonaws.com/v1/master/82ded7a88773aef3d6dd1fedce15ba2d57eb6bca/wse_powr_com_60f88620abf1e257404a9250",
    "QO2ubNOz/laaD7VOREiEgg==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5bf22491932c8304fc4533e4",
    "gpMeXMdThKI2kKNmhV8V2A==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5e2626030145130f25474626",
    "xMYicJmpM/ifExDokCrGGw==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c9538b9932c837b4939735c",
    "m0cKF74ktvjc+EFNlJ4lew==": "https://95771f8415a84e31bd152fe9c6c9905c.mediatailor.us-east-1.amazonaws.com/v1/master/82ded7a88773aef3d6dd1fedce15ba2d57eb6bca/wse_powr_com_5c953910932c837b4939735d",
    "jVcY22ph0AzNjHRLIynYvA==": "https://cdn3.wowza.com/5/djRwZmQvTEJidmZD/burbank/G0240_009",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "mm0EOzz+DM/ImhxGnYXEeg==": "http://butv10-livestream.bu.edu/live/WIFI-2096k-1080p",
    "rLU+8Y9DF3Ypkm9xF9rDBg==": "https://buzzr-samsungus.amagi.tv",
    "6b1Ivbql7vmPz6eHxL3FNQ==": "https://d1k6kax80wecy5.cloudfront.net/RLnAKY",
    "Qh4DFEsdhFVfEpJCIGtmIg==": "https://bk7l2w4nlx53-hls-live.5centscdn.com/AETV/514c04b31b5f01cf00dd4965e197fdda.sdp",
    "M/BzlGMfcJhIX/iDzrzT2Q==": "https://cdn3.wowza.com/5/UWpORHhLSEs5SkJs/calabasas/G0009_003",
    "24Qsv8WT1rVoMYGNf7PDjw==": "https://playout4multirtmp.tulix.tv/live7/Stream1",
    "ywVEQzN1dbNVT3WwWDUG1A==": "https://stream.ads.ottera.tv",
    "//yPwFtV/CEljHzHwVYVXg==": "http://cdn8.live247stream.com/canadaone/tv",
    "MIkp0FZgucHAc/YzEPHmTA==": "https://main.clickstreamcdn.com/agm/star-canada",
    "yS+M+vdfpvU5uobFrNFWsA==": "https://rtvelivestream.akamaized.net/segments/24h",
    "RuE3LVphrK6I/uQlKbF1Dg==": "http://digicom.hls.iptvdc.com/canalmotor",
    "7wPIefVwZFOdtEOTOGALjg==": "https://hls.savoir.media/live",
    "kjmmrM/9TUHu27JSrT19cg==": "https://reflect-stream6-capsmedia.cablecast.tv/live",
    "8O+YT7gywJFyRWmo/r85eQ==": "https://reflect-stream15-capsmedia.cablecast.tv/live",
    "BCAZfd/xzyOmtxOzoUHg8A==": "https://edge-f.swagit.com/live/carlsbadca/live-3-a-1",
    "lrkH9eL94m/weg/aO468Sg==": "http://198.16.106.62:8278/streams/d/Cn",
    "j+GKqqEnZ62MI5ZdfOFZEw==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023167/tooneast/slate",
    "Jt1LOnmjIpC0BFFHEt5pnw==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023180/toonwest/slate",
    "A5xxeogaoDhQvl3VhtLSMg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/599375885ceaac3cabccbed7",
    "U2hSylWXnVGumUg2s2CWYQ==": "https://vs-cmaf-pushb-uk.live.fastly.md.bbci.co.uk/x=3/i=urn:bbc:pips:service:cbbc_hd",
    "7XXokwC0LDUBE63n1SgZCw==": "https://1740288887.rsc.cdn77.org/1740288887",
    "W2/ELlrfDEBl/VBAhXtd+g==": "https://vs-cmaf-pushb-uk.live.fastly.md.bbci.co.uk/x=3/i=urn:bbc:pips:service:cbeebies_hd",
    "zFJM3oLFqG1WxbF6bG0Xgg==": "https://bcovlive-a.akamaihd.net/re8d9f611ee4a490a9bb59e52db91414d/us-east-1/734546207001",
    "9CG/m8/usGQo8rvYHVVRHw==": "https://livevideo01.wfmynews2.com/hls/live/2016285/newscasts",
    "tp3jf4qlLOSPJPPGJApL4A==": "https://livevideo01.krem.com/hls/live/2017156/newscasts",
    "5ZctMvzZDdzpIFmtupqlCw==": "https://content.uplynk.com",
    "Tv4TE/EmBLYRXMTqvEjXAA==": "https://livevideo01.wwltv.com/hls/live/2016516/newscasts",
    "AmkQLUSaYdjTBT26WrcGaA==": "https://livevideo01.5newsonline.com/hls/live/2011653/newscasts",
    "zfVKG6zOVGAhB2nCVSz99g==": "https://livevideo01.kens5.com/hls/live/2016281/newscasts",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "oG0Hdi72gVkH+AlHHiOnUA==": "https://svc-lvanvato-cxtv-whio.cmgvideo.com/whio/2596k",
    "BQQkzn/IHb8C9YPexcFfMA==": "https://livevideo01.cbs8.com/hls/live/2014967/newscasts",
    "kJ3w5y+zFX5BqWE+ffy+Ww==": "https://livevideo01.wusa9.com/hls/live/2015498/newscasts",
    "4fLDfsH1rsMKDYA5NXxf5g==": "https://livevideo01.10tv.com/hls/live/2013836/newscasts",
    "g7RlkEz/BH3BbgKG2wOEAw==": "https://livevideo01.wtsp.com/hls/live/2015503/newscasts",
    "Ee1/6zIIuaDU/uM/HJEjHg==": "https://livevideo01.khou.com/hls/live/2014966/newscasts",
    "fA9HCLunczpzOMYnhOR1bw==": "https://livevideo01.wtol.com/hls/live/2017153/newscasts",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "yLKgk5z+kqNjkE/hZBAKfg==": "https://livevideo01.13wmaz.com/hls/live/2017376/newscasts",
    "VDrrn043Xk9yu8E/h8soiQ==": "https://livevideo01.wltx.com/hls/live/2017152/newscasts",
    "4Gt86KDncYhJ+3A3kbjViQ==": "https://livevideo01.cbs19.tv/hls/live/2017377/newscasts",
    "xJ5+o4tYXY86l1bmNk6QDQ==": "https://16live00.akamaized.net/CBS_EAST",
    "pPvO3amNmjVXQ84LTiHhKw==": "http://trn03.tulix.tv/teleup-cbs-whp-new1",
    "TvxNNjEetLoCrD8b9iCG4w==": "https://trn10.tulix.tv/WGCL-CBS",
    "+MimBdQ2oZFzOQzyiWzGxQ==": "https://cbsn-us.cbsnstream.cbsnews.com/out/v1/55a8648e8f134e82a470f83d562deeca",
    "XkqEXGsJf74ugIkUfDmLYQ==": "https://cbsnews.akamaized.net/hls/live/2020607/cbsnlineup_8",
    "anB6z37Q67gGVtwQa4mXXA==": "https://voa-ingest.akamaized.net/hls/live/2033876/tvmc07",
    "dzcwUxThCD+u58zjn1QhVQ==": "https://cbsn-chi.cbsnstream.cbsnews.com/out/v1/b2fc0d5715d54908adf07f97d2616646",
    "snKO2Nt8sn/smi5gylmQ/g==": "https://cbsn-den.cbsnstream.cbsnews.com/out/v1/2e49baf2906244ecb01b07d9885fbe7a",
    "xuIDtwTQtFwV3t9I4ksPJQ==": "https://cbsn-dal.cbsnstream.cbsnews.com/out/v1/ffa98bbf7d2b4c038c229bd4d9122708",
    "RqiUoM+8OOTfMxe6sFDi3w==": "https://cbsn-la.cbsnstream.cbsnews.com/out/v1/57b6c4534a164accb6b1872b501e0028",
    "HXVgiul+KuwCM4ER+GZgaQ==": "https://cbsn-mia.cbsnstream.cbsnews.com/out/v1/ac174b7938264d24ae27e56f6584bca0",
    "VUWqNSdayWa4rEB9Ha0Odg==": "https://cbsn-pit.cbsnstream.cbsnews.com/out/v1/6966dabf8150405ab26f854e3cd6a2b8",
    "5XuX1euCjmQ17xcnp0Nq5Q==": "https://cbsnews.akamaized.net/hls/live/2020607/cbsnsac_2",
    "jtYmZve5CKibjkkI17xiIQ==": "https://5e6cea03e25b6.streamlock.net/live/WCTVDT.stream",
    "Y9YZHo2jIZZBFcLw3DkN+A==": "https://livevideo01.thv11.com/hls/live/2017154/newscasts",
    "hMgqA5VmQ+j1ICKSKCvadw==": "http://156.142.85.152/live/WIFI-2096k-1080p",
    "UJWtilKi6xcvemJnHJnJLQ==": "https://playout4multirtmp.tulix.tv/live8/Stream1",
    "Vyjb/0VzCStOijhPKo++vA==": "http://210.210.155.37/qwr9ew/s/s31",
    "UsaMzHLO+mbWKsG2lyHf+g==": "https://cdn3.wowza.com/5/UWpORHhLSEs5SkJs/cerritos/G0010_002",
    "0AY4L9ZjdB42J5+Ibgjq7g==": "https://uni8rtmp.tulix.tv/cfntv/cfntv",
    "F+fHn/uOA+1+V7yROZnYGQ==": "https://news.cgtn.com/resource/live/english",
    "zjWtAfoB/tX8OGLszq/Tbw==": "http://39.135.138.59:18890/PLTV/88888910/224/3221225645",
    "Td28cK5wYLRGx+ewAwrW8A==": "https://reflect-champaign.cablecast.tv/live-7/live",
    "lutIQ0EhFd6yGiT0sb3q4w==": "https://ddftztnzt6o79.cloudfront.net/hls/clr4ctv_okto",
    "ymzFifBM1EDzHusYhbfd7g==": "https://kalends.anl.bz/localchannels/channel7.stream",
    "by27OFGarRtcxFideNhsbA==": "https://d1k6kax80wecy5.cloudfront.net/WFqZJc",
    "8YFVwRRFVClpVd8EurDgew==": "http://dammikartmp.tulix.tv/slrc2/slrc2",
    "k5dYFE9uEjszg/OWtndkMQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/ChannelsTelevision",
    "N6mocVX4sY91UMZ0celkOw==": "http://content.uplynk.com/channel",
    "bB7f+Yv+Riji8AetBnIiUA==": "https://5e6cea03e25b6.streamlock.net/live/CHARGE.stream",
    "3EHW+hrQi41V0levJCzKvQ==": "https://cdn3.wowza.com/5/cHYzekYzM2kvTVFH/charlotte/G0055_002",
    "VVHa7Tt1JwZrNatuLEompQ==": "https://temp3.isilive.ca/live/CHCOTV/live",
    "XiFDLe6KJM5WX72RPL7ghA==": "https://cheddar-cheddar-3.roku.wurl.com/manifest",
    "K9pfINi2A4ompJEDMYImgA==": "https://rpn1.bozztv.com/36bay2/gusa-chefchampion",
    "Q6/QPrf1IDZbIwAU0hwqcA==": "https://rpn1.bozztv.com/36bay2/gusa-chefrock",
    "lD+pVp1gDRq+FZwGRF2DxA==": "http://c0.cdn.trinity-tv.net/stream",
    "tpSsUwSged+2x+hhvkWOwg==": "https://dai.google.com/linear/hls/event/2C5P0JGUSj65s8KpeyIDcQ",
    "8nu2nPJGIUmX59H0N2tuuA==": "https://edge-f.swagit.com/live/chinohillsca/smil:std-4x3-1-a",
    "Cz3qwtoXzgBKYivLxdp/gQ==": "http://a.jsrdn.com/broadcast/4df1bf71c1/+0000/high",
    "trbL0CmJRvkIRTZ2Kw08Uw==": "https://linear-11.frequency.stream/dist/plex/11/hls/master",
    "oBtt/prnXsFfodbDwGSfJQ==": "http://media3.smc-host.com:1935/cycnow.com/smil:cyc.smil",
    "/TBoAjRHWV+CYPz3Y+CBLQ==": "https://magselect-stirr.amagi.tv",
    "TfDVy1IZrc0M9cr91H7n0g==": "http://210.210.155.37/dr9445/h/h04",
    "bVLhyw7UZNxeXdSS3WLlUA==": "http://31.220.41.88:8081/live/us-cinemax.stream",
    "FF60O4NAVqNgy5t6XWRv8Q==": "https://gsn-cinevault-80s-1-us.vizio.wurl.tv",
    "y1p4uKX1nPcc5G9F59Ml3g==": "https://20995731713c495289784ab260b3c830.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Roku_CinevaultWesterns",
    "hAjDeW5PVmW34IAb4rhw1w==": "https://circle-roku.amagi.tv",
    "z5c/vJrqqFiNH4aVId+TXg==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/user/kenyacitizentv",
    "7rduEm7kwCRZuT6Z/tONQQ==": "https://cdn3.wowza.com/5/cHYzekYzM2kvTVFH/oakland/G0219_002",
    "i9BFUc0VOEMjuJ+qe86kpw==": "https://vblive-c.viebit.com/5f0d9ca5-4e85-4c01-a426-9ec8d44c2c9c",
    "0tCIlpuS8VzpkwrlVpCI2Q==": "https://cdn3.wowza.com/5/dk84U1p2UUdoMGxT/sandiego/G1826_005",
    "4Lw6lTo1sXuJXu4anOinaA==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c7e2531932c8368bdbfd87c",
    "cC7/hA10Zvi7PV1Qq/35OQ==": "https://d6s2o8so4wk28.cloudfront.net/v1/master/3722c60a815c199d9c0ef36c5b73da68a62b09d1/cc-2vzmnn0zl3exh-prod/amgclarity4k",
    "2MAOCOezFf6T/mzO1v1LUA==": "https://classicarts.akamaized.net/hls/live/1024257/CAS",
    "imoWygkUbLfhXPC3SBrgoA==": "https://rpn1.bozztv.com/36bay2/gusa-classiccinema",
    "xQDcjAXP4QAWgA03CKxKXQ==": "https://dai.google.com/linear/hls/event/wnQPvAN9QBODw9hP-H0rZA",
    "FG54yDs2q2q8joJ/i50BXQ==": "https://cloudflare.tv/hls",
    "T0PYrd0ZtLkDYJVbwZlHWQ==": "https://cmc-ono.amagi.tv",
    "EGsb12e39/EKO2Xs0iAQmg==": "https://d2ko4czujk9652.cloudfront.net/hls/clr4ctv_cnas",
    "Y2zgVK1sbpcAW3f9CwZ7gQ==": "https://d2e1asnsl7br7b.cloudfront.net/7782e205e72f43aeb4a48ec97f66ebbe",
    "2Afai2EF3JB7Hb2JEgkIlQ==": "https://16live00.akamaized.net/CNBC",
    "qpo0UA3tYn/U9BDgBmQiOg==": "https://5be2f59e715dd.streamlock.net/CNBC/smil:CNBCSandton.smil",
    "r8GxVE4eVOvfOD+WODaMnA==": "https://cnn-cnninternational-1-de.samsung.wurl.com/manifest",
    "HO6hlcStJzL5sKxI1/gUXg==": "https://streaming.cnnphilippines.com/live/myStream",
    "+7mPPP/joerZK5BVHLP62g==": "http://50.7.220.74:8278/momo1_twn",
    "AahMyrbdbhSL2cRMpd5Hkg==": "https://4ea7abcc97144832b81dc50c6e8d6330.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Roku_Cocoro",
    "vRmT31C12+k2aDnROOiB4w==": "https://watch.collierschools.com/EducationChannel/educhannel.stream",
    "uaIMsDSa57qzUUhWVxR+7A==": "https://reflect-collier-countyboc.cablecast.tv/live-4/live",
    "4xr/IEIta23/NJE1chOtcA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d4947590ba40f75dc29c26b",
    "/JoBXyM05QPymg29cbXnPw==": "https://uksono1-samsunguk.amagi.tv",
    "EVZhkn0EL/KdFSsQQfFBsA==": "https://cinedigm.vo.llnwd.net/conssui/amagi_hls_data_xumo-host-comedydynamics/CDN",
    "N6mocVX4sY91UMZ0celkOw==": "http://content.uplynk.com/channel",
    "plXgbizwoKwFT3IERBmtgA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxcomplex/CDN",
    "lqaF5YY56VP/4P4r3DgJ9Q==": "http://reflect-live-concord.cablecast.tv/live",
    "rmcpSRvRrb4ZjlGg13t/Zw==": "https://reflect-contra-costa.cablecast.tv/live-7/live/WIFI-696k-360p",
    "TiuVXsrY0SYyNRqrG223+w==": "https://contv-junction.cinedigm.com/ingest",
    "FsV5Qy+AH00knboNH0It+A==": "https://contvanime-littlstar.cinedigm.com/ingest",
    "skQD62gOCUrJX5wRVHfcZw==": "https://stream-us-east-1.getpublica.com",
    "s0HsqM9QH8KhNzqePEKkGg==": "https://cdn3.wowza.com/5/UWpORHhLSEs5SkJs/costamesa/G0075_002",
    "NKLv9DRAF2v6Exa7cvH/mw==": "https://cdn3.wowza.com/5/V2Y2VmhqMEFDTUkx/sdcounty/G0283_012",
    "sjyLANGjPsC2u4BMx9ebzQ==": "https://cdn-katz-networks-01.vos360.video/Content/HLS/Live/channel(courttv)",
    "eQG2fZA8ll9FB7XGDscdOg==": "https://5e6cea03e25b6.streamlock.net/live/QVC.stream",
    "xPIsaMRRBvjb4+EhWWwwDA==": "http://184.177.41.241/live-10/live",
    "TDPkd/zW0vIbJp2MTNtJbg==": "https://d7z3qjdsxbwoq.cloudfront.net/groupa/live/f9809cea-1e07-47cd-a94d-2ddd3e1351db/live.isml",
    "XTPkD9blgkUkfjvrVDPMTA==": "http://crackle-xumo.amagi.tv",
    "fTiW8NQmFV0yHzETqPRGbQ==": "https://live-hochanda.simplestreamcdn.com/hochanda",
    "EmP69uPB9lZNceQ1BNV4sA==": "https://reflect-creatv.cablecast.tv/live-19/live",
    "MjWttDB5IP07bCZscU6tZA==": "https://reflect-creatv.cablecast.tv/live-14/live",
    "s8zR19UKJCg5nK7U1QSapA==": "https://reflect-creatv.cablecast.tv/live-13/live",
    "k7htj0TVArOCn8qwsYEjbQ==": "https://reflect-creatv.cablecast.tv/live-16/live",
    "YSObZkHdpERV924o5W/Jng==": "https://aenetworks-crime360-1.samsung.wurl.com/manifest",
    "z8uKtbh6Rip56ud/ZSvYxw==": "https://crimetimebamca-roku.amagi.tv",
    "E8AQoxWn4wkIZMK/mOGuNg==": "https://cdnamd-hls-globecast.akamaized.net/live/ramdisk/cruise_tv/hls_video",
    "SS5KfkkeXAxx6FNEcSU8ww==": "https://tvsantacruz.secure.footprint.net/egress/bhandler/tvsantacruz/streamb",
    "DjimLP2O0Ctoqf9UQBU4Ug==": "http://media.smc-host.com:1935/csat.tv/smil:csat.smil",
    "0NEPbbK5va+nkrCl3vT/IA==": "http://trn03.tulix.tv/teleup-cspan",
    "Ve0aWRW4ZCjKmIOm5sLT0A==": "http://video.ct-n.com/live/ctnSupreme",
    "7Ds+uqevonqdAVrWHfaWnQ==": "http://video.ct-n.com/live/web2stream",
    "Utl1B9wDagDy67mV3QnD8w==": "http://video.ct-n.com/live/ctnstream",
    "nJWcOqOjlHcYVknLhkt7Gw==": "http://rtmp.ottdemo.rrsat.com/ctntv/ctntvmulti.smil",
    "6vb3z/2kGCY5t7TpbwN40g==": "https://ctntv.getstreamhosting.com:1936/Lifestyle/Lifestyle",
    "iXbinDAjzcFIIhTzfJKLEQ==": "https://pe-fa-lp02a.9c9media.com/live/News1Digi/p/hls/00000201/38ef78f479b07aa0/index/0c6a10a2/live/stream/h264/v1/3500000",
    "JFMs4y3NdtRptVyVrQ/1xA==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/channel/UCj3dt20MAZcvDN8GKeT2FBg",
    "WzFI42uQptopcyv62mum1A==": "https://trn10.tulix.tv/WUPA-CW",
    "DheExXNMC9I7kbNo3QWPXQ==": "https://cwseedlive.cwtv.com/ingest",
    "PXgEf+EYIpo4Ifb1ArE12g==": "https://edge-f.swagit.com/live/cypressca/smil:std-16x9-1-b",
    "kwETLEUlRZQiBShqgdNTyg==": "http://sc.id-tv.kz",
    "rfIglGHDW/0pY+UKydiVSg==": "http://dai.google.com/linear/hls/event/oIKcyC8QThaW4F2KeB-Tdw",
    "7kaY+MtUqaqH7YC/Dkqf2A==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5d40855b3fb0855028c99b6f/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720/10&deviceVersion=unknown&embedPartner=samsung-tvplus&profileFloor=&profileLimit=&samsung_app_domain=https://play.google.com/store/apps",
    "8j6dMXYrhL26n2H5/QKg2A==": "https://3abn-live.akamaized.net/hls/live/2010545/D2D",
    "YzgyAfw6kKVo6h5Abv6uQg==": "https://distroscale-public.s3-us-west-2.amazonaws.com/strm/channels/darkmatter",
    "IxD5S6F/YLc/UtwWbh61GQ==": "https://cdnuk001.broadcastcdn.net/KUK-DAVEJAVU",
    "Ti26BkkArueidB+Putra9A==": "https://hls-live-media.cdn01.net/dvr",
    "OHdl0zf6hbHQO41s0AJRzg==": "https://video.oct.dc.gov/out/u",
    "OHdl0zf6hbHQO41s0AJRzg==": "https://video.oct.dc.gov/out/u",
    "OHdl0zf6hbHQO41s0AJRzg==": "https://video.oct.dc.gov/out/u",
    "77KFJBSbK1zXhb1z5Mwq4g==": "https://dhx-degrassi-1-us.samsung.wurl.tv",
    "K5k7lxuVDMSH3fQanomSQg==": "http://dhx-degrassi-2-ca.samsung.wurl.tv",
    "+PMJxOGCVMBEa8Gfs5dD9A==": "https://d25ykpi2vxhoyc.cloudfront.net/delmar-cdn/dmtv",
    "SYCbXaju2rT/gk+LkbKthg==": "https://demandafrica-klowdtv.amagi.tv",
    "64guXhXe7c1g4R++EM9tbw==": "https://demandafrica-samsungmexico.amagi.tv",
    "Hs33t/eJ0eTNt3log5uBlQ==": "https://cdn3.wowza.com/5/bGZUOHp2TnhudnM2/denver/G0080_002",
    "pDODyRVOyhJsdqAZnyOClg==": "https://dai.google.com/linear/hls/event/-NacIpMDTZ2y1bhkJN96Vg",
    "OHdl0zf6hbHQO41s0AJRzg==": "https://video.oct.dc.gov/out/u",
    "BKuesNvfo2Arq28d73642g==": "https://divineplayout-us2.tulix.tv/live/Stream1",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "W2/kAzw19oiv7eiYv/NyjA==": "https://dltv-live-edge.catcdn.cloud",
    "r2l41z0fxxEIJyRrKQHhzw==": "https://docurama-plex-ingest.cinedigm.com",
    "q+HWgMrguHkPQkdEr9En+g==": "https://cinedigm.vo.llnwd.net/conssui/amagi_hls_data_xumo1234A-dovenow/CDN",
    "a/eqCvdqVOdO+SHGHJo3RQ==": "https://dover-de.secure.footprint.net/egress/bhandler/doverde/streama",
    "BIDr/kVTcG+g67ULtH2AaQ==": "https://wescottcc.piksel.tech/Manifest",
    "Ry8ZZQrFKQclZ3zqHiAE5A==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f24662bebe0f0000767de32/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720/10&deviceVersion=unknown&embedPartner=samsung-tvplus&profileFloor=&profileLimit=&samsung_app_domain=https://play.google.com/store/apps",
    "eFySNJ6R9l749WB2aLtpYA==": "https://a.jsrdn.com/broadcast/e29bdbbbf3/+0000",
    "fiWcDaNJjJeCo2PfjraiGQ==": "http://dminnvll.cdn.mangomolo.com/dubaione/smil:dubaione.stream.smil",
    "76DsAU+orHBuR1WdfCY32w==": "https://dmithrvll.cdn.mangomolo.com/dubairacing/smil:dubairacing.smil",
    "yTp28k4L9VrTkpmUSyvBPg==": "https://mmm-ducktv-2-it.samsung.wurl.com/manifest",
    "V4s9/IJFjcaagu7kSQsgSw==": "https://dai.google.com/linear/hls/event/xuMJ1vhQQDGjEWlxK9Qh4w",
    "tDI9I0q+qSG76T3WhQSkrw==": "https://dust.sinclair.wurl.com/manifest",
    "NXkklf+lcnNEVjXKGMiltg==": "https://dwamdstream102.akamaized.net/hls/live/2015525/dwstream102",
    "nNyxq7WEeylKViNSyFhl8g==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/DZRHNewsTelevision",
    "oF0r8QZVV9ZfiHgPxvL31A==": "https://ov.ottera.tv/live",
    "JlXVjLGjuyXYBR9guinuDQ==": "http://ebsonair.ebs.co.kr/plus3familypc/familypc1m",
    "mAoEdxCDh9uyAVqj65S9BA==": "https://euc-live.fl.freecaster.net/live/eucom",
    "gH8g0hu61E2WHLYDNReEfw==": "http://ebsonair.ebs.co.kr/plus2familypc/familypc1m",
    "mAoEdxCDh9uyAVqj65S9BA==": "https://euc-live.fl.freecaster.net/live/eucom",
    "zwIwggOQDw/bz5tHlof+rQ==": "https://edgesport-samsunguk.amagi.tv",
    "/hx8UTHBYL5AqJOGagD4Yw==": "https://eu.streamjo.com/eetlive",
    "th6R7ZOSuDYb1iYkXoKHAw==": "http://172.96.160.37:9138/stream/live",
    "e4YkBqLkQHgXV8fVjzwyqw==": "https://cdn3.wowza.com/5/cHYzekYzM2kvTVFH/elsegundo/G0014_002",
    "Ft2g2qbrmZFkwGBqMHVJtw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-electricnow/CDN",
    "QSRBPk6KbDpgdqinXE8Ssw==": "https://ap02.iqplay.tv:8082/iqb8002/3m9n",
    "EDFaUAVEWSwbSoqHvum2Hg==": "https://a.jsrdn.com/broadcast/7582ed85f7/+0000",
    "A4Lwnb77Lres4t/h/GnuZw==": "https://cpcdn.azureedge.net/ESCAMBIACOFLLIVE1/ESCAMBIACOFLLIVE1",
    "TwZSVE7NOOnVNAML6Lbjpg==": "https://dai.google.com/linear/hls/event/xrVrJYTmTfitfXBQfeZByQ",
    "XpfDCw6H7Oi3N9R0sb4ZUg==": "https://pubads.g.doubleclick.net/ssai/event/pJrzNyDoT_K_GwYQsijTsQ",
    "xX49HFaEXcVbKfl4KK8uVw==": "https://livecdn.live247stream.com/eternallife/tv",
    "ij+9tvQmGYawIkjzBbc1tQ==": "https://a.jsrdn.com/broadcast/7b1451fa52/+0000",
    "r2PISiySQ9jh+sf8rdPYYA==": "https://cdn3.wowza.com/1/QmVNUVhTNTZSS3Uz/YWQ0aHpi/hls/live",
    "Y5+GAvvKXb/qL7zqQYZrow==": "https://cdn3.wowza.com/1/YW5wSWZiRGd2eFlU/bGV0aVBq/hls/live",
    "l5aUlm1WHCBLU8SfcWk7IQ==": "https://cdn3.wowza.com/1/SmVrQmZCUXZhVDgz/b3J3MFJv/hls/live",
    "GJo2mJs03dfC1tResnbujQ==": "https://cdn3.wowza.com/1/T2NXeHF6UGlGbHY3/WFluRldQ/hls/live",
    "nZXNaJ9aPZK3P0rkgXu50Q==": "http://livestreamcdn.net:1935/ExtremaTV/ExtremaTV",
    "sU5wrzVdmepSv8O0rRgaFg==": "https://streams.helnix.com/autoHLS/900735315c2bc38b",
    "nipnAXRbGOmJ6IZekjwhUA==": "https://streams.helnix.com/autoHLS/02d8dab006ef9ffd",
    "YUVOGH+Rt5hxm+v2kp/YHA==": "https://reflect-fairfield-ca.cablecast.tv/live-8/live",
    "FPa3rSkpTPLVa+SmPbGxWw==": "https://biblescreen.faithlifecdn.com/biblescreen/faithlifetv",
    "4ACLazi3ek6dS9oagHNMpw==": "https://biblescreen.faithlifecdn.com/biblescreen/bibleScreen",
    "JEyvwNxk2lfdzSSK+IU8cQ==": "https://vse2-na-us-ne24.secdn.net/logos-channel/live/christmas",
    "HY2PM7HRqKiBYbHeW4EPUw==": "https://fashiontv-fashiontv-1-eu.rakuten.wurl.tv",
    "Y1EO8/P+ZPlgI1rT57cXKQ==": "https://fash2043.cloudycdn.services/slive/ftv_ftv_gmt_-5_qko_43090_default_1225_hls.smil",
    "cf/pYoBRaBpPE5AEEHmpmQ==": "https://fash1043.cloudycdn.services/slive/ftv_pg13_adaptive.smil",
    "zpwRpAxmpOHeVjLnO1nSyQ==": "http://fash1043.cloudycdn.services/slive/ftv_pg16_adaptive.smil",
    "xxNmsMvjvolvhO2lV7/h8A==": "https://fash2043.cloudycdn.services/slive/ftv_ftv_asia_ada_xiv_42149_default_137_hls.smil",
    "9o1ywHaXdku0iW+N0vUT7w==": "https://fash1043.cloudycdn.services/slive/ftv_ftv_pg13_zw9_27065_ftv_pg13_sam_197_hls.smil",
    "OiNNqeiF8jS0AHsA53hFUg==": "https://fash2043.cloudycdn.services/slive/ftv_ftv_4k_hevc_73d_42080_default_466_hls.smil",
    "LhLJw4JFFXqjrOvV4s8S7g==": "http://lb.streaming.sk/fashiontv/stream",
    "ma+7af+BrM5RO2yv0l8vPQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/channel/UCT3Dk_ZPcoR7CeHM_Wwb3QA",
    "DfbZE/fDLffi268A/rNjmA==": "https://reflect-fcpublicmedia.cablecast.tv/live-3/live",
    "qfg6d3UjwpWOfzG3+oByuw==": "http://n1.klowdtv.net/live3/fido_720p",
    "KhkAL+ncCY+dMxMwypjFsA==": "https://d12a2vxqkkh1bo.cloudfront.net/hls",
    "AYu4coeA/9fTxTrmrTc7Ag==": "https://shls-fight-sports-ak.akamaized.net/out/v1/ee7e6475b12e484bbfa5c31461ad4306",
    "ag3YuTRoIGwtWCbReNI6NQ==": "https://a.jsrdn.com/broadcast/47cff5378f/+0000",
    "yvY8iari4E3Pmn8xllINJA==": "https://api.new.livestream.com/accounts/19514369/events/6947821",
    "4EHB4fThL/XzgXCAcq8r2Q==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxfilmhub/CDN",
    "4xHUFTo4h4oOVR4UxXtzVQ==": "https://dai.google.com/linear/hls/event/hW5jMh7dTRK1UXW5fTH07A",
    "oV6UohtP3oRjwzHeeYvYBA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxfilmrisefamily/CDN",
    "uzAABS3ynRPmxH8leNfy7A==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxunsolvedmysteries/CDN",
    "oQHHqQlsCRJeB9Bv61I4pg==": "https://spi-filmstream-1-eu.rakuten.wurl.tv",
    "1qHHewA61bkgslFkQtFB9A==": "https://a.jsrdn.com/broadcast/aee08372e5/+0000",
    "YEbkkyZLH5dc45ZdkA6d/w==": "https://uni01rtmp.tulix.tv/firstlight/firstlight.smil",
    "B9/NUPLp3hslp4xNsUR8bw==": "https://a.jsrdn.com/broadcast/8b43a16c1e/+0000",
    "HyA21dKSRbT2Bl63svQGKQ==": "https://cdn-cf.fite.tv/linear/fite247",
    "blEEteQNIn+nzgqUc+p5kg==": "https://edge-f.swagit.com/live/flagstaffaz/live-1-a",
    "9aKR7QihtaSvFuqXMrKS2Q==": "http://584b0aa350b92.streamlock.net:1935/folk-tv/myStream.sdp",
    "EyIVpdM9P0VsNSZgYy7vNg==": "https://cdnapi.kaltura.com/p/2158211/sp/327418300/playManifest/entryId/1_24gfa7qq/protocol/https/format/applehttp",
    "i/01fMTPTNCJVH0/z69fww==": "https://reflect-watchkfon-fontana.cablecast.tv/live-3/live",
    "wrIfWbjYM8kKWSCTsY5wSw==": "https://cinedigm.vo.llnwd.net/conssui/amagi_hls_data_xumo1212A-redboxfood52A/CDN",
    "8P8OqLLX3Fn9KcRYpMiYaQ==": "https://edge-f.swagit.com/live/fortpiercefl/live-1-a",
    "s4ykjgtpCKc/CMU+SdUOEw==": "https://cdn3.wowza.com/5/cHYzekYzM2kvTVFH/fountainvalley/G0806_001",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "Rq6dZsqV1ZbM6l12xVbq8g==": "https://livevideo01.myfoxzone.com/hls/live/2017381/newscasts",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "CRF9vlF2h7i+XIySeA84iQ==": "https://livevideo01.fox43.com/hls/live/2011656/newscasts",
    "OzLZ8q3x6eEk28K49gUpIA==": "https://livevideo01.rocketcitynow.com/hls/live/2011659/newscasts",
    "aM1IH269jo0BTc/V1ZM2nw==": "https://livevideo01.fox61.com/hls/live/2011658/newscasts",
    "qDp1D5IG5kOjYnERpQdwnA==": "http://trn03.tulix.tv/teleup-fox-wpmt-new1",
    "LvWumAPEMh7/QOqNRmXPQQ==": "http://199.66.95.242/1/1172",
    "6322FGdqkAj2KRTytnXYAw==": "http://live.streams.ovh:1935/foxtv/foxtv",
    "HtKB9WCCyrgm2YnGdAgNqQ==": "http://trn03.tulix.tv/AsEAeOtIxz",
    "DuUlXJjTDovyP6samwyBzA==": "https://fox-foxnewsnow-samsungus.amagi.tv",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "4Fu8SpchQsJKYsBdY+a9PQ==": "http://fox-foxsoul-roku.amagi.tv",
    "iyMLsR//xLwJo9+bb1kpzg==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-foxweather-xumo/CDN",
    "TgYgSYtFJc5JxTv8U9C42g==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/FRANCE24English",
    "Z+dOpxlDWhIVs85GAV/3ow==": "https://edge.fstv-live-linear-channel.top.comcast.net/Content/HLS_HLSv3/Live/channel(b168a609-19c1-2203-ae1d-6b9726f05e67)",
    "sZQoQcp8f8ifoIY8d9SXlw==": "https://d3cq7cdp2cfi92.cloudfront.net/v1/master/3722c60a815c199d9c0ef36c5b73da68a62b09d1/cc-2ff27mp9b8422-prod/hls-harvester2-1293-prod/us-east-1/cc-2ff27mp9b8422",
    "TUeMefx7v0caR2ziuNVDwA==": "https://reflect-vod-cmac.cablecast.tv/live-11/live",
    "NsIVyZmSzVvCfWM1Uyv5xQ==": "https://reflect-vod-cmac.cablecast.tv/live-12/live",
    "JqqJYiisdS7ta5mOlZaO6A==": "https://reflect-vod-cmac.cablecast.tv/live-13/live",
    "8IaomF8pcipznxNyj9P3Ww==": "https://eleven-rebroadcast-samsung.roku.wurl.com/manifest",
    "BtgtLumuQHeIyG2eQ+Jiyw==": "https://elevensports-uk.samsung.wurl.com/manifest",
    "fsBVVOyoVwyZJrtknTAliw==": "http://fueltv-fueltv-14-nl.samsung.wurl.com/manifest",
    "vaBdOBX46zx2HMwoGwxDtQ==": "http://104.143.4.5:2080",
    "rJnCSfC1kpmtsuG6Hujjzw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxfunnyordie/CDN",
    "ot1SztySDsF+Q70Ixje7rA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxfuse/CDN",
    "gcj0BFvlohYFixvSMyu7JQ==": "https://unidfp-nlds159.global.ssl.fastly.net/nlds/univisionnow/galavision_east/as/live",
    "0f1eXkY0suH5LZPmFu2+NA==": "https://unidfp-nlds159.global.ssl.fastly.net/nlds/univisionnow/galavision_west/as/live",
    "i+GYYetZ8MsxYsRRKUOE6g==": "https://5d846bfda90fc.streamlock.net:1935/live/galaxytv",
    "PPn5Zi4hMF++IB0intpAlg==": "https://stream.swagit.com/live-edge/galvestontx/smil:hd-16x9-1-b",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "io6l/eTyCTSVnqRapmMYHw==": "http://n1.klowdtv.net/live2/gsn_720p",
    "hl9D23X71gvPuKZ1wIJnJg==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/GBNewsOnline",
    "ywqOz9NPXzXdBCBSraNMXw==": "https://edge1.lifestreamcdn.com/live/geb",
    "AplVS7TYhtMZhiXVXzEPoA==": "https://amg01460-gemshoppingnetw-gem-ono-x662c.amagi.tv",
    "rel3dOCRqvY/C6AAAGqfhg==": "http://57d6b85685bb8.streamlock.net:1935/abrgemporiaukgfx/livestream_360p",
    "LCjoAD+3tpinSyJCbPSjFA==": "https://d3jxchypmk8fja.cloudfront.net/v1/master/9d062541f2ff39b5c0f48b743c6411d25f62fc25/GFNTV-Plex",
    "GAmLJCE5YcYsIrjqQM1msA==": "https://cmap.secure.footprint.net/egress/bhandler/cmap/streamb",
    "RVZ62hXhmgT+pWjFFR5i0Q==": "https://cmap.secure.footprint.net/egress/bhandler/cmap/streamc",
    "npCzT5V7ihAGvQxafChIBQ==": "https://cmap.secure.footprint.net/egress/bhandler/cmap/streamd",
    "B6mSbM6Z1Ar7PTVZovdm5Q==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxglamour/CDN",
    "s51ye7n3f231RHRjvWLOXQ==": "https://2-fss-1.streamhoster.com/pl_122/200562-1176456-1",
    "JYmjHnYGhcc8QqrlSU43mg==": "https://stream.swagit.com/live-edge/glendaleaz/smil:std-4x3-1-a",
    "oJhqRklXBM0KFDAi09RZTw==": "https://reflect-gtv6-glendale.cablecast.tv/live-2/live",
    "KAJ8ve0oL27QXFkN8RwQyQ==": "https://dai.google.com/linear/hls/event/ChWV1GupQOWE92uG4DvbkQ",
    "e/tKpRYonOhp5K3mLhqgng==": "http://liveen24-manminglobal3.ktcdn.co.kr/liveen24/gcnus_1300k.stream",
    "FWgmGuP70Mr5G1ZkrdLrNg==": "https://vcngfcssai.teleosmedia.com/linear/globalfashionchannel/globalfashionchannel",
    "GQcQwJwDTemcpUXh/yzbfw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxglorykickboxing/CDN",
    "8TtHdPE0GntO2ssGAwPF+w==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxgotraveler/CDN",
    "OyTfuXGVdvBOxx5J3b54BQ==": "https://reflect-golden-co.cablecast.tv/live-3/live",
    "P/2Ab+kRqGM6PDWQnOwgGA==": "http://104.238.221.63:9138/stream/live",
    "OYcxFYrHLOw4lWo/DhOhqw==": "http://1-fss29-s0.streamhoster.com/lv_goodlife45f1/broadcast1",
    "EL53DwWmxSfszNe91BMCAQ==": "https://cdn3.wowza.com/5/Wi9jakJPdFhPREFj/live/myStream",
    "jiC4hCulfA1X7iFRTsTNXw==": "https://bstna.tulix.tv/live/bs_2m",
    "0cD2E4RPeOBTna4gac10Gw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxgq/CDN",
    "wcwO+ajit8+ZKl6kIfnvRQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxgravitas/CDN",
    "7GzQdwtFFqb+/4aHvsZ/iw==": "https://greenbeltacctv.secure.footprint.net/egress/bhandler/greenbelt/streama",
    "uCoFlKTvYCn09WBhOIV70A==": "https://lin12.isilive.ca/live/greensboro/GTN",
    "vRkA+Cu6PoVfVJvqbv0jUw==": "https://d37j5jg7ob6kji.cloudfront.net",
    "dPR8FjtsnCBaGSSmoec3Aw==": "https://gstv-gsshop.gsshop.com/gsshop_hd/gsshop_hd.stream",
    "ocpeBgn6cRcD5THRR9+Ltw==": "https://443-1.autopo.st/100/weblive/bcgurduwarabrookside",
    "g+mvg9F0vrIaUGX2aaT10g==": "https://d3cajslujfq92p.cloudfront.net",
    "aD1DBWr5XFrY+FndGIJUAw==": "https://reflect-greenwood.cablecast.tv/live-3/live",
    "z2MCiInzv97BIKJ6gtZtfQ==": "https://reflect-hktv.cablecast.tv/live-3/live",
    "7ZvAGjHzrzTkZWQFodlM8Q==": "https://happykids-roku.amagi.tv",
    "YIPCHd5csrGDyQViTxSUXQ==": "https://happykidsjunior-vizio.amagi.tv",
    "bBvhdXqKE5wMPQsgXp9+TQ==": "https://d3uyzhwvmemdyf.cloudfront.net/v1/master/9d062541f2ff39b5c0f48b743c6411d25f62fc25/HardKnocks-PLEX",
    "9jQpqrjkm6KezyMhKivroA==": "https://hdtv.prod2.ioio.tv/broker/play",
    "9jQpqrjkm6KezyMhKivroA==": "https://hdtv.prod2.ioio.tv/broker/play",
    "9jQpqrjkm6KezyMhKivroA==": "https://hdtv.prod2.ioio.tv/broker/play",
    "VSWVlJQHuKNTW0hFYnBk4A==": "https://haunttv-roku.amagi.tv",
    "IS7VGFSi1jqv7R3K0jZSvw==": "http://50.7.220.74:8278/hbohd_twn",
    "xWCZKWMBxf7MA10Ud6xIew==": "https://d76toswjmqqzm.cloudfront.net",
    "BPgxiA6+9dHr4M7BG0/D9w==": "https://5e6cea03e25b6.streamlock.net/live/HI.stream",
    "J/sSyzL6F3r5PIV+5IP5Zg==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5c7e2503932c8368bdbfd875",
    "4Fd5mMBP7611jrswgur8wQ==": "https://cdn3.wowza.com/5/M0lyamVmM2JWcjhQ/hillsboroughcounty/G2155_002",
    "tQH5ovDWXe1m1cLxVHz1mg==": "https://vod.tv7.fi/tv7-se/smil:tv7-se.smil",
    "yl4RNVCS/BsocRMY6O3xgA==": "https://bk7l2w4nlx53-hls-live.5centscdn.com/HISTORY/961ac1c875f5884f31bdd177365ef1e3.sdp",
    "xwlh/Tl3jz+50WIlhcHHLQ==": "http://210.210.155.37/dr9445/h/h37",
    "Qx/0DdBZyDjJtMmAhLRZhA==": "https://tve-live-lln.warnermediacdn.com/hls/live/586496/cnngo/hln",
    "tR8xBktnCjFTG4l0SORXLQ==": "https://hncfree-vizio.amagi.tv",
    "qsGwWpwFcGEXLJEldTWHNw==": "https://bozztv.com/hwotta/playlist",
    "A4D2mYHIi+W8i4yXQCuZ9g==": "https://a.jsrdn.com/broadcast/d5b48/+0000",
    "7LQqh1aTAwYcJLKgql/PiA==": "http://media1.adventist.no:1935/live/hope1",
    "NiKSsfDOG9zL0jzduZ/Nqw==": "https://olympusamagi.pc.cdn.bitgravity.com/Horrify-roku",
    "mcS3pMJAQ0A40iNi1QOrzw==": "https://hnc-free-viewlift.amagi.tv",
    "MtXD4/cTpOJe/rDFlkZyFA==": "https://hncfree-samsungau.amagi.tv",
    "KNLh9/jw2EAhfEE4VdE26A==": "https://hncfree-samsung-uk.amagi.tv",
    "GitFx8IrZ/W8vqRmn9du6A==": "https://uplynkcontent.sinclairstoryline.com/channel",
    "VedYks11m4K0LFSpYt+dhw==": "https://hartford-ct.secure.footprint.net/egress/bhandler/hartfordct/streamc",
    "AOwI4qmmXq6FmTWZO/QJpQ==": "https://hartford-ct.secure.footprint.net/egress/bhandler/hartfordct/streamb",
    "NWjqjyYfVOJOTnGNDHI/mQ==": "https://hartford-ct.secure.footprint.net/egress/bhandler/hartfordct/streama",
    "JHrcjtIdXKFFOuvN18/TKw==": "https://hsn.samsung.wurl.com/manifest",
    "7/W0sz9zqkXjkBXD+otC/A==": "https://stream.swagit.com/live-edge/houstontx/smil:hd-16x9-2-a",
    "2M0OaZ9F6qB8sr072DKPrw==": "https://stream.swagit.com/live-edge/houstontx/smil:hd-16x9-2-b",
    "XDCl82AG58dGaXaYFqlcTg==": "https://damkf751d85s1.cloudfront.net/v1/master/9d062541f2ff39b5c0f48b743c6411d25f62fc25/HumorMill-DistroTV",
    "tcJK4Dar3ucYaShbcMHu+g==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxhungry/CDN",
    "YeTpN7GJEdkq02ELwDmzfQ==": "https://1111296894.rsc.cdn77.org/LS-ATL-56868-1",
    "bz35Ge9V/JE93epz1ozYWQ==": "https://cdn3.wowza.com/5/M0lyamVmM2JWcjhQ/huntingtonbeach/G0088_005",
    "+iMd0AEbB8IHV1SmiWUMhA==": "http://138.68.138.119:8080/low/5a8993709ea19",
    "68LJdgHfx/a0gdbj7yAACg==": "https://amdici.akamaized.net/hls/live/873426/ICI-Live-Stream",
    "PPX5/n82IQ2Zwq/GjTvH7g==": "https://60ba7ef02e687.streamlock.net/ICNET2/ngrp:icnet_all",
    "AkymhvZq+0SBSwUzVyYFLQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/IdealworldTvShopping",
    "hm/DT1+f0fnTkuz8DX9wBA==": "http://a.jsrdn.com/broadcast/529a360c04/+0000/high",
    "5A+bFa53XUqzgtIyvLp3ng==": "https://bcovlive-a.akamaihd.net/070ffdaa203f439cacbf0d45a1ddb356/us-east-1/6240731308001",
    "Wu1CipjlUAcS19nnZc1LIw==": "https://live1.presstv.ir/live",
    "jxzbrAckWOnD3d5ph0/5DA==": "https://ft-ifood-roku.amagi.tv",
    "PQYRZtHz7lbfbeKmkSfnWQ==": "https://ign-plex.amagi.tv/hls/amagi_hls_data_ignAAAAAA-ign-plexA/CDN",
    "ycnAJ4NgMhkNRX/ZZAcWJw==": "https://uni10rtmp.tulix.tv/iipctv/iipctv.smil",
    "fWTtIBrQKgPrV5lrc1lI8g==": "https://d2p372oxiwmcn1.cloudfront.net/hls",
    "rFTZjQjDnn/+GBRVq5xoAA==": "https://indtv.secure.footprint.net/egress/bhandler/indtv/streama",
    "HSqLz5tG/1cadOqqBKHVjA==": "https://indiatodaylive.akamaized.net/hls/live/2014320/indiatoday/indiatodaylive",
    "Zxbo+DwVQ+iatAaYyI0I+A==": "http://wpc.9ec1.edgecastcdn.net/249EC1/infowarshd-edgecast",
    "J7bV1npzLD1bSt3edUEPig==": "https://insighttv-vizio.amagi.tv",
    "IoDzUjsxnO23sYQfYGwKUA==": "https://59d39900ebfb8.streamlock.net/8478/8478",
    "vOQVMZSpNrWoB8huKITJYQ==": "https://introuble-samsung.amagi.tv",
    "GmJCZAFV7/98jef6WRd9+A==": "https://inwild-samsung-uk.amagi.tv",
    "aXKcZMzW7Wvm6XtcNYPKmw==": "https://inwonder-eng-rakuten.amagi.tv",
    "QuCfs/uoizDVfSN3iHdEFw==": "https://jmc-live.ercdn.net/iqraaeurope",
    "DEv4tb8m4lH4Q3YC2fmi6A==": "http://51.210.199.53/hls",
    "sP38db4wEqOIdnt1CdBv0Q==": "https://cdn3.wowza.com/5/WDIrTW5sM1JEY1NN/irvine/G0016_010",
    "6YtzRYY/IjctSte06YT3pQ==": "https://live.islamchannel.tv/islamtv_english",
    "jmJgEkzCs9IamqvLafw3vw==": "https://a.jsrdn.com/broadcast/41e3e6703e/+0000",
    "gyVso0m9iGLWcqqZHVpgAQ==": "https://isntv.mmdlive.lldns.net/isntv/f79b65204e7141c6a5cc74e63cf0dae5",
    "emrUCE4vAgOTJ5kaqvD+ug==": "http://31.220.41.88:8081/live/itv2.stream",
    "GN4etIKH9G88cixOgxN6Rw==": "http://31.220.41.88:8081/live/itv3.stream",
    "RcrNv2vVgvCCu8ectZpP1A==": "http://31.220.41.88:8081/live/itv4.stream",
    "90NpItLfsX/CScdHP1BG7w==": "http://31.220.41.88:8081/live/itv1.stream",
    "6Yk/pSDab6YtFbOhoAWIbA==": "https://b1english.beritasatumedia.com/Beritasatu",
    "jRcUKzB4pYgvV0cXjrt0Uw==": "https://vse2-sa-all4.secdn.net/tvstartup11-channel/live/mp4:jotvedge",
    "YOR4lOkFsM3Gm3RxfOGkQQ==": "http://uni8rtmp.tulix.tv:1935/shalomtv-pc/smil:shalomtv.smil",
    "OD/DVY9aCldU4jpx+9B5pw==": "https://lo2-1.gemporia.com/abrjewellerymaker/smil:livestream.smil",
    "RdnshuBan8O3XNxe9Q/xGA==": "https://cdn3.wowza.com/1/eUdsNEcyMmRvckor/K3pydHZw/hls/live",
    "9TutY3Jlff7hxFV2a2JCwA==": "https://cdn.igocast.com/channel12_hls",
    "6E5pGRHaGla7uc2qvalzjg==": "https://cdn3.wowza.com/1/R3ZYNjNvdGVoaDFZ/Q3pENnlF/hls/live",
    "j4kSzrBwORLbSmoyrNIIYQ==": "https://jlt2104.cdn.nextologies.com/ebaed9568f2b8e61/ffaaf4b7e1d0e7a8/ea5f88d4e7c252b2/056b5eafae61b1e6",
    "mNh1GkSfSC8USfZMZHw6mw==": "https://johnnycarson-redbox.amagi.tv/hls/amagi_hls_data_redboxAAA-johnnycarson-redbox/CDN",
    "yI4iLZnr7U40FX99kvSsyw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxjourny/CDN",
    "dtnE821N74vY9cAa+23csg==": "https://cb5273f195a147f2bcf23544e4495f66.mediatailor.us-east-1.amazonaws.com/v1/master/82ded7a88773aef3d6dd1fedce15ba2d57eb6bca/wse_powr_com_5eb1e7261474f9020c06f9ec",
    "jeRsTYpOqQdHmYz2uQlsNw==": "https://juicex.nz/hls",
    "hhvsGeXSjKzEQMgS9JASFQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-viziojustforlaughsgags/CDN",
    "T0mR9Ndkt1K+qKMKl/43qg==": "https://streamone.simpaisa.com:8443/pitvlive1/k21.smil",
    "RfEzV/OIR00fKrupsSre5w==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxkabillion/CDN",
    "dPjVKFrG6lkYKz5wtuuLJA==": "https://cdn3.wowza.com/5/dk84U1p2UUdoMGxT/albanyca/G0327_002",
    "z0UMSWocSbM5NMbYz0eAHw==": "https://10380e91fda5e303.mediapackage.us-west-2.amazonaws.com/out/v1/e8a622ce6ed34d07b468dd6ea2f94ee8",
    "DWHqJM/q1uWipx2gEYRKTQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://dai.ly",
    "4JwfIO/bt819IUJvdLKs5A==": "https://simultv.s.llnwi.net/n4s4/KartoonCircus",
    "Cpzv9GGCDnjuOPZAPbQIzw==": "https://s3-us-west-2.amazonaws.com/beverly-hills-high-school.castus-vod/live/ch1",
    "RWMfQzhxxO6Qt6nvvhATfA==": "https://live-k2302-kbp.1plus1.video/sport/smil:sport.smil",
    "q9vReG6RrAXh+jvTsCwD+A==": "https://cdn3.wowza.com/5/R09KQXpaMWlrRjly/brightonco/G0883_001",
    "YrSv+ysQOsC/B1e6Rl9T2g==": "https://kbsworld-ott.akamaized.net/hls/live/2002341/kbsworld",
    "q4zdeXVjNkzrSv73hNXJbA==": "http://66.242.170.53/hls/live/temp",
    "Ns/AP7S7pYbO1slLu459Gw==": "http://197.243.19.131:1935/kc2/kc2",
    "cgOSBiuWScUfwX6IHPUD2g==": "https://reflect-kcat-live.cablecast.tv/live-2/live",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "Tl4mMDAZ3h1wIFqUyHtg7Q==": "https://cdn3.wowza.com/5/dk84U1p2UUdoMGxT/kern/G0169_003",
    "H0+u7jk71xeGPkWTvqhx1A==": "https://csm-e-boxplus.tls1.yospace.com/csm/extlive/boxplus01,kerrang-alldev.m3u8?yo.up=http://boxtv-origin-elb.cds1.yospace.com/uploads/kerrang",
    "R2Z7YmHV/tbzj/4oym7sZQ==": "https://content.uplynk.com/channel/ext/96195dc445894d079a91958abba8d3af",
    "gYy3unECKLGqghpbE/4JOw==": "https://content.uplynk.com/channel/ext/4413701bf5a1488db55b767f8ae9d4fa",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "hyvM5/ZHmaZcnIfA7ytVDQ==": "https://usgeowall.sinclairstoryline.com/channel",
    "skQD62gOCUrJX5wRVHfcZw==": "https://stream-us-east-1.getpublica.com",
    "s4UJSmSc3H894eMF9X2XXA==": "https://csm-e-boxplus.tls1.yospace.com/csm/extlive/boxplus01,kiss-alldev.m3u8?spotxc1=195996&spotxc2=190878&yo.up=https://boxtv.secure.footprint.net/kiss",
    "FiUv2RC7KO37uwXvP0qx9g==": "https://fuel-streaming-prod01.fuelmedia.io/v1/sem",
    "t/4yW9eyJrbvXbtS9uWrcg==": "https://dk7psf0dh3v1r.cloudfront.net/KMTV",
    "5ASnm/GeGxsaF8doRXlnBg==": "http://knstream1.azureedge.net/knlive",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "MjJkDd9/GnNl9TC4H4X0sA==": "http://w10.streamgb.com:1935/kool/kool",
    "gcTtudu3mZerkkvNIDBU6g==": "http://209.182.219.50:1935/roku/roku",
    "G+IdCvysKMnP3Na1nLd1Cg==": "https://ptvlive.kordia.net.nz/out/v1/3fc2254c865a457c8d7fbbce227a2aae",
    "K1nJVaucDob2aUeVXRVC1Q==": "https://uni01rtmp.tulix.tv/kqsltv/kqsltv",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "K41zdbZpn4LZ/JbWnsKJIw==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/user/standardgroupkenya",
    "rskfsa50ylxadm1zYDjhvw==": "https://cdn3.wowza.com/5/ODB6NmF5K3l4T1h5/persis/2147483647_360tv_247",
    "enBKqQPI6ILD3n/LismEYw==": "https://content.uplynk.com/channel/ext/1efe3bfc4d1e4b5db5e5085a535b510b",
    "As5NlId45/ay+XlKziYigg==": "https://2-fss-2.streamhoster.com/pl_138/amlst:201950-1309230",
    "dNR0oKi8fP8O04cdusbgyA==": "https://a.jsrdn.com/broadcast/9c897f1973/+0000",
    "lr6+8FQ7rb4suuy7qydr/A==": "https://reflect-losangeles.cablecast.tv/live-3/live",
    "Kl67lVAvVakojzwcR14Tcg==": "http://185.105.4.193:1935/ltv/myStream",
    "GC0ICBHGSmXsqnaBYk1rcA==": "https://vcdn.dunyanews.tv/lahorelive/_definst_/ngrp:lnews_1_all",
    "1srSG/PHdzd53LocMPO9xg==": "https://live8fd.lakewood.org/live-2/live",
    "5GkQf4q+zK8AI+i2cNiLPQ==": "https://s3-us-west-2.amazonaws.com/lakewood.castus-vod/live/ch1",
    "hSzp1XxarRiuGRLxKO8SzA==": "https://live.latinosnc.tv:1443/MRR/live",
    "DrjaIG5VAl8JHmRAOLJhRw==": "http://lawandcrime.samsung.wurl.com/manifest",
    "15HSsI98gLB7PxySvs0/cQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1234A-lawcrime/CDN",
    "PeXsLJ5/1AeknrsdFUF42A==": "http://67.53.122.248/live-4/live",
    "ycFOUupBLaAfhrRCtLJyGQ==": "https://1840769862.rsc.cdn77.org/FTF",
    "kFn5vV7I+VowKXUjYym/xQ==": "https://reflect-lakefront-leesburgflorida.cablecast.tv/live-5/live",
    "qHZjYgDZuDu9mSb3/aDgdg==": "https://legochannel-roku.amagi.tv",
    "pf5G8f3DQ6ZAwaVQN+/7yg==": "http://edu.leominster.tv/Edu/smil:Edu.smil",
    "ILDK83roSkitBR8fPwx88Q==": "http://gov.leominster.tv/Gov/smil:Gov.smil",
    "xNJPEeJBmNFVxXeDdb/cIA==": "http://gov.leominster.tv/Pub/smil:Pub.smil",
    "xZs9CXHJ5Z3WI2hiF1yrWQ==": "https://cdn3.wowza.com/5/cHYzekYzM2kvTVFH/lakehavasucity/G0643_003",
    "V4iQS4Z0j4Vz7KMSZlUp1A==": "https://2-fss-2.streamhoster.com/pl_138/200226-1359204-1",
    "DZkPznwJl1YGS0BOAxeOmg==": "https://2-fss-1.streamhoster.com/pl_122/200226-1427780-1",
    "JfQxDG0WAbutR6IM5VxkUg==": "https://uni5rtmp.tulix.tv/lifevision/lifevision.stream",
    "FKDWKfy5N9QlNZQBx7+r9w==": "https://brightstar-hisword.secure.footprint.net/egress/bhandler/brightstar/brightstarHisLight",
    "dST4ArpxwI33gjMKvnkZuw==": "https://brightstar-hisword.secure.footprint.net/egress/bhandler/brightstar/brightstarHisWord",
    "X7GKP2hCruKFeAdffFbt8w==": "https://ch8.littletongov.org/live-2/live",
    "GV27Sg73Ji0lOF0WKunEiQ==": "https://dai.google.com/linear/hls/event/xC8SDBfbTKCTCa20kFJQXQ",
    "jUQci8r45CQ14lNT3fsDPQ==": "https://cdn-unified-hls.streamspot.com/ingest1/0b5c0f18e9",
    "TqxoIUQ0gIZTc5vSFLAniw==": "http://5tv.lincoln.ne.gov/live/WIFI-2096k-1080p",
    "gIeLjtDy5tM+l/U4DGWFFQ==": "http://80tv.lincoln.ne.gov/live/WIFI-2096k-1080p",
    "/C2UdnxgsCSruPDMVH6E0g==": "http://10tv.lincoln.ne.gov/live/WIFI-2096k-1080p",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "1+TlRjN19Lyjz5S0GvYXcA==": "https://5aafcc5de91f1.streamlock.net/logoschannel.com/logoseng",
    "YQfplLQiLcqoWqXUz+HO3A==": "https://lompoccmttv.secure.footprint.net/egress/bhandler/lompoccmttv/streama",
    "OcsK2j6JEid15sc9tfo/Ag==": "https://lompoccmttv.secure.footprint.net/egress/bhandler/lompoccmttv/streamb",
    "sOjjPy10OYGjOMQxs+N6tQ==": "https://lompoccmttv.secure.footprint.net/egress/bhandler/lompoccmttv/streamc",
    "CYl3aXVCPaOwk1lpoBAupQ==": "https://lonestar-rakuten.amagi.tv",
    "YEAs4t+AunqNEKthzk79LQ==": "https://reflect-padnet-live.cablecast.tv/live",
    "TRPZ0W7QXVt4LdCeRvegTA==": "https://cdn3.wowza.com/5/WDIrTW5sM1JEY1NN/longbeach/G0020_001",
    "KEC08l8p88w4wJq91sbAjg==": "https://ch8reflector.longmontpublicmedia.org/hls",
    "Dgycz9ugWMd88aaA6Z4Mjw==": "https://ch8reflector.longmontpublicmedia.org/hls/14",
    "g+MQS7ImFYZt7/qZbDbw5w==": "https://ch8reflector.longmontpublicmedia.org/hls/16",
    "r3EGtN/qLluE58W9SjCY6w==": "https://55e014b3437040d08777729c863a2097.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Roku_Loop80s-1",
    "7orBISit0IpFkeOh91gEUA==": "https://a500d902bdf94ea69ad343720add6036.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/80s_party_littlstar",
    "Wq6fpLryfn2eq2iI6arqDQ==": "https://7626362bfa104137aded60d8d7e72ff5.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/90s_kids_littlstar",
    "Krry4q/FMETcHb5jbwPJGQ==": "https://884a4c762d524aad88d463477402fb7d.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/beast_mode_littlstar",
    "8Fzrs2ZaAiBEy5rE8On0Kg==": "https://3bbe22c035b4409d80f997adc8ad33ee.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/bedroom_beats_littlstar",
    "JZAs90dChK6c5JoLvkJh+g==": "https://0bdf3efc906045538c63468aa2f86a96.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/electro_anthems_littlstar",
    "1NXMj2qYJbibQ31bBgKjDQ==": "https://957d71ce01dc447384d3978d3cdc55d9.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/that_70s_channel_littlstar",
    "F5yAmOx5vf1Y4DtrKqaZHA==": "https://ea86081fb9454be9b3b50037f9117024.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/like_yesterday_littlstar",
    "ktP3CC3Gy6z8bQHwe/GOmg==": "https://e4d2547e0c8c492a883054acd48276be.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/hip_hop_bangers_littlstar",
    "Z07Qq6cxMY4r2K6Uq4jZgw==": "https://2e9a0ef101a14c2ebe97c713bc5340be.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/hottest_of_the_hot_v2_littlstar",
    "jPB0K3wL1hr3Pb/5kaOfSg==": "https://c3b9df023def467086d10677827171f8.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/latin_x_pop_littlstar",
    "/3LFM8+kRtEN/NBon4a2uw==": "https://1d79349342334eb0bdeddd168b5c6e1a.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/party_littlstar",
    "Svcieyu5Gsb3PzsZNQdZ0w==": "https://0cf4f660964046daa9e0b7b6467a4e84.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/hot_rnb_littlstar",
    "8Tn6VL7d/PJYAcZVt8MvQw==": "https://2807722353b745629456a555257b16bc.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/neural_focused_littlstar",
    "xNgcz1hJl8I8rSFuOv+/qQ==": "https://2fb88e730c2647d69629c6f90b0b98b9.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/texas_sized_hits_littlstar",
    "ZUm0rtR774WBOQ5Pa5Fvtg==": "https://480e67fe68b64c35ae48b77192cb1fdf.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/friday_feels_littlstar",
    "3tpBa33auPPacwIMP2dd/A==": "https://dccd6216f2c9471399015e69d64818cd.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/thats_hot_littlstar",
    "gw7vI/lNeW8M+j55Yum6Cg==": "https://3d26c463850c48c788975a9aad86c508.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/trending_littlstar",
    "QLqMKH40/T8fMahxvxS6gA==": "https://8c455e94c5ff44d0ada529dffef58ae5.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/unwind_littlstar",
    "cimVVjO2W55hhJUQtOyyRA==": "https://90a0d12cbaff4b959ea24bb8a3560adf.mediatailor.us-west-2.amazonaws.com/v1/master/6b8beeb9ed833d048c8c8155a25a28fe617c5474/yacht_rock_littlstar",
    "36vBA4rWunSbtEKDJWq2sA==": "https://reflect-channel36-la.cablecast.tv/live-3/live",
    "yBWH0t8uxZ/PiVp5J1NnMw==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/channel/UCro5PeODE-MCnNzuWyxRJ6A",
    "XzOeZY+8BInaQxg8Kmyudg==": "http://d2dw21aq0j0l5c.cloudfront.net",
    "j2kuFV5TvopRqEFmvlLumA==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5d51ddf0369acdb278dfb05e/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720/10&deviceVersion=unknown&embedPartner=samsung-tvplus&profileFloor=&profileLimit=&samsung_app_domain=https://play.google.com/store/apps",
    "PDMIQebnf5Gfxsy4qS33iw==": "https://d18dyiwu97wm6q.cloudfront.net/v1/master/3722c60a815c199d9c0ef36c5b73da68a62b09d1/LoveNature4K2-prod",
    "DIvpDAjRxChCE7rM4Qtw6w==": "http://bamus-eng-roku.amagi.tv",
    "e/UO1iLiwh8YdYVd+kQIQg==": "https://kalends.anl.bz/localchannels/lovetel.stream",
    "99hfnJnBZQxjGwQM+O8ldw==": "https://reflect-cityofloveland-co.cablecast.tv/live-3/live",
    "Dx3spINfC7nzAAFfjybFfw==": "https://cdn.lwuk.live/live/smil:lwukweb.smil",
    "kczOM3Iyz9tCPkkzzJs4og==": "https://cdn3.wowza.com/5/RGtVZkFxL3FOQkxX/lwut/ngrp:lwu.rtmp_all",
    "txjNxBVgzL7SJOtQdjkJ3A==": "http://51.210.199.33/hls",
    "JpsQmnt+2tEgTC62mB0QxA==": "https://rpn1.bozztv.com/36bay2/gusa-mwg",
    "MPr2eg3tjufuAaYx3CUT9w==": "https://madnitv.vdn.dstreamone.net/madnitvenglish/madnienglishabr",
    "jH7N+Hqliq4H9bl0a81eOg==": "https://dai.google.com/linear/hls/event/5xreV3X4T9WxeIbrwOmdMA",
    "eOKjlK7LPEdRqmSq1n4SyQ==": "https://reflect-mcsb-vod.cablecast.tv/live-16/live",
    "YW4JQqthJPVMEfEFh2Xq+A==": "https://dacastmmd.mmdlive.lldns.net/dacastmmd/8e6d110b223b4aca9dd6f7c368baec07",
    "lhhrctEud6i8GU+rYksBNw==": "https://dacastmmd.mmdlive.lldns.net/dacastmmd/ddf2a073e3da4acb9feb34bef6d58672",
    "pHLsfaehK13tyYlvAD/CDw==": "https://ampmedia.secure.footprint.net/egress/bhandler/ampmedia/streamd",
    "h2N6/8ge7hesOUwC81hDDw==": "https://stmv.panel.grupolimalive.com/marvision/marvision",
    "wiVlK1xqYvAISZFMVRXNeQ==": "https://cdn3.wowza.com/5/UWpORHhLSEs5SkJs/martin/G0074_002",
    "HkL2ThcZHGLK/7u7VDfwJg==": "https://feed.play.mv/live/10005200/niZoVrR2vD",
    "r/vCDG9Tk+GdPgEGkaD4sQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redbox-maverickmovies/CDN",
    "2of2ap0iRiD2e+gyxXCP/g==": "https://mavtv-mavtvglobal-1-eu.rakuten.wurl.tv",
    "8wcTjxG10udFnVb+kZY66g==": "https://shls-mbc4-prod-dub.shahid.net/out/v1/c08681f81775496ab4afa2bac7ae7638",
    "Tn9CkNACk4fUk9c28H4bCA==": "http://41.216.229.205:8080/live/livestream",
    "AoZvfWHTM1Pvj82p9WxNIQ==": "https://shls-mbcaction-prod-dub.shahid.net/out/v1/68dd761538e5460096c42422199d050b",
    "Ddkx4L1A7ajoDyQTN+IHfA==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.twitch.tv",
    "WTzzvK5766AvF1Uplt9GYw==": "https://d18fcxaqfnwjhj.cloudfront.net/CDN_Ingest/MCN6_MAIN.smil",
    "v2EYhTXF1TXjRk0SEOv1fw==": "https://d18fcxaqfnwjhj.cloudfront.net/CDN_Ingest/MCN6_COMEDY.smil",
    "CWqv29pM9cgu8s8D4FcJ2w==": "https://d18fcxaqfnwjhj.cloudfront.net/CDN_Ingest/MCN6_MUSIC.smil",
    "JWhPSs9BjPsVTkVP2y2/tQ==": "https://livestream.lamusica.com/megatvP320/ngrp:megatvP320_all",
    "gCN39teU5xfzvGkNVWRj6w==": "https://streamone.simpaisa.com:8443/pitvlive1/mehran.smil",
    "tQJfQELk/gFOh3aIAllNVQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/user/CountyofSacramento1",
    "bzsrwSdkR98QrcbZZgaM8A==": "https://mercedcouedu.secure.footprint.net/egress/bhandler/mercedcouedu/streamc",
    "DFCcKM+CrPnPzOHrxd082Q==": "https://5e6cea03e25b6.streamlock.net/live/WCTVDT2.stream",
    "FmsRj1dCUv1mNK+B3NvkKQ==": "https://16live00.akamaized.net/ME_TV_EAST",
    "lD+pVp1gDRq+FZwGRF2DxA==": "http://c0.cdn.trinity-tv.net/stream",
    "YWv2//S/gfZO+ifSSxbBJA==": "https://369f2966f62841f4affe37d0b330a13c.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Plex_MidnightPulp/playlist.m3u8?ads.app_bundle=&ads.app_store_url=&ads.consent=0&ads.gdpr=0&ads.plex_id=5ef4e1b40d9ad000423c4427&ads.plex_token=z1MCPUpbxYcHru-5hdyq&ads.psid=&ads.targetopt=1&ads.ua=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/84.0.4147.89+Safari/537.36+OPR",
    "Oh18GzGSUbxNsQgySHRfXw==": "https://5c2974786200d.streamlock.net/live-chan30/ngrp:ch30_all",
    "NqvEIXDi3eEfy+3qMtiYzQ==": "https://5c2974786200d.streamlock.net/live-chan75/ngrp:ch75_all",
    "R5wZBX/c658zmrnVPvovmA==": "https://5c2974786200d.streamlock.net/live-chan26/ngrp:ch26_all",
    "ZBV5v0iklo873JgCxOw8fw==": "https://5c2974786200d.streamlock.net/live-chan29/ngrp:ch29_all",
    "vmQrhbrosM6t/I8VTVwtlg==": "https://5c2974786200d.streamlock.net/live-chan28/ngrp:ch28_all",
    "mX9dB0vmXBE0YtGSakMKjQ==": "https://603591da64140.streamlock.net/live/mp4:MCTVtest_aac",
    "KisyghiCrGMPt+CCrs1uWA==": "https://cdn.appv.jagobd.com:444/c3VydmVyX8RpbEU9Mi8xNy8yMDE0GIDU6RgzQ6NTAgdEoaeFzbF92YWxIZTO0U0ezN1IzMyfvcGVMZEJCTEFWeVN3PTOmdFsaWRtaW51aiPhnPTI/mnews24.stream",
    "695o3uzuWxRWzbkk2u6pdA==": "https://cdn.appv.jagobd.com:444/c3VydmVyX8RpbEU9Mi8xNy8yMDE0GIDU6RgzQ6NTAgdEoaeFzbF92YWxIZTO0U0ezN1IzMyfvcGVMZEJCTEFWeVN3PTOmdFsaWRtaW51aiPhnPTI/millenniumtv-odr-up2.stream",
    "jAOony0Z7HNbnF06dWfMlg==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5812b821249444e05d09cc4c/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720",
    "T5B2PkMy4opOKNr78uO/8w==": "https://pubads.g.doubleclick.net/ssai/event/DXkHhH2QSnma-HnE3QJqlA",
    "JesbFWqc2BAFqs02O55fng==": "https://5afd52b55ff79.streamlock.net/MISTV/myStream",
    "MBtjA5lQQqB8PNs4dnDBbA==": "https://6096a9cf11ae5.streamlock.net:1943/live/missiontv",
    "ljZsCyWXu6c7wJyf4yHDzQ==": "http://a.jsrdn.com/broadcast/80f6ba72c8/+0000/high",
    "JvidO6+g58vcG5W+anJT8Q==": "https://live.mnb.mn/live/mnb_world.stream",
    "gRrVlDHgVavZlDyQGOYMIA==": "https://dai.google.com/linear/hls/event/LGDVXxxyT8SxrL4-ZodxKw",
    "wG8LVHRW4pUeZ9qcD0hw+w==": "https://5b200f5268ceb.streamlock.net/MCPSS/MCPSS247.smil",
    "Fv0ueQiW800OfPh+J8K+ew==": "https://a.jsrdn.com/broadcast/0c9a09c94c/+0000/low",
    "G9NM1AyMhzdpaw10goobsw==": "https://castus-vod-dev.s3.amazonaws.com/vod_clients/monroe/live/ch1",
    "B6RdpoE4FJVH45aNpO3pWw==": "https://ampmedia.secure.footprint.net/egress/bhandler/ampmedia/streamc",
    "cddyFxq3p5307U0DUd8keg==": "https://moonbug-rokuus.amagi.tv",
    "cp6dRPgG7qAt8haHUkSDHQ==": "https://cdn3.wowza.com/5/cXdyRHF0Z3kxN0k2/moorpark/G0086_003",
    "M/wRQZCc5X+BpaZwdzcIJQ==": "https://agp-nimble.streamguys1.com/MBCh20/MBCh20",
    "QPymE5oySPwlyJmeEWB2uw==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/60817e1aa6997500072d0d6d",
    "KzF2/ytwzD8yE6s+/SQAkw==": "https://a.jsrdn.com/broadcast/e9b4093a41/+0000",
    "2WpFDEFLFNNPluIyyYMXWg==": "https://moviesphere-samsung-samsungus.amagi.tv",
    "jdOEsmZ3oeQJ4jlaA9S92g==": "https://mst3k-redbox.amagi.tv/hls/amagi_hls_data_redboxAAA-mst3k/CDN",
    "KZqGsPyIOgE0OHb0cmsq/A==": "https://chlivemta1.akamaized.net/hls/live/2008145/mta1",
    "pnNKIKt0+cfP0rpjSzwHxQ==": "https://chlivemta1.akamaized.net/hls/live/2008145/mta2",
    "KYsCx9suVJ++v66BoitLpA==": "https://chlivemta.akamaized.net/hls/live/2010555/mtaafrica1",
    "Eyh/coIEyRzSCA86QfR0FA==": "https://chlivemta.akamaized.net/hls/live/2010555/mtaafrica2",
    "9pyWi9C2Q43q+ruoyT1O6A==": "https://livemtaasia.akamaized.net/hls/live/2039224/mta6asia",
    "moENkz+3RCT++Roy+pE06A==": "https://livemtaasia.akamaized.net/hls/live/2039224/mtaasia2",
    "XsXzweZAD6WELgcty6G6xw==": "https://chlivemta.akamaized.net/hls/live/2016718/mta8",
    "p5MbFPiXkrMiTG/8BpDpOw==": "http://144.217.70.181:9587/hin2/MTVINDIA",
    "9wzgSTOSMRnWskG31HvOtA==": "http://190.2.155.162:8080/mtvhit",
    "mbk7WQUewxVW16/jPT/GjQ==": "http://cdn.us195.jpnettv.live:1935/jptv/mtv",
    "WbLx6sVDAu199f2t4MA69g==": "https://cdn-ue1-prod.tsv2.amagi.tv/linear/amg01492-secomsasmediart-museumtv-en-plex",
    "FhFVQ1ptbapP+3adZl+Uog==": "http://210.210.155.37/uq2663/h/h18",
    "AQ/zQxBqcCeN3u2ze2jRhw==": "http://210.210.155.37/uq2663/h/h194",
    "BzmC+Uybcqw7HATVWjnJCw==": "https://ad-playlistserver.aws.syncbak.com/playlist/13613390",
    "Z9zs86TMebyRe/Zs4VUN0Q==": "https://5a13fe32ef748.streamlock.net/mmplay/mitv",
    "JY4OIPgqNL5nw6sGYUWzIg==": "https://cdn3.wowza.com/5/RXJNMFI3VlVkOEFP/encinitas/G0322_002",
    "u2kjm1hPYHQ4EJ/ZTmf3Nw==": "http://trn03.tulix.tv/e5CGxWp8iU",
    "1t+rGYfu54R+5SNQjcUKKw==": "https://mst3k-vizio.amagi.tv",
    "CD7qLA9Tga1mFKL2nTPIPw==": "https://mytimeuk-rakuten-samsung.amagi.tv",
    "vW73DHG3kfwiGYFrcjHZxA==": "http://65.36.6.216:1935/live/kcwx.smil",
    "ZR9Jmo2xZG+HOloQ9YEI3Q==": "https://cdn-ue1-prod.tsv2.amagi.tv/linear/amg01255-secomcofites-my-myzen-en-plex",
    "3knL5clTVidljJ3m88wuhA==": "http://stream.pivotalelements.com/nactv",
    "rH6ShIvTRANIymWzGCSVHQ==": "https://cdn3.wowza.com/5/WDIrTW5sM1JEY1NN/napatv/G0360_003",
    "JxXFrFVZ1z2HspYkMqtSmQ==": "https://cdn3.wowza.com/5/WDIrTW5sM1JEY1NN/napatv/G0360_004",
    "GitFx8IrZ/W8vqRmn9du6A==": "https://uplynkcontent.sinclairstoryline.com/channel",
    "7tZCcmpTU4q0ZwFQ0KS1KA==": "http://iphone-streaming.ustream.tv/uhls/9408562/streams/live/iphone",
    "IPNt1cHP63Y3s7dk4HhBMw==": "https://ntv2.akamaized.net/hls/live/2013923/NASA-NTV2-HLS",
    "ZNZa+JhmeSdpOHWk9yhKHg==": "https://ntv1.akamaized.net/hls/live/2014075/NASA-NTV1-HLS",
    "UFYIGoWcE6C/XPEF71d++w==": "https://endpnt.com/hls/nasa4k60",
    "X8HNf+N43rr2HvFg96qm/A==": "http://stream.ec.nau.edu/live/amlst:channelfour",
    "FbI9+8BUOkyoX6GVgiDwaA==": "https://livevideo01.wgrz.com/hls/live/2016286/newscasts",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "r6Rc1nFyvF4DhwHGJ6Ialw==": "https://livevideo01.king5.com/hls/live/2006665/live",
    "1KMfquwHmFc7o/cLZIPHvQ==": "https://livevideo01.ksdk.com/hls/live/2014965/newscasts",
    "Tf1N+M10Fd3Gv1PHvbl7PQ==": "https://livevideo01.kagstv.com/hls/live/2016283/newscasts",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "mzJm63i0yUgzViau2cGNwg==": "https://livevideo01.kcentv.com/hls/live/2017155/newscasts",
    "+FiTVZ68mvIqy2cNEYEMIA==": "https://livevideo01.ktvb.com/hls/live/2014542/newscasts",
    "/R8z0enVUgeWQczqD0gyXw==": "https://livevideo01.kgw.com/hls/live/2015506/newscasts",
    "o1uJF5CF6O2tI2/8GfShxQ==": "https://livevideo01.9news.com/hls/live/2014548/newscasts",
    "g9ATWluJTj7SHBeQd4AvUQ==": "https://livevideo01.wbir.com/hls/live/2016515/newscasts",
    "vPpDxiqMuVj28KWJ+E/M4g==": "https://livevideo01.kare11.com/hls/live/2014544/newscasts",
    "Kv8vc+lIB+5bycfN9cXElQ==": "https://livevideo01.12news.com/hls/live/2015501/newscasts",
    "mQJ3SfTZDNNAxinVkdJJxw==": "https://ad-playlistserver.aws.syncbak.com/playlist/899088",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "7s9Bd4bbdeItLvlW/GC1lg==": "https://livevideo01.wcnc.com/hls/live/2015505/newscasts",
    "MWHdJw6zzejB+nZJyiYgyQ==": "https://livevideo01.newscentermaine.com/hls/live/2014540/newscasts/live",
    "fv1QZpT8KVWRHxlXs7m17g==": "https://livevideo01.firstcoastnews.com/hls/live/2014550/newscasts",
    "mwXOxRgFfI8Ryr8hyvyLjA==": "http://trn03.tulix.tv/teleup-nbc-wgal-new1",
    "goyxR457OiTKpa2upkfWaw==": "http://51.161.118.146:8080/ISG03_NBC_BALTIMORE_MD_WBAL",
    "12MZcLZfZvvshC0RG5dAng==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-xumo-nbcnewsnow/CDN",
    "EaQqrwdWNXft8359GtBpEg==": "https://livevideo01.newswest9.com/hls/live/2017380/newscasts",
    "KaegJEBG37NPw1Tz0jQHBg==": "https://thainews.prd.go.th/lv/live/ch1_L_L.sdp",
    "qYJpoIvVPD7VkcE6rEiUEQ==": "https://newcastlecoutv.secure.footprint.net/egress/bhandler/newcastlecou/streama",
    "T+XIWNM3l1m0UqO4c8sE1Q==": "https://cdn3.wowza.com/5/cHYzekYzM2kvTVFH/nevco/G0644_005",
    "ENw86A8tmZ3RW6L7cIELIQ==": "https://cdn3.wowza.com/5/cHYzekYzM2kvTVFH/nevco/G0644_002",
    "9omOi0lX+PO5EGakyxZAdw==": "https://cdn3.wowza.com/5/cHYzekYzM2kvTVFH/nevco/G0644_001",
    "p1lJjdopp2Ks3FbrPC2u4g==": "https://ndtvprofitelemarchana.akamaized.net/hls/live/2003680-b/ndtvprofit",
    "dyGdajCU9vljgpNwxGY06g==": "https://bcovlive-a.akamaihd.net/bea11a7dfef34b08be06aaca4a72bcdf/us-east-1/6141518204001",
    "4bM7tc2vY5IBs5pQ4dhZKw==": "https://nctv79.secure.footprint.net/egress/bhandler/nctv79/streama",
    "l4NU3RioFpYjFPA4gWs9Iw==": "https://aka-amd-njpwworld-hls-enlive.akamaized.net/hls/video/njpw_en/njpw_en_channel01_3",
    "bjXMzhEvd/GNUenEzVWfWw==": "https://b9860b21629b415987978bdbbfbc3095.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Roku_NewKID",
    "aGBKNO9t5dzw9ATsI3pjew==": "http://media4.tripsmarter.com:1935/LiveTV/NOTVHD",
    "miX7zxMHkhJfBrvUNQAuUA==": "https://2-fss-1.streamhoster.com/pl_122/201748-1431018-1",
    "BAsLJxGul3a4/ZSQjZwNBg==": "https://s3-us-west-2.amazonaws.com/newington.castus-vod/live/ch1",
    "KNCvH2oSUSHJbfMjd3pjaw==": "https://s3-us-west-2.amazonaws.com/newington.castus-vod/live/ch2",
    "aLhIze9i8ZKwT2AfpULLcg==": "https://cdn3.wowza.com/5/RXJNMFI3VlVkOEFP/newportbeach/G0064_003",
    "xHCgCbi9F3xLNicRfeSBCw==": "https://lnc-news12.tubi.video",
    "8EbXoQ3bACZ6aut1nAXwhA==": "https://newsmax-plex.amagi.tv/hls/amagi_hls_data_plexAAAAA-newsmax-plex/CDN",
    "SXstKeg5E/scVfuIf6/7Aw==": "https://2-fss-2.streamhoster.com/pl_138/amlst:201950-1311088",
    "NX44M+fSgcVnQIQvm84T3g==": "https://547f72e6652371c3.mediapackage.us-east-1.amazonaws.com/out/v1/e3e6e29095844c4ba7d887f01e44a5ef",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "9fNx/SrXXNmVGaG6anbASA==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/channel/UCSPEjw8F2nQDtmUKPFNF7_A",
    "cQV22i2vX7JVJpMPYifEqg==": "http://212.224.98.213:2200/EX/Nick_Jr_Too-uk",
    "lD+pVp1gDRq+FZwGRF2DxA==": "http://c0.cdn.trinity-tv.net/stream",
    "ZKaLXcmFdAbCR+SoWrOuhg==": "http://31.220.41.88:8081/live/us-nick.stream",
    "hb57TT8kivbtBSxa9lbiGg==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxnitrocircus/CDN",
    "30o/prKheivGNv4996kKkw==": "http://45.76.186.114:8080/hls",
    "1ktdAWEqyBqOB0VLfkEKxQ==": "https://pe-fa-lp03a.9c9media.com/live/NOOVO/p/hls/00000201/716cf4c845225692",
    "DpI62edzmw/i3um+NTLzMg==": "http://highvolume04.streampartner.nl/nos_pais_24_7/nos_pais_24_7",
    "jNwV9iSacIJWcQu9SMEzxQ==": "https://stitcheraws.unreel.me/wse-node02.powr.com/powr/ngrp:5eb1e76d1474f9020c06f9ee_all",
    "1xl2JdUBjTBEGeVd+5dLZQ==": "https://stitcheraws.unreel.me/wse-node04.powr.com/powr_480pt/ngrp:5eb1e7f848f1ff2e1d2555a2_all",
    "LmlwijDszws4zjuNPnrfoQ==": "https://stitcheraws.unreel.me/wse-node02.powr.com/powr/ngrp:5eb1e7261474f9020c06f9ec_all",
    "LvIDSty1uc0XK6u0njsdPw==": "https://stitcheraws.unreel.me/wse-node04.powr.com/powr_480pt/ngrp:5eb1e88458ad7801fa2cfc2e_all",
    "ZKLMeLn/GCfz1I1F9B/GyA==": "https://stitcheraws.unreel.me/wse-node04.powr.com/powr_480pt/ngrp:5eb1e84c95ee0253b97679d7_all",
    "24ELM9r/fh8pMGBZbiteuw==": "https://30a-tv.com",
    "5vk105gWhn7Hvn2Q1PGmMA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxnowthis/CDN",
    "IC6xWJlEDYfPYWbOXSYZpg==": "https://uni6rtmp.tulix.tv/nrbnetwork/myStream.sdp",
    "PXK0ucTL6WLgoJ7sxHrBOg==": "https://api.visionip.tv/live/ASHTTP/visiontvuk-entertainment-ntai-hsslive-25f-4x3-MB",
    "DWHqJM/q1uWipx2gEYRKTQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://dai.ly",
    "tA8ZMT6U0r+++/RGrwLTxw==": "https://2-fss-1.streamhoster.com/pl_122/201748-1282644-1",
    "hmdAAmWiM1/T26aX1a+daQ==": "http://oneamericanews-roku-us.amagi.tv",
    "V7VXpPrqdSO1l+qqPIMtRw==": "https://cdn.herringnetwork.com/80A4DFF/oane_oregon",
    "xUbfOoRt+F5uv66TZlk4EA==": "https://securestream6.champds.com/hlssstc/KOCTCALIVE",
    "tT7lR4RuDqtHZZrEdy1VEQ==": "https://securestream6.champds.com/hlssstc/KOCTCALIVE2",
    "VkMNlYBPZVl71wbCeRuUiA==": "https://d33zah5htxvoxb.cloudfront.net/el/live/cr1",
    "MXkoTBSRIE3P4KNRv9fyfQ==": "https://d33zah5htxvoxb.cloudfront.net/el/live/cr2",
    "z0MtxaGmYpcKx2s3yGzzJg==": "https://d33zah5htxvoxb.cloudfront.net/el/live/cr3",
    "jWQ/7moAUjk069XVWrC87w==": "https://d33zah5htxvoxb.cloudfront.net/el/live/cr4",
    "FhxvSIAEj9M4aMvbBE3y8w==": "https://d33zah5htxvoxb.cloudfront.net/el/live/dail",
    "jaGt4kyvMG44vTElBSynGw==": "https://d33zah5htxvoxb.cloudfront.net/el/live/seanad",
    "4IIoWY2QNAhgdYVzElEX9A==": "https://partne.cdn.mangomolo.com/omsport/smil:omsport.stream.smil",
    "1khCUc6DfJuriMbB4LTa5A==": "http://livestream.5centscdn.com/shaditv/23abe62a446fc05ce0a6c810f4045308.sdp",
    "MQ1CRC4v4fiins/AeuB8iA==": "http://162.250.201.58:6211/pk/ONEGOLF",
    "x0HYYbG963ae3oQArTle+w==": "http://origin-http-delivery.isilive.ca/live/_definst_/ontla/house-en",
    "PgKs4as7yEF5cFeqnVUAlQ==": "https://cdn3.wowza.com/5/dk84U1p2UUdoMGxT/ontarioca/G2446_002",
    "xeP0vbCs8IZiH5ErJqNsow==": "https://hls-cdn.tvstartup.net/barakyah-channel/play/mp4:ourtvedge",
    "K7SmV8/3yELWol6oY01Oqw==": "https://otv3.ocfl.net/VisionTV/smil:VisionTV.smil",
    "yYZM5efdGAocnC0JQ/Kw7Q==": "https://ogat.secure.footprint.net/egress/bhandler/ogat/streama",
    "QO0KvD3RwSgsBSAlJ1bRXg==": "https://cdn3.wowza.com/5/R09KQXpaMWlrRjly/cityoforange/G1025_004",
    "8tU8uB10xQeIK9uA02akqg==": "http://otv3.ocfl.net:1936/OrangeTV/smil:OrangeTV.smil",
    "NMLgmjroCZ78aPdtLK4cnw==": "https://d18toqrnfyz3v1.cloudfront.net/v1/master/9d062541f2ff39b5c0f48b743c6411d25f62fc25/OutdoorAmerica-PLEX",
    "iyTTqiNfNyQteRKdnQW0pQ==": "https://outside-tv-samsung-ca.samsung.wurl.com/manifest",
    "/lsWH7OJZVWq0fUvphv8Hg==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxoutsidetv/CDN",
    "Yx1UDyMG7IGEcs4/fTZ6MA==": "https://outsidetvplus-xumo.amagi.tv/hls/amagi_hls_data_outsidetv-outsidetvplusxumo/CDN",
    "F2vsY7EnC72SlgGzjfVU6w==": "https://pac12-redbox.amagi.tv/hls/amagi_hls_data_pac-12AAA-pac12-redbox/CDN",
    "Zun/zh+Ffmxb1ksaruCE8w==": "https://pacifica-ca.secure.footprint.net/egress/bhandler/pacificaca/streama",
    "eFHa8Be+ORbp5GomUnMh0Q==": "https://pacifica-ca.secure.footprint.net/egress/bhandler/pacificaca/streamb",
    "cV9Wo3zHOdWPW4Xf7psk2g==": "https://edge-f.swagit.com/live/palmspringsca/live-1-a",
    "rGPEeXxC9wK2WVDUOoYMsw==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5cb0cae7a461406ffe3f5213/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720/10&deviceVersion=unknown&embedPartner=samsung-tvplus&profileFloor=&profileLimit=&samsung_app_domain=https://play.google.com/store/apps",
    "ddnnaO6IFaF9tsKDFQuwQg==": "http://stream.pardesitv.online/pardesi",
    "sHyzWEnvm+SEscgEBP5Z2w==": "https://ptvlive.kordia.net.nz/out/v1/daf20b9a9ec5449dadd734e50ce52b74",
    "skQD62gOCUrJX5wRVHfcZw==": "https://stream-us-east-1.getpublica.com",
    "sRy+aFY2XZ31O2/XUzwk4A==": "https://pasadenamed.secure.footprint.net/egress/bhandler/pasadenamed/streamc",
    "XzpA0TGLolA/Q9PYFojDwg==": "https://pasadenamed.secure.footprint.net/egress/bhandler/pasadenamed/streamb",
    "jhKCRs4lulg079clHQuW+A==": "https://pasadenamed.secure.footprint.net/egress/bhandler/pasadenamed/streama",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "72uDe12HtwLJP+wMsbhnOg==": "http://uni6rtmp.tulix.tv:1935/ucur1/Payvand",
    "BXUC+yRo/1stwnFs46MQ2A==": "https://stitcher-ipv4.pluto.tv/stitch/hls/channel/60d39387706fe50007fda8e8",
    "XyuIK80sJjUGtihsu44jRQ==": "https://forerunnerrtmp.livestreamingcdn.com/output18/output18.stream",
    "ubAaNzwQv4gJAP28DpMZ6A==": "https://d1mxoeplf1ak5a.cloudfront.net",
    "ycGztV43HxcjwoaVduRvlw==": "http://trn03.tulix.tv/lnABbIUBrO",
    "h5VcMYbSUXwjzkiqt3EVcA==": "https://wmhtdt.lls.pbs.org/out/v1/5c496bd4d16348f0bca933eca69bdd1e",
    "WYYaLqenow0dS2z5hyg8vQ==": "https://knmedt.lls.pbs.org/out/v1/6bb7cfa3e3c34906a80c5babc026ca92",
    "vdwsNwMXMnphDT5JidKvNw==": "https://wneodt.lls.pbs.org/out/v1/59487e8689f14a92a443d8fd557ac948",
    "ZsxMMCNyzIA3fcXeYSAAZA==": "https://pbs-samsunguk.amagi.tv",
    "QB1CB5yToU2/+Onrx2f20Q==": "https://kakmdt.lls.pbs.org/out/v1/01b38c70d1e94da78deec21bb13383ed",
    "WJaYGLEwgSYjTtZ7jvibsQ==": "https://kwcmdt.lls.pbs.org/out/v1/e178660dc7cf4389bf8834e4bb10df20",
    "KxtzNaGLC61VLs5swS8pLw==": "https://wgtvdt.lls.pbs.org/out/v1/1fe7fe6e36524881bd999a7003394ec7",
    "EBMnbgS8bfTTin8n20d5aA==": "https://woubdt.lls.pbs.org/out/v1/f9f879eacf9c4b3d859b93c1f889a5e0",
    "HagbS9xYB0Q5236PSSoF4w==": "https://klrudt.lls.pbs.org/out/v1/c5d426d04957476186321c38e943c49f",
    "5hZZYhrpP6lhF7jUdYL/jA==": "https://wdcqdt.lls.pbs.org/out/v1/ef33b9ec5f2f42ad831574cbb2c478f8",
    "WxpjzxD8+Ppgo6N9cxIU9A==": "https://wlpbdt.lls.pbs.org/out/v1/3f6379f418924ca39e09415a34c92738",
    "wPVrkx8cyr8VINfVLViyMA==": "https://wskgdt.lls.pbs.org/out/v1/ff443d82d55c481a9d1561c5f77a3a4b",
    "NoH3IRjp3MqokhWCVrSklA==": "https://wbiqdt.lls.pbs.org/out/v1/3d5c7da724d741da9b8e203d03b6b8c3",
    "B3XesgGuNT2AKRd3AMvp9A==": "https://wtiudt.lls.pbs.org/out/v1/189f0df07ad448d29880d68f295ab06e",
    "O+bKKEJ+bo3eRU1Rwj583w==": "https://kaiddt.lls.pbs.org/out/v1/1ba7213ff76e4f3cb73405a2108922ce",
    "LCI351y6mipAKQs9aWGUIA==": "https://wgbhdt.lls.pbs.org/out/v1/0e31746edf794871ab0f06cdb48c1e82",
    "3Tgp27qj6ULxGI+DJIffVg==": "https://wbgudt.lls.pbs.org/out/v1/6e28e12e9db04b798dc82052cc6d3375",
    "L9c8g2FF0mZvlJrvdyASUQ==": "https://kusmdt.lls.pbs.org/out/v1/ad7a1ac654bc4231854568d83529f893",
    "ybu6ZNxZdaZpMZxNDSjUCA==": "https://wneddt.lls.pbs.org/out/v1/9042ad5168e54cf8bf14b5db5582a84a",
    "01sDFwR2DZfOh64hoRoyhw==": "https://wetkdt.lls.pbs.org/out/v1/9c3c95a5cabc4611b06086ae798b7716",
    "F1zIXP3Y1BVE/iJxkhD33w==": "https://wuncdt.lls.pbs.org/out/v1/84bedaad5c7e4d7abd8a6b63f1b8d4c4",
    "zyIUM03y7JRzI6NVvktF9Q==": "https://weiudt.lls.pbs.org/out/v1/9f2dc5c07afb4e2a8b704e1462030872",
    "FVUcFiGxZvoKv24ud+gPwg==": "https://wtvidt.lls.pbs.org/out/v1/e01f07bdc0cc4375b8894f72b1f0bb40",
    "84QPHQnc7N4wzgnbCIfAGg==": "https://wtcidt.lls.pbs.org/out/v1/b9b09144bbaf4c5b864711748cc32680",
    "oWphOGi7Obi46gDEyzutLg==": "https://wttwdt.lls.pbs.org/out/v1/c9c6c698c02f404190e9e5a4e9f4e903",
    "uk3pD47PNt12k4cx1jQ1VA==": "https://wcetdt.lls.pbs.org/out/v1/742a384715ac468cbcd93fef92dafd9d",
    "Q6uyIitBA485UCC0e2Jg6A==": "https://wvizdt.lls.pbs.org/out/v1/94ec1f9fa451444789391cd8558ea5ed",
    "M1JK+W/5ieb3ygUg4qsprA==": "https://kamudt.lls.pbs.org/out/v1/60a3ebbf04084e1e851df9b22d45a5e1",
    "E6qrBW1pYJNIUlsanDbLhQ==": "https://wrlkdt.lls.pbs.org/out/v1/ce2d1420a66b4c2a88d8a48ffecd908d",
    "P7VqewHrkz7Oat5S66XBgQ==": "https://wosudt.lls.pbs.org/out/v1/72f8d6d91e614561b97f37439cd13f81",
    "LURN0uqbwbkmOfF3Vwkxfw==": "https://wctedt.lls.pbs.org/out/v1/f7929641d8ae4f0296b10e77ffe6d31c",
    "Hk2NVD34vC+AyU9F7vbcHw==": "https://wknodt.lls.pbs.org/out/v1/b7065d6c2d6047c0bb5bd9e20202103c",
    "ZHr9QG4ppf85rpxG60vrKA==": "https://kedtdt.lls.pbs.org/out/v1/2955c90649c44dac83a2a77513c0b861",
    "g2+zEbt9iEpiW095oMTqnA==": "https://5e6cea03e25b6.streamlock.net/live/CREATE.stream",
    "vmVW9uf2ndBiuICzez827g==": "https://keradt.lls.pbs.org/out/v1/8dd50e7e0ee24d4e8a0812872f332a2c",
    "/9sgPyA/ffFwQa7sOqFHDQ==": "https://wptddt.lls.pbs.org/out/v1/f372be5c7a994b3ebeab2797323de8ee",
    "x+EqCv/FgGaVgtE/ZRIKKQ==": "https://kbdidt.lls.pbs.org/out/v1/5a01f14ff4e4492eb7cda1a79b0ced60",
    "f8FQe1neT54FCgkc+JeQnA==": "https://krmadt.lls.pbs.org/out/v1/45cb988e1a7440288aae1fe7fe819841",
    "CE4r2cUeSf+CZP1QTmF+zg==": "https://kdindt.lls.pbs.org/out/v1/e41a89f5fe884dbea2c80fdc974b21c6",
    "AYESGj3z6eTO0YHGGq8l3w==": "https://wgvudt.lls.pbs.org/out/v1/a9456b151c3e4fe490213e776735bb16",
    "u7Hd0SmS7vllGRR0YaB+xw==": "https://wdsedt.lls.pbs.org/out/v1/33c52d8e7d6e43099ff584805245b694",
    "Dn8+SGRFLTXiBQcqcwg+tw==": "https://wenhdt.lls.pbs.org/out/v1/a1c1eea03387432086459cf0fdd96334",
    "G8totHDnLxhW/lj+3F2Vtg==": "https://wkardt.lls.pbs.org/out/v1/5b13b5c72f5d4b80a6ee9140392caf74",
    "lIxymvXRES12pncS4gMEGg==": "https://keetdt.lls.pbs.org/out/v1/a223371529b14afa882d1e872d8acd3d",
    "APM9u4Jrh5wadq5OXbdbyg==": "https://wnindt.lls.pbs.org/out/v1/338a207086464e179e97f83d4b1798be",
    "9zxj+YGE6JBj5Qf2/DESqQ==": "https://kfmedt.lls.pbs.org/out/v1/25be24fcd0864ec9be6f6b60cb2be826",
    "4haF33mSetgV6OBEPMwItA==": "https://wgcudt.lls.pbs.org/out/v1/ac57905c80c8486a8290af7ca78c5026",
    "heDr9DZoMcx2jvKsBzbDig==": "https://wfwadt.lls.pbs.org/out/v1/8b2a780393274c2ba9b71b9168df2208",
    "LVmSX7kFtN6yyQPa3/X/kA==": "https://wyindt.lls.pbs.org/out/v1/27414b46e52d43758be8227e4a91c863",
    "Mdxmh8gs2zEu6N+1C7sliw==": "https://witfdt.lls.pbs.org/out/v1/15cd55cd6f7442c4a193a47bbfae608a",
    "S+RpbIs3RpNK/+5LEOJOcA==": "https://wedhdt.lls.pbs.org/out/v1/04182c8d6be24c1a98de212f3c55a442",
    "tiS+Yw2YgmwJHpvQJ7JMuA==": "https://khetdt.lls.pbs.org/out/v1/7ec7903413294b72bb64f83963d8ea9b",
    "0FnPhjgns0pUhTAY1LzGFw==": "https://kuhtdt.lls.pbs.org/out/v1/5b02f861c8e6453aa2b6cd8c6d26e698",
    "2jyy7GlvfkXuMGc6hsOGaw==": "https://wfyidt.lls.pbs.org/out/v1/f969c8f98dc24032b3879664b622ead0",
    "TaEGOlIoQ/W+tVfYkQROmg==": "https://wmpndt.lls.pbs.org/out/v1/d914d235ec79418a866aef53f54f2bd2",
    "NEf9e/Cvhadq/TnGx+QzgA==": "https://wjctdt.lls.pbs.org/out/v1/a691e1e86f77462d81a738395505e911",
    "2TZ8gsXc1vSpLJJVywNNxA==": "https://kcptdt.lls.pbs.org/out/v1/f63eb4e92e484fae845c31912340e2a2",
    "YIHYKWbWfIuHR+9XiOzH7Q==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://api.new.livestream.com/accounts/28355708/events/8865717",
    "H3aPOv5PedRcoS6+0nDYqA==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://api.new.livestream.com/accounts/28355708/events/8904290",
    "scuiPvecRjNo9Ik0rl0LRQ==": "https://2-fss-2.streamhoster.com/pl_140/amlst:200914-1315484",
    "rGukuAECHjLHKYiv1s0g3Q==": "https://2-fss-2.streamhoster.com/pl_132/amlst:200914-1315486",
    "kJoXZFmnvb0IGiWMAGxe0g==": "https://2-fss-1.streamhoster.com/pl_134/amlst:200914-1282960",
    "9q/DHzAUC6l4MaZpv6d79A==": "https://2-fss-1.streamhoster.com/pl_122/amlst:200914-2942150",
    "5MyWfO/kZxy7TAXb3S8seQ==": "https://livestream.pbskids.org/out/v1/2963202df0c142c69b5254a546473308",
    "gNy9b8Qs65u2utpLR9nqQA==": "https://livestream.pbskids.org/out/v1/1e3d77b418ad4a819b3f4c80ac0373b5",
    "xeRtoTvggm+/k3giFuHApw==": "https://livestream.pbskids.org/out/v1/19d1d62bf61b4aea9ec20f83b6450a4e",
    "bYh9gfQj9VlqjJQ7wEbODA==": "https://livestream.pbskids.org/out/v1/00a3b9014fa54c40bee6ca68a104a8a4",
    "oUwBlGEn0JWU1hy3/IvXIw==": "https://livestream.pbskids.org/out/v1/c707b9310f2848de849b336f9914adbc",
    "MATEIRAYI7uwKf6PWCOy1w==": "https://kawedt.lls.pbs.org/out/v1/b3a7b02a0d4241a193c91f1f33755c85",
    "qFKi3SZYhHx86nv/6yJSJw==": "https://krwgdt.lls.pbs.org/out/v1/9cbfc7807e834ee39d2849c1bad667f2",
    "vdeD12kpgc2DBUCfzIiRLw==": "https://klvxdt.lls.pbs.org/out/v1/c2d457573e4d4783b558c44e20547e21",
    "EonPtVW1QUUOO+csWFRuVw==": "https://wcbbdt.lls.pbs.org/out/v1/d1ca1cb603fd4da09694f0f1f6ba8db0",
    "OkHU86QkIeK3rGxpaoUXyQ==": "https://wkledt.lls.pbs.org/out/v1/26354efcebc1400e8861988cd6a321ca",
    "fRUDRloQKD6DBzDmy1rdkA==": "https://wljtdt.lls.pbs.org/out/v1/1ddf810d67f64eeeab40ad9da8885945",
    "gG/wjyeqYWfxP4/z5M5B5Q==": "https://kuondt.lls.pbs.org/out/v1/91d8b5ffc5c1453c8a621508a07749a6",
    "xy0UnUvEQ3LGDpf1eSsH/w==": "https://klcsdt.lls.pbs.org/out/v1/6ee318cffa774733acf31f9a1af38036",
    "IH6GE2GslMzkMpduepIyvg==": "https://kocedt.lls.pbs.org/out/v1/75f564cba25e4053a8789a1a14d13344",
    "zexzHiLy+A38dhpV16Kmfg==": "https://wpnedt.lls.pbs.org/out/v1/12d4e3cd7f2c476ea575165bbfb5ac50",
    "Xd7davPfp6nhxN0WLtC0dg==": "https://wnmudt.lls.pbs.org/out/v1/d762d9a7dd4a46c08ca89b1a1abbc475",
    "9Tr1oiVGtEUKbdZB40eH4w==": "https://ksysdt.lls.pbs.org/out/v1/aecb830f3f7146a5ab62bacbeeaff661",
    "cUERG9wVETchYQArG7s9SA==": "https://wlrndt.lls.pbs.org/out/v1/9e8346f507f645259f0c6f2837fb7cbe",
    "2r5HYF+53euaJlO9YdNTSw==": "https://wpbtdt.lls.pbs.org/out/v1/0fbd3da6bffb465ba84f94abaff14973",
    "UU0JFQlv09urB3VsAKWZwg==": "https://wmvsdt.lls.pbs.org/out/v1/654e3fa9db6d465ea578cf39818fcee6",
    "M+/TW9eI0XYhCzCY1U4OVQ==": "https://ktcadt.lls.pbs.org/out/v1/21103812ea504393b7f0d521a8b37ab7",
    "jXjli0DlIrkqNamt/kFvgg==": "https://wqptdt.lls.pbs.org/out/v1/6ab72cd3813b469cb5f79a577d49c0b7",
    "dwA8WvSt9PcI8S8emsSdOA==": "https://wcmudt.lls.pbs.org/out/v1/45ff0524571c41398c5f39ebab6262ef",
    "T2suSlASiQUyTqCpbHjI1g==": "https://2-fss-2.streamhoster.com/pl_138/amlst:201814-1291584",
    "rFt8nH6kFQ8AlNqT4bhz0Q==": "https://wipbdt.lls.pbs.org/out/v1/73cd2d86797b4fc6ac5b660cd5a6f9c4",
    "QQ1ACS6O+YOhjW5Ku1NlSg==": "https://wnptdt.lls.pbs.org/out/v1/f6bca6d722674c5cad621f54b17c217b",
    "sRCWryKg2oph94n62Z11bA==": "https://pbs.lls.cdn.pbs.org/est",
    "n+E4v9DdoEIIXIc0xGThsQ==": "https://pbs.lls.cdn.pbs.org/pst",
    "vvrAECdhnnQpiF2IVkBifQ==": "https://wnjtdt.lls.pbs.org/out/v1/e62efd8d4f92403996425fc389df0ffd",
    "qUQhOxQKZD7szzPASK8EaA==": "https://wyesdt.lls.pbs.org/out/v1/3d4b8e15f65d475f8278fee4ff14becf",
    "mcBRBnbU1P8GwvNQUTd1ng==": "https://whrodt.lls.pbs.org/out/v1/3266ff3730e745eba63de795e95e3c08",
    "UDf4ry186BeNjtMmgAYDyA==": "https://kpbtdt.lls.pbs.org/out/v1/9b66cea20b8341b8accdb0d20a49431f",
    "Auw9+YkRdEYoXk8QpmnCYg==": "https://ketadt.lls.pbs.org/out/v1/b718c2a2e2ab4a67a0fce0b1c3fb71a9",
    "KmtvTHbfiuTyltJ4osFxdw==": "https://wucfdt.lls.pbs.org/out/v1/6557aa0623bc486d8fb3e54afad37307",
    "4qZA1POaQ0loJ2awYI10Lw==": "https://wmpbdt.lls.pbs.org/out/v1/d1dbc3dc021148fb9ba084e7a68c3739",
    "2bEax6FvZDB6lpUonozp/Q==": "https://wsredt.lls.pbs.org/out/v1/d615170d96024c229c6ae2177dec84e5",
    "pUvIIVAohf9fEqNJEQciUw==": "https://wtvpdt.lls.pbs.org/out/v1/9e8f6bfce87a437d8a8a9aab016421e8",
    "mSl9nb6MKpIgmWrB54FAXQ==": "https://whyydt.lls.pbs.org/out/v1/40b7857a84ee4302be8ab755a719cc14",
    "/m96xzuv003Cy9IibbQiiQ==": "https://kaetdt.lls.pbs.org/out/v1/259f25e61b3d47ce8a7e2339a00c5561",
    "Fsje0Kui3fgjmxh/xwzk0g==": "https://wqeddt.lls.pbs.org/out/v1/1f10d52cea0f45ae88184800e9e6b79e",
    "jNd134lpkjbUDm7UVskG8w==": "https://wcfedt.lls.pbs.org/out/v1/9483ef28a5a8442f8ff45b26ac23a9b0",
    "sYr9bKfpCZRpAVrCgGqTLQ==": "https://kenwdt.lls.pbs.org/out/v1/5a08bd0c12464a42959d67ad54324081",
    "07ZgKm2cnDO+aiK1aYXVFw==": "https://kopbdt.lls.pbs.org/out/v1/a946a78ff0304b51b4f95b40f6753f20",
    "2mwjB8dEWnhOpK6552Z9zg==": "https://hls-wsbedt.lls.pbs.org/out/v1/282a0653ed3341ebac0ff99c0f2a8137",
    "leQNrYMh0rEVGkwPiHTcjw==": "https://kixedt.lls.pbs.org/out/v1/fb0ef314bff940b18d8ff89dcfc0e395",
    "zgmmRHl+/mI1peNF6ZScYg==": "https://knpbdt.lls.pbs.org/out/v1/662db9937fe94ff997eda3af5a09ea43",
    "CTfeZNeUv7fFzd+ruFnxhw==": "https://wcvedt.lls.pbs.org/out/v1/178cb4bb51c44edc9bac3365ddbc66ca",
    "nM1NrqJSEB5rLKL84rgeoQ==": "https://kcwcdt.lls.pbs.org/out/v1/2f8c171f73764e29893631dad5be2849",
    "7Hc0Yhbd8MSRFlkgv0dq5A==": "https://wbradt.lls.pbs.org/out/v1/cee6288a82584aee9e105cc7abc51da9",
    "i9f5XTUYXo0kMhSllmWvEQ==": "https://wxxidt.lls.pbs.org/out/v1/9ea6c5eb539d4545b74b67d064d12395",
    "66HTQG4TvCi6BjwS7IuTbA==": "https://krcbdt.lls.pbs.org/out/v1/1b383c47407b41a28a57037ee7fc237c",
    "s91SFPFovQw604bcG9uA5g==": "https://kviedt.lls.pbs.org/out/v1/034f052201e7437da6266c4679e97526",
    "r1k2AjM6OdzpXqCcuHt0hg==": "https://kueddt.lls.pbs.org/out/v1/53400b74960e4a84bc4b945148e9e19a",
    "Ac++XytBg3Y87gri5gZv2Q==": "https://klrndt.lls.pbs.org/out/v1/4d29690f8127489fafb33fb5ebd2cbeb",
    "sBwWjd9HDG44bnbp5G2/0A==": "https://kvcrdt.lls.pbs.org/out/v1/5114aad2d1844ccba15d559173feec19",
    "8hlV/kK7cZ4PWMCK+Nuvnw==": "https://kpbsdt.lls.pbs.org/out/v1/cf509cc4289644f886f7496b7328a46b",
    "Mt1z7IkMgWDWWr8LB6W9LA==": "https://kqeddt.lls.pbs.org/out/v1/7bc5c6cfcf9b4593b7d6ad1f8b0a0138",
    "0H8toCUA8o9Ajam9tYL83Q==": "https://wviadt.lls.pbs.org/out/v1/aa3bcde7d86a4b60b57f653c565188df",
    "u+Pezhl9eCmg3r+YnialAg==": "https://kooddt.lls.pbs.org/out/v1/67d31d78887e485282d135628be5489f",
    "0g2wUEpM9HQMiCXU6blIbg==": "https://wnitdt.lls.pbs.org/out/v1/0eb01a8a161e4650af15b6542a20cde5",
    "WLGHMGdltG209QrBQW0UnA==": "https://kspsdt.lls.pbs.org/out/v1/cf8babf84d2b48e3876bae15e08dcdc6",
    "IRKBUFCYOohQEF/QQgW8Yw==": "https://ketcdt.lls.pbs.org/out/v1/08273a78d29c4b0abd6e0eb996b3d8cf",
    "O6xBncJO/ANj1ts+ztEh2w==": "https://kbtcdt.lls.pbs.org/out/v1/4f08c8e00549441b9a2acce47d112525",
    "UMmtR37I2EjhOW247s24+w==": "https://wfsudt.lls.pbs.org/out/v1/d2be172139764358a0d54352c8411845",
    "3BvqxHjklZwvM4GIgn/AXA==": "https://wedudt.lls.pbs.org/out/v1/3e147f13bc464958b6ace4e5a5b9accc",
    "0lXRJ0ZhVqgLg75Pmak5Cg==": "https://ktwudt.lls.pbs.org/out/v1/567e503539034dd0ab8838b7e33ba5de",
    "7DmOYwoLLg7GHSwZkwC43w==": "https://kuatdt.lls.pbs.org/out/v1/8d95fb8559594a7b9359077ea0a512c3",
    "AIJnuBEWPRHpmNXno5+joA==": "https://willdt.lls.pbs.org/out/v1/15103ad003674a29b20b847deb71992b",
    "2ppR+QrtZ17e/vjtg/UHoQ==": "https://kusddt.lls.pbs.org/out/v1/38b8947635c54de8a15c5260e5cf774e",
    "exfw8Sik84LQjiyznrAhjA==": "https://wvutdt.lls.pbs.org/out/v1/6f47817ed7d54053815e35042c1f4824",
    "ivIMc1gmYjm/WuwHH0HjpA==": "https://hls-kmosdt.lls.pbs.org/out/v1/95689f4594814dfca261ea90892eafab",
    "vGpEF5HUMxCy/VSp7tCSxQ==": "https://whutdt.lls.pbs.org/out/v1/dd1102f24d7948e58517ba6a6573c928",
    "gsEuGRIhF3Sc9Qvv5onNtw==": "https://wpbsdt.lls.pbs.org/out/v1/e3680a91029c4df9b7797ce13d828207",
    "Qf73KxEINXeWROht6Yh2DQ==": "https://wxeldt.lls.pbs.org/out/v1/d4f2bc8357164a2e93d35abd2caecc4b",
    "gqeyneCM5g2nc49CY3vVLA==": "https://kptsdt.lls.pbs.org/out/v1/1ca3404d6bc3404c9daa86c8f1ae19d0",
    "zV02wei+RPFUJG+NM8yz3Q==": "https://cs.ebmcdn.net/eastbay-live-hs-1/apt/mp4:apt-world",
    "GDx+y6VwxW/MHmHMOAk7jQ==": "https://d1qaz9zojo1ayt.cloudfront.net",
    "PXUgcEFiF3CMz8Y/fCqGNA==": "https://fc2f8d2d3cec45bb9187e8de15532838.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Roku_BabySharkTV",
    "FpUeKsHLPzNLyjF12LEViA==": "https://cdn3.wowza.com/5/cXdyRHF0Z3kxN0k2/pinole/G0032_004",
    "t8BAR/BgBjjDSkp+tUi8Og==": "https://cdn3.wowza.com/5/cXdyRHF0Z3kxN0k2/pinole/G0032_002",
    "kAF5Nx55xJ2b5ORY08N5FA==": "https://cdn3.wowza.com/5/M0lyamVmM2JWcjhQ/placentia/G0928_002",
    "0rWNDTXh5se17aLpm3DEUg==": "https://hls-cdn.tvstartup.net/barakyah-channel/live/pbtv",
    "K0SpcjtqBQMCz2GTTXfgoQ==": "https://b12eca572da7423284734ca3a6242ea2.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Plex_PlayWorks/playlist.m3u8?ads.app_bundle=com.plexapp.desktop&ads.app_store_url=https://app.plex.tv&ads.consent=0&ads.gdpr=1&ads.plex_id=5f0ff263d71dcb00449ec01e&ads.plex_token=MorUy57ijWhGe4ixZb_T&ads.psid=df8e1a36-847d-5096-86a7-3803ed330ede&ads.targetopt=0&ads.ua=Mozilla/5.0+(Windows+NT+6.1;+rv:83.0)+Gecko/20100101+Firefox",
    "DwYO/iYxcVv4XLjsBr9o+w==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-xumo-playerstv/CDN",
    "60cWlw/cGIyv03F7qWrVcQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f4d878d3d19b30007d2e782",
    "Z8d1N1jyNiHp6Kd31rW6dw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5ca525b650be2571e3943c63",
    "s6j6AL2kIm3f2gECbH1okQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f4d86f519358a00072b978e",
    "M00CtryWeF1+RtRlhOJKBQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f4d83e0a382c00007bc02e7",
    "AqXebPAy2ZIiZnMdC7xQ5g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e84f54a82f05300080e6746",
    "6gPLbk3m403X2KymucNTkQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5e8db96bccae160007c71eec",
    "aTo8m9OfifPmwPaAvKDAhQ==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ddf8ea0d000120009bcad83",
    "nG9e14Z81W30poT9xaM5Ng==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ad9b6f57ef2767e1846e59f",
    "6ecUBI5BjeFB1sVs6+W4+w==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5be4c6311843b56328bce619/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720/10&deviceVersion=unknown&embedPartner=samsung-tvplus&profileFloor=&profileLimit=&samsung_app_domain=https://play.google.com/store/apps",
    "Hw29CCM8UKi+T1QxmecujA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5812b7d3249444e05d09cc49",
    "mPrNGWXn7KPyJwxDfV5y4w==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/600adbdf8c554e00072125c9",
    "924CyCugIC/IeW1HAkcjFQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5595e43c66ace1652e63c6a2",
    "oFpXtbJkgXquTQ7+uUNX2Q==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ebac49ce4dc8b00078b23bc",
    "n4VXuZ92GjKosrQgkpExLg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5cabdf1437b88b26947346b2",
    "7zIS9+QQX3JC1lx1TfknEw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d815eb889bca2ce7b746fdd",
    "VEJH33Sx8IY/3uOFs/y76Q==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5ea18c138c32460007cc6b46",
    "ePSOtjfLHk7L+cjFaxav3Q==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ebc8688f3697d00072f7cf8",
    "ciFxDzcWcmnnazDs99yxEQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5887ba337b8e94223eb121bd",
    "D6YJglPr0QLVeXS6435+sA==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ca670f6593a5d78f0e85aed",
    "6IXHvBo5uc7vk/HRcI0zww==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d51e6949ab8e2b35bdcaa9f",
    "Okl0zi+Xz0Ffg70vHw9p0w==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5db81695a95186000941ee8b",
    "4GcBxk7bIsh0EkIdsxPbNw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f1aa7aab66c76000790ee7e",
    "idY7RITTVp0nqQzUvFfvOQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5d4af2a24f1c5ab2d298776b",
    "jQs1F1O8B48zZ2G7ok80Xw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/58af4c093a41ca9d4ecabe96",
    "z+DDzSnMC5n3CDaQcPcX0A==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d51e2bceca5b4b2c0e06c50",
    "HQyc7d71BtFqZZC5/IhMOw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e46fba0c43b0d00096e5ac1",
    "N/IKN5a/xNDJHEfEa+IN4Q==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e8b5a4bb7da5c0007e5c9e9",
    "4buxoKHOK9HoIeLqpZhc3g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5812b3a4249444e05d09cc46",
    "RnsP+x1Tb8Q/n653Ms+jAQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5eb1afb21486df0007abc57c",
    "FNGuRW0dw2vBUH/AjW7LGA==": "https://cbsn-bos.cbsnstream.cbsnews.com/out/v1/589d66ec6eb8434c96c28de0370d1326",
    "wnj13g4bXkr9AnsAoJzW4g==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5eb1b0bf2240d8000732a09c",
    "AWdXzNiHrE5Z3wErlxDgvQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5dc48170e280c80009a861ab",
    "P6mTp9Hup2KbSqpUciI/uw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5eb1b05ea168cc000767ba67",
    "hGXCMYpGyY86USzXcBLFxw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d8bf1472907815f66a866dd",
    "rTWwmp0WkeX4HPKLqCtiRg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e8c4c3f141f350007936f7d",
    "fUEtxQosImBsLIMf+SWmxg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5cf96b1c4f1ca3f0629f4bf0",
    "lqLQUSxKvF5TEhVKrpOxmg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/561c5b0dada51f8004c4d855",
    "UAEh3ZOPsaq4rSOR+L8V8A==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/562ea53fa9060c5a7d463e74",
    "dA8+4O8uJqmipcYCZ5YIXA==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e46ae801f347500099d461a",
    "N+NqMsxDn4aOTu4n6x6JoA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f15e32b297f96000768f928",
    "e4Zl/mCKn4Jerzmb7nDZ0g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f15e3cccf49290007053c67",
    "Ls1mFh2a3zOBig0GM2brOg==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5dcc42446750e200093b15e2",
    "KX4LvANSxnGFGn+1aoQpUw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f68f53eb1e5800007390bf8",
    "9YF5vfWM0+aQRBLgRxZ+1w==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5b4e94282d4ec87bdcbb87cd",
    "B5Xfc2XtTKI4P1Tii7vmRg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5421f71da6af422839419cb3",
    "vpc9L/w5VUBCAL4JVwUfDw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5c37d6712de254456f7ec340",
    "zp/sZVHUSMSNQSl9CazbVA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5bb1ac3e268cae539bcedb07",
    "QKn7QsYo1ViHEH66ug2AXQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5c363c2411c5ca053f198f97",
    "4xr/IEIta23/NJE1chOtcA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d4947590ba40f75dc29c26b",
    "bHr0zuTpxCwqOtd9SXX7Dw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f99e24636d67d0007a94e6d",
    "31sUbXeMtWf55VLrzqC5UA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5cf96dad1652631e36d43320",
    "XaRKFDfdLlqsmus2+Mfp7g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e1f7e089f23700009d66303",
    "jiE7fufgbXjk4PRHQnCvhQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f31fd1b4c510e00071c3103",
    "aMZ6gxC6wsgW47k4mks4kg==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f4d8594eb979c0007706de7",
    "BHejb21A/Lo9Xj3+Quy8sg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5efbd29e4aa26700076c0d06",
    "ZnTis/sxmRZm4/0a2y1/Eg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5c665db3e6c01b72c4977bc2",
    "uEc1t4oQ1rFeonnyFjtHtA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e843d849109b700075d5ada",
    "18YYuaQ+u47Dome2xhKcQw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ef3958c66ac540007d6e6a7",
    "LjHXCtW3+ILUxpDuzqddkA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5ca1df0d50be2571e393ad31",
    "bGt63V328roEL8uhejJUxQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e9debf8c881310007d7bde1",
    "yBwWbw4WKGdn8toSAHIL0Q==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5c6eeb85c05dfc257e5a50c4",
    "yOYQ0Bm5QXaRQfGlnvDtLQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ce4475cd43850831ca91ce7",
    "gSo2AhkT/aD5XqdGNun89w==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5b85a7582921777994caea63",
    "7Ijf2CHt2iAxsOSTO1cZaw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5bee1a7359ee03633e780238",
    "USTBM0isltLW4z62PrHM8g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5b329e0a7b9d8872aeb49ceb",
    "dSbg05r6M84ki/NciHbnFw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e43c344b54fe800093552f4",
    "9UbtdVPqQbAibmMOl8YADg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5b4e92e4694c027be6ecece1",
    "d1kqmmzv5S1HuxhXU3AvDQ==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ddf91149880d60009d35d27",
    "Z3quW2fYQoAwPu/uA6hqww==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f24662bebe0f0000767de32",
    "91NhJT1uJT72kX1wFezo/g==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f6b54b9e67cf60007d4cef1",
    "QYy3CGJ8PDCNgAwNAv008w==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/60d3583ef310610007fb02b1",
    "EGmyk7hsrIZBzhamjtCeow==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5ad9b8551b95267e225e59c1",
    "G8PWExt+wYxNicH8EKSkRA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f8ecd9169d2d4000864a974",
    "H8BhorhOUBr0Aig5vm+evQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5c58a539fae3812612f33ca3",
    "1gmSEjmZJ84Yg6+HrcsCew==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5dc3fc6b9133f500099c7d98",
    "/QnufKZUbRBpffA3JC5V3g==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f77939a630f530007dde654",
    "CsxvgRDwM2Zf/0p0W+0lJA==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5b64a245a202b3337f09e51d/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720",
    "L2gmpNvtpVIOf6ovBbFTrQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5cb6f6f9a461406ffe4022cf",
    "dbXDeZWm6xOEYN5PpV0I+Q==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/588128d17d64bc0d0f385c34",
    "DAqNJ+A8JdYlZa0bCLRWdw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5ca1de9208ee5378be82db3b",
    "BwTrapws1jZlILKNax04jg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ad9bda9fd87eb3a2717cce0",
    "wDmjxZOdLqAktjSaFW55gQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5d4af39510fd17b31a528eda",
    "3teyMFwzL8WQZWOHBKDmTQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e8b0c92783b3f0007a4c7df",
    "7dhSi/H97/aBMOUdBRtGAw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/58e55b14ad8e9c364d55f717",
    "V347YJxrDd2cMOAGD4mKlQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5877ac8cb791f4eb4a140d81",
    "YMsuQHa+rUcJcldah8ueEw==": "http://stitcher.pluto.tv/stitch/hls/channel/5bb1af6a268cae539bcedb0a",
    "oNFz6oTGGUm3o2BsikvmNg==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5e78faa05a0e200007a6f487",
    "3THVrXvaJenxLFjQHBEycw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/580e87ff497c73ba2f321dd3",
    "KZxnlxVb6+IhTywYcWvg9Q==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e54187aae660e00093561d6",
    "CPYDdjoD8na3x+S02VI/pw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ca7f16c37b88b2694731c79",
    "ywa91XJuK4QyS091VoAV0w==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5dc2a69bc928a600093a7976",
    "EgCWEBxHp19rHOmXUCDD0A==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5c45f5a9d40d58066869fa60",
    "g03n3KHwIdeHr6Y0k2aIaQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f27bbe4779de70007a6d1c1",
    "IS1fHno+rDNGt0NoYJjW4A==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ad9be1be738977e2c312134",
    "aYcyDLiFviBc6Colioixow==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f1aa89d42a0500007363ea3",
    "f/KvwvVWpXeJ8W1GSvVs+Q==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5b4e99f4423e067bd6df6903",
    "g66BGmoiwcT2M/Jz7+NADA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f7794162a4559000781fc12",
    "A2dGY3B6VSGjxLZ5I1P1ZQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5c5c2d7ae59bf23c192c411c",
    "dt+GtI4TnU4eVomRgx4CRQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5eb96303f5bb020008e7e44f",
    "mfbOt5sl7KZBF31hS4xWew==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5c5c2e9d8002db3c3e0b1c72",
    "wZ/KEjTMZ21GKLm42ZU2kw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/569546031a619b8f07ce6e25",
    "dMHwhj9K85Ra6jUBQAywwQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5c99f5810c95814ff92512f9",
    "3XT5Fqh0RNfMcvSJvmRkSQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ce40f42ba7f7f5ea9518fe1",
    "9uGqCJlY2PuRGmxpNphV2A==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5ce40e59246a395e9758923e",
    "1DIRszt+62LXocqPhAC2oQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5dbc2d1ce10f0b0009e6cf9e",
    "Yz4JtZ4gRhRbhcscvn6tGg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e9decb953e157000752321c",
    "u7byRE5TAtuk0xab3pQLpA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5af09e645126c2157123f9eb",
    "U73+P3J+Qwtf2M/r1I8G8g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5db0ad56edc89300090d2ebb",
    "S+eCBhfr2MTeP5rUSTyqOA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5eb301b7395671000780d100",
    "dr59SYY0D3wYhbbTkpEaZg==": "http://stitcher.pluto.tv/stitch/hls/channel/5873fc21cad696fb37aa9054",
    "/yycwIQ+aoRNiYvgMMKR2w==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5dc1cb279c91420009db261d",
    "se/DQcMR5Y9bPelDjXSwjQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d8beeb39b5d5d5f8c672530",
    "otNIy9HZpKWP50CcdMuR3g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ce5a8954311f992edbe1da2",
    "SfwvMgQnZHaWYPj6OtzB0g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d51ddf0369acdb278dfb05e",
    "l3tDhqmcsg1ZCGeu0E4tJg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f15e181520cfa000771ce79",
    "tLJbTMybAv4iEdd9qcG47g==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5e14486590ba3e0009d912ff",
    "VmvpHUxXQjYqqQFH3PGwjQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5ea18e5df6dd1d0007cf7bad",
    "zubnzkWK3nX8kJmyzWiXeQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5cbf6a868a1bce4a3d52a5e9",
    "NhZT36XLV+UYofOCjr8TcQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5bb3fea0f711fd76340eebff",
    "d07IKZcck+NV4yiQWeLwIw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f77977bd924d80007eee60c",
    "I35YqKU17hN9OrH2DVvBxA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5e66968a70f34c0007d050be",
    "jo4LL7ZpL0yCKLShvPavKA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5cb626cfcaf83414128f439c",
    "zxoBqVP7XnTxN08dmW1p7Q==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5c5c3b948002db3c3e0b262e",
    "dCL4hbz5BNxfJ3XjnHqZaQ==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ca672f515a62078d2ec0ad2",
    "0Gbz7YfMJbHqBTTGyR4N+w==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5caf325764025859afdd6c4d",
    "set+nqNfg02KN2fbaX86xg==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f6108d8cc331900075e98e4",
    "LUEV8mJm+nqJCm8MvtSAaQ==": "http://pluto-live.plutotv.net/egress/chandler/pluto01/live/VIACBS02",
    "zFOe7GnEtpjpvllHhDt5Iw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d3609cd6a6c78d7672f2a81",
    "5+1+k/FmbPJDNsj5NFqcpw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ca6899a37b88b269472ea4b",
    "H5lRfUtiEhFk26VwLuPVSw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f1aadf373bed3000794d1d7",
    "8RIJIWDHpEwHenE0tr0HqQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f9847fd513250000728a9a5",
    "iYfiyjsW0CfSM0uO8eusqA==": "http://pluto-live.plutotv.net/egress/chandler/pluto01/live/VIACBS07",
    "/GFYYXVQC6D8NYGjdEzpbQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5cffcf5686dfe15595fb3f56",
    "NA8tnvWNX1kqrkKsyASP4g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d00e86bf0bac55fe7f75736",
    "8ugXi8F8vqJDQVkf5bLrhw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5caf32c2a5068259a32320fc",
    "8+/aLOPVoeLB3W7JxZm0Lg==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f98471110cca20007d39f76",
    "TOxXFvy2fLu/sFCRPrUv5Q==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5e8dc008d4422e00072d2405",
    "2uN/mN3mnvUTXqe8S3CKqQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5d2c571faeb3e2738ae27933",
    "eUNwSNEd802U6tr4hrU9NQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5bd833b41843b56328bac189",
    "qxPSyii2ttFwmJIR98LudQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5da0c85bd2c9c10009370984",
    "7lWOMfVvdH+juviod2h9Vw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5be1c3f9851dd5632e2c91b2",
    "hSstYz6HfXk3W6qMYIWDpA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5812bd9f249444e05d09cc4e",
    "1agivd+EFm9tIylbOv8ptQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5268abcd0ce20a8472000114",
    "GUyG4rmQbO9jq7TwRh/b1g==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ced7d5df64be98e07ed47b6",
    "k4y+d0qR3yNj/klbkFh9+w==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ede448d3d50590007a4419e",
    "SVhRMkT8ou6xSfdztD89yw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ede45451dce190007ef9ff2",
    "fwA+SyJnNRpufQFsk6zNsg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5aec96ec5126c2157123c657",
    "CRWg4WaJ2liAdQfKsH8F0g==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f7790b3ed0c88000720b241",
    "daZId2bF4X9/7CZjl0tqmg==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5ff8c708653d080007361b14",
    "ESk5wuMT52AJsoUleMmb0w==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5de94dacb394a300099fa22a",
    "H1JlQdRQYBfttxadBsauOQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5be1be871843b56328bc3ef1",
    "LO88oWHRXg+mt9NfKcOLEw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e82530945600e0007ca076c",
    "UW0HgQXJy4RqT63xcduXmg==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5e79c2f280389000077242a8",
    "Rt/Q7f9N/bLokUn5ZX80pw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f36f2346ede750007332d11",
    "H60fH9RTr+BauMbmwTfPhg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d8bf0b06d2d855ee15115e3",
    "Pvbfz6fWlxrHALf7uwZVrg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f21e831e9fe730007706acb",
    "yXnYaM5lrHmvEhMZ6DBLVg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e1c669094e0e80009b22ab8",
    "cGlpmQeGI42iiuNdfpAP0A==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/58d947b9e420d8656ee101ab",
    "YMB9BlTJGc5qhZDUY7FALQ==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d7677c0edace7cff8180b16",
    "4pTZGz/x+824PRcgn0stxQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5dbc327d0451770009ed7577",
    "qgVSTS2tnau1apytvGuoog==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5e8b5ba20af628000707cee3",
    "Wp1hmDELyZ53n6aGmc3nPQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/563a970aa1a1f7fe7c9daad7",
    "jUvIFFGjK3Cj8W+jtUGpUg==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5e8dc0af6784d10007d8ad42",
    "tVKkorp5/bI0iBGok5Nhqw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5e9ed47c26ebb000074af566",
    "dI3ltloGow9H/u1G3PNU7A==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f9853138d19af0007104a8d",
    "fJyyAeuKgTpSeUb86fwTow==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5dc2c00abfed110009d97243",
    "GRnvxQvzkxiY1iwN7kEOvw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f988934a507de00075d9ae7",
    "Ci+tQtz7q71RJ+hWedocfA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/6000a6f4c3f8550008fc9b91",
    "RnrAhXBIuXHSWq7S/4DBBQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e82547b6b3df60007fec2b5",
    "5YK2y4FYOf8kz0I41qp0AA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5317bfebff98025b3200ff99",
    "eZnM8rnx9vWFg3FmP4BpIA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f21ea08007a49000762d349",
    "fifFu3/A8IL0xKY+x6irQQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5dbc2f98777f2e0009934ae7",
    "Yzr+b8PiKu8CIinO4KBTYg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5c393cad2de254456f7ef8c2",
    "y2ZS/xmrZJhsbirKAoTvsg==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d7677fa2ec536ce1d587eeb",
    "6WAiJWFVKhOfQghcmXOTLA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ba3fb9c4b078e0f37ad34e8",
    "ghWRSO8Xq3YMxOol38B8+g==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f4d863b98b41000076cd061",
    "T7AvNTTXliHNggeSMooGsQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5637d31f319573e26b64040b",
    "guCEqwx2+CgnjXNarZWWuQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5efbd39f8c4ce900075d7698",
    "xrgOKaAl98eHaG50kvaU0g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e8254118601b80007b4b7ae",
    "u4dYUlnd04/TdhPSodpLDA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e1452156c07b50009d0230e",
    "LIMRv5voW0uznD+yqbkaRg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f21e7b24744c60007c1f6fc",
    "ft6eyjJbxOIS8XdzddTDyA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f15e281b0b8840007324b55",
    "cMyYqGXUjVXIThSx9M2zcg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5c6dc88fcd232425a6e0f06e",
    "DEevA/mir5E7yn0XDORoqA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5d81607ab737153ea3c1c80e",
    "qRGqbabeKQgkkzkyjSOIkg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f21e8a6e2f12b000755afdb",
    "3/VZkMKp4CNenjkAyZjGPQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d48685da7e9f476aa8a1888",
    "MNIijl5S71IWb/oUbWpg8A==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f4ff8c8bcf3d600078af3eb",
    "od6yX3SO+W0B1Vp4GlrdCw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f7794a788d29000079d2f07",
    "UIB2gyYzNz82/h8bmW52MA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f7791b8372da90007fd45e6",
    "ZWjAlV8TILDmJW/L/n40kQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e825550e758c700077b0aef",
    "aao+9cgpsvS5l5RsjwB8wQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5ea18f35ae8f730007465915",
    "MM/ekaPp6EfUcpPt+uSeLw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5f982c3420de4100070a545e",
    "0J6TogaUQaaBNxwEGjnYtQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d51e791b7dba3b2ae990ab2",
    "2G2DF49R5P0DuxVi+qZACQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ef3977e5d773400077de284",
    "2yQk4rewR3sqFnhECb3eJw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5b4e69e08291147bd04a9fd7",
    "Gb0q5bLb1EfKq+bBYGfeUA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/601a0342dcf4370007566891",
    "bNX+3cvHPYMyGPBkFWC4RQ==": "http://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5c3f8f12a93c2d61b9990a4e",
    "WUgTHEhVUFsGdZjRavS0bg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5dae084727c8af0009fe40a4",
    "X7kbQsQJBgQLjqgeWe8g0g==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d6792bd6be2998ad0ccce30",
    "eQW/409FKKVFpjsj6BY0Wg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/59c01b1953680139c6ae9d4d",
    "ULwkHaBspigxzzOwZ7Qtow==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5812be1c249444e05d09cc50",
    "PAv3EGluOa9uPNxpPBExzA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d40bebc5e3d2750a2239d7e",
    "QkFLDdMtrSAkOS9M4mTyQQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5c2d64ffbdf11b71587184b8",
    "maI5mDtuBFceaICkZezuyQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5db0ae5af8797b00095c0794",
    "zujgXZGN5LwbGJE3JxqH8g==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5331d5fb753499095a00045a",
    "erDIn91wcRwJWol26K/djQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5dc2a961bac1f70009ca7524",
    "r58sdD8NqT77Wqqt/WkESA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f0dc00b15eef10007726ef7",
    "XgKwBgAD0+q5FgK6qrCUVQ==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5b4e96a0423e067bd6df6901",
    "hor7aZbm3EpkMR0epgRUtA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5fd7bca3e0a4ee0007a38e8c",
    "u0o+3GDx0dxIL1GcFZQSpQ==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f32f26bcd8aea00071240e5",
    "r3VFyW6jUDq+HxtQ7jXT4A==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5fd7bb1f86d94a000796e2c2",
    "Q/nvnfUAV+ofUBXf7GKoHA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5da0d75e84830900098a1ea0",
    "GdjBcmS7xhW3TH+3MCRsCA==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5da0d83f66c9700009b96d0e",
    "Bk8b3tRU/G4yCin+7UZtKg==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5d71561df6f2e6d0b6493bf5",
    "Bz8Cg1hrMpJ/8tHln0IWvg==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5d7154fa8326b6ce4ec31f2e",
    "D3vyrBW6h2svA9w2b9AfeA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5bdce04659ee03633e758130",
    "zbYmdzeNI/Qi99lSZP65sA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5877acecb16bb1e042ee453f",
    "Agj7B9BL17n8wf76EqqcEw==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5e8df4bc16e34700077e77d3",
    "id9yOpMDZOPF69e6OX7qrA==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5d48678d34ceb37d3c458a55/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720/10&deviceVersion=unknown&embedPartner=samsung-tvplus&profileFloor=&profileLimit=&samsung_app_domain=https://play.google.com/store/apps",
    "/9nJA5TSutJpVNFBl8iUyA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5ed6828192e8b3000743ef61",
    "YS6ppVRv6zf6UfAya+IPJA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/6176fd25e83a5f0007a464c9",
    "moywwzWCA2IZeBSaa8nrIw==": "https://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5f4ec10ed9636f00089b8c89",
    "z7T1UfV80qis/jkfFf9aoA==": "https://vse2-eu-all59.secdn.net/barakyah-channel/live/plymouthtv",
    "Mefry8s7JtIlVXib45+Cag==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxpocketwatch/CDN",
    "5cOAdqC8A+X7lHm4UKqiiA==": "https://live-sonybebanjo.simplestreamcdn.com/live/popmax/bitrate1.isml",
    "bYf0Ag9nHyAEb/wxjAwrmw==": "http://n1.klowdtv.net/live2/pop_720p",
    "haoZetm2F2NUDQ4asb2lvg==": "https://linear-10.frequency.stream/dist/plex/10/hls/master",
    "3mILS6My0jD+AUw1GKTuFQ==": "https://tbn-jw.cdn.vustreams.com/live/positivtv/live.isml",
    "LzD8ofF3q/NXCR1VKSvXhA==": "https://reflect-broadcast-psdschools.cablecast.tv/live-6/live",
    "bLTeuhhORfbfx9IKEWFVlg==": "https://live2.tensila.com/1-1-1.power-tv/hls",
    "MjAL5fPJPNwIG8lvfAj6NQ==": "https://live1.presstv.ir/live/presstvfr",
    "th6R7ZOSuDYb1iYkXoKHAw==": "http://172.96.160.37:9138/stream/live",
    "196auOoAlk2qv4h+5nw2UQ==": "https://cmero-ott-live.ssl.cdn.cra.cz/channels/cme-ro-voyo-news",
    "ygjaKbApKzQcPuNf49fQIA==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/PTVPhilippines",
    "uH4ynewr1ByJ6kKg5aq7mQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/channel/UCj-e7yp2_-qE-TPritppZGQ",
    "h7+aN+i+1LphAv+bT+zh8g==": "http://cdn3.wowza.com/5/UWpORHhLSEs5SkJs/pueblo/G0822_002",
    "bdl9xGl5et8HkS11nlrXhQ==": "http://cdn9.live247stream.com/punjabitvcanada/tv",
    "ht9kq/b5v7HctneutRngdQ==": "https://pursuitup.samsung.wurl.com/manifest",
    "rJ75gYjVQdnAfTB/Po2FhQ==": "https://d2gjhy8g9ziabr.cloudfront.net/v1/master/3fec3e5cac39a52b2132f9c66c83dae043dc17d4/prod-samsungtvplus-stitched",
    "RIz8e6zaqeFOWfTr6gKXCw==": "https://player.qtv.gm/hls",
    "WV/byK8B7hiIEYZqFY+GQQ==": "https://dai.google.com/linear/hls/event/6ANW1HGeSTKzJlnAa9u1AQ",
    "uqmh07P0Czepp0ZGrlMqIQ==": "https://qvmstream.tulix.tv/720p/720p",
    "WlylreMSCJqIToV0Cjy1LQ==": "https://qvc.samsung.wurl.com/manifest",
    "DCWV9zV/N5T0o43fha96Ig==": "https://d2mn03dhv5o3g8.cloudfront.net/live/qvcde_beauty_clean/bitrate1.isml",
    "Er01vFbzcp9OF4bF4Nc83g==": "http://n1.klowdtv.net/live2/qvclive_720p",
    "/BE4BdEOUDu/ITF9BdK00g==": "https://d1txbbj1u9asam.cloudfront.net/live/qvcuk_main_clean/bitrate1.isml",
    "cgpLpmn1HXeSORhGAAEmgg==": "https://live-qvcuk.simplestreamcdn.com/hera/remote/qvcuk_primary_sdi1",
    "9R9JWa4nB8pwauUj8jcmMw==": "http://live.qvcuk.simplestreamcdn.com/live/qvcuk_beauty_clean/bitrate1.isml",
    "lFkPISvBbAhNlk/oJ68nPQ==": "https://live-qvcuk.simplestreamcdn.com/live/qvcuk_extra_clean/bitrate1.isml",
    "tvfClA4d/I/3oog1lrubOA==": "http://live.qvcuk.simplestreamcdn.com/live/qvcuk_style_clean/bitrate1.isml",
    "yPRGYsiqmaRmZlwJvUL6fQ==": "https://cdn-ue1-prod.tsv2.amagi.tv/linear/qwestAAAA-qwestclassic-uk-samsungtv",
    "eOQcccFFqFYv50EJQBcngw==": "https://cdn-ue1-prod.tsv2.amagi.tv/linear/qwestAAAA-qwestjazz-uk-samsungtv",
    "A8MxfwHRY9QO9lIOi+QMAA==": "https://cdn-ue1-prod.tsv2.amagi.tv/linear/qwestAAAA-qwestmix-uk-samsungtv",
    "RFm1j/nZVRsimb5gcWDs3g==": "https://nrpus.bozztv.com/36bay2/gusa-racecentral",
    "ZHgzWilvj8xbEdmbeL5vuQ==": "https://racingvic-i.akamaized.net/hls/live/598695/racingvic",
    "5YjdRZSS/cbPiFbfzsucGQ==": "https://cdnlive.radiou.com/LS-ATL-43240-1",
    "CsImceE4q9qrp2eyfEFeHA==": "https://lds-realfamilies-samsunguau.amagi.tv",
    "1X2aSclKiRxKTegWqDcSLQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxrealnosey/CDN",
    "Ow79Hp+TZFiBgR4wweeoiA==": "https://lds-realstories-samsungau.amagi.tv",
    "XZ0Y2QX1t3PYKq3/LzyycQ==": "https://realstories-samsung-uk.amagi.tv",
    "m6WPv5zGu8U7LH+HQwk+Vw==": "https://lds-realstories-plex.amagi.tv",
    "r68Wz6a2WD43tkkviGvDvg==": "https://a.jsrdn.com/broadcast/2a755012a8/+0000",
    "HzKaovtl63BiJodAlDXCUA==": "https://cs.ebmcdn.net/eastbay-live-hs-1/fcps/mp4:fcps",
    "1981x7cgJBtE/g1YSXCofw==": "https://rbmn-live.akamaized.net/hls/live/590964/BoRB-AT",
    "apDPDxLKx6ABndeObe97zA==": "https://spotlight-redbox.amagi.tv",
    "avdcrmh0uAm1PNPyZPoW/Q==": "https://comedy-redbox.amagi.tv",
    "X25nOolauK2/srRm14WRsA==": "https://rush-redbox.amagi.tv/hls/amagi_hls_data_redboxAAA-rush/CDN",
    "ggbWjGXkjAL9tIR74i1DMA==": "https://redseat-thefirst-klowdtv.amagi.tv",
    "71/6TDQyL5MODQ96+qp9Pw==": "https://bcovlive-a.akamaihd.net/c733a9aa448a4a44a10c527c6f5bf7a4/us-east-1/5245389775001",
    "YIJI5wnlVAl6uj7GzqUSsw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxreelzchannel/CDN",
    "kt0bwehBCyLAXaF5dyg85g==": "https://a.jsrdn.com/broadcast/76381deeda/+0000",
    "PP2i5FSly3sR6PMIO3GLeA==": "https://weblive.republicworld.com/liveorigin/republictv",
    "OPXSn1VtkZbHDR4mhpPbdg==": "https://59f1cbe63db89.streamlock.net:1443/retroplustv/_definst_/retroplustv",
    "652RdvzBuaZFqsib+mN+AQ==": "https://45034ce1cbb7489ab1499301f6274415.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Plex_RetroCrush/playlist.m3u8?ads.app_bundle=&ads.app_store_url=&ads.consent=0&ads.gdpr=0&ads.plex_id=5ef4e1b40d9ad000423c442a&ads.plex_token=z1MCPUpbxYcHru-5hdyq&ads.psid=&ads.targetopt=1&ads.ua=Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/84.0.4147.89+Safari/537.36+OPR",
    "nPTWibG8yVmO4o8R1g9P1Q==": "https://reuters-reutersnow-1.plex.wurl.com/manifest",
    "HElQ5LG8asWI0p83K3OtFw==": "https://rtv.cdn.mangomolo.com/rtv/smil:rtv.stream.smil",
    "4WuzSYfA4d4lFrXyyEe9tg==": "https://linear-5.frequency.stream/dist/plex/5/hls/master",
    "oPqE4hF2jGEmwIopCCBNZA==": "https://linear-44.frequency.stream/dist/plex/44/hls/master",
    "nPNRGUEQNXS0ugvowCwBYQ==": "https://4aafa23ec0a6477ca31466bd83a115a4.mediatailor.us-west-2.amazonaws.com/v1/master/ba62fe743df0fe93366eba3a257d792884136c7f/LINEAR-43-REVRY2-GALXY/mt/galxy/43/hls/master",
    "DuxkOy5CTwT6tck6fDFeXw==": "https://rialto-rialto-samsungaustralia.amagi.tv",
    "uG153fW5kdxFxwunSNWNxw==": "https://riflecmttv.secure.footprint.net/egress/bhandler/riflecmttv/streamb",
    "gNGlgfWcxYwUUO4ruWiQ5A==": "https://cdn3.wowza.com/5/RXJNMFI3VlVkOEFP/riversideca/G0879_001",
    "BrqGC32ooKAB98HyEbob1w==": "https://securestream3.champds.com/hlssstc/RockyHillCTLIVE",
    "zRdgF3GsIRh6V5NO6LNQCQ==": "https://d2klx6wjx7p5vm.cloudfront.net/Rooster-teeth/ngrp:Rooster-teeth_all",
    "WRjkZm/nYVo3Su+B1SiRHQ==": "https://rt-usa.rttv.com/live/rtusa",
    "0tpWkmE8Y2dYmLi+F1GckA==": "https://rt-rtd.rttv.com/live/rtdoc",
    "iuhKq0eqZmSIfT3OtG7cag==": "https://rt-glb.rttv.com/live/rtnews",
    "hGNYImsiIeJRFDW423lGpw==": "https://rt-uk.rttv.com/live/rtuk",
    "Nd/FVxf/nq5wZyJz6iXKZQ==": "https://d1211whpimeups.cloudfront.net/smil:rtb2",
    "peLRsBwY6IuozopDJyLQFA==": "https://d1211whpimeups.cloudfront.net/smil:rtbgo",
    "jXsaOIOir6XWhwJGQaDJ2g==": "https://live.rte.ie/live/a/channel3/news.isml",
    "4vP+lEXXElpKad9EwY7gZw==": "http://197.243.19.131:1935/rtv/rtv",
    "W6CmVxOEmwu1JoyMFF/Skg==": "https://ryanandfriends-samsungau.amagi.tv",
    "/Tdyy9u7Nt9rEUe+SgxvvA==": "https://live-uk.s4c-cdn.co.uk/out/v1/a0134f1fd5a2461b9422b574566d4442",
    "mrHNuY0Nc5I3RPQRGXp16w==": "http://18.191.91.130:1935/live/safetv",
    "rpsfM8PkQkRlTHAngGvZcA==": "https://zm6gdaxeyn93-hls-live.5centscdn.com/slworld/d65ce2bdd03471fde0a1dc5e01d793bb.sdp",
    "BwwQNZVveKhr2I+6xIjblg==": "https://vod.slocoe.org/live-3/live",
    "GvesAfmWls8MOsaxc8sjNA==": "https://vod.slocoe.org/live-4/live",
    "HUPy5iKH0WjU58QRnzQe5A==": "https://api.new.livestream.com/accounts/6986636/events/5362122",
    "JDKYO61ADskPK0YfSyNgmg==": "https://santamariactv.secure.footprint.net/egress/bhandler/santamariactv/streamc",
    "t0SOi0mMO8zjd6pzHRVvBg==": "https://santamariactv.secure.footprint.net/egress/bhandler/santamariactv/streama",
    "qZ7d7vQffu5+iwRiAVfObw==": "https://santamariactv.secure.footprint.net/egress/bhandler/santamariactv/streamb",
    "D3fph+lkivrJWXph/8x2rA==": "http://cdn3.wowza.com/5/bGZUOHp2TnhudnM2/santamonica/G0039_002",
    "qs/88AkozWZnljxla7JBlw==": "https://cdn3.wowza.com/5/WDIrTW5sM1JEY1NN/saratoga/G0135_002",
    "fIZrU5/v9X3OicOoUj5Mcg==": "https://dai.google.com/linear/hls/event/nPy2IRtvQTWudFfYwdBgsg",
    "3dFn6LzJP4Y9AzV9ii/IyA==": "https://tvsantacruz.secure.footprint.net/egress/bhandler/tvsantacruz/streamc",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "A3TlJbS+9aTRfUuv9I0Gzw==": "https://reflect-scvtv.cablecast.tv/live-2/live",
    "JumcDpUS7rW1DnXec2SxRA==": "https://cdn-telkomsel-01.akamaized.net/Content/DASH/Live/channel(9ce3f094-4044-467e-84b7-b684a49571d5)",
    "D84Si6aWlrIkjQzQbk8nAw==": "https://ampmedia.secure.footprint.net/egress/bhandler/ampmedia/streame",
    "LnyVmEnKnG8/XxqQAe4e+Q==": "https://rpn1.bozztv.com/36bay2/gusa-stgn",
    "S4Yebsi9/qBkW8WLlTWNlg==": "http://stgn-49.tulix.tv/live19/Stream1",
    "18e8LHSX6bvOatBeUDuBbQ==": "https://reflect-bayarea.cablecast.tv/live-5/live",
    "TMYMqaSaGC81ZmVnuXQCwg==": "https://reflect-bayarea.cablecast.tv/live-6/live",
    "xwdSmniDYpqSqisvGNZp6g==": "https://cdn3.wowza.com/5/V2Y2VmhqMEFDTUkx/sanfrancisco/G0051_008",
    "dmDpjJgowBKKjN0QrohOWw==": "https://cdn3.wowza.com/5/V2Y2VmhqMEFDTUkx/sanfrancisco/G0051_003",
    "viePllDax0MHlu8Nas1kQg==": "https://svs.itworkscdn.net/smc4sportslive/smc4.smil",
    "IY+QDMdISJin3098mDPYkw==": "http://tv.sheffieldlive.org/hls",
    "i8I9jduEavbpN5Sl5ehaEQ==": "https://aos01-evine.secure.footprint.net/evine/clean",
    "J/m+Bj6vnOaBSbFlmVgtEA==": "https://cdn-shop-lc-01.akamaized.net/Content/DASH_DASH/Live/channel(ott)",
    "2AA0WghWnYzTVsCCEZISOg==": "http://shoutfactory-redbox.amagi.tv",
    "cOZfWIGZ1mndAvCanKQOEQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxshowtimeattheapollo/CDN",
    "DWHqJM/q1uWipx2gEYRKTQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://dai.ly",
    "av0+4A7XOuwyTv1gFJEj0A==": "https://streamone.simpaisa.com:8443/pitvlive1/sindhnews.smil",
    "qUr39UR14GX5tx6L58/tvg==": "https://d2xeo83q8fcni6.cloudfront.net/v1/master/9d062541f2ff39b5c0f48b743c6411d25f62fc25/SkiTV-SynapseTV",
    "skQD62gOCUrJX5wRVHfcZw==": "https://stream-us-east-1.getpublica.com",
    "mNxE/lzfD2ryac0vE6ae6w==": "https://skynewsau-live.akamaized.net/hls/live/2002689/skynewsau-extra1",
    "YKYlhWXm6IBeKbDdJyVSwA==": "https://skynewsau-live.akamaized.net/hls/live/2002690/skynewsau-extra2",
    "ZDUWZ4hQUIaQfeKY7XtQwg==": "https://skynewsau-live.akamaized.net/hls/live/2002691/skynewsau-extra3",
    "EseSTDIUrozPvLpkeCfOjQ==": "https://stream.mux.com",
    "o0RQUsMzp2hUoTKA1DMwOA==": "https://agp-nimble.streamguys1.com/SLOC/SLOC",
    "7gAq12MZYmi/9LPvtgaMog==": "https://brightstar-sls.secure.footprint.net/egress/bhandler/brightstar/brightstarslshd",
    "QgXbSDXMFZL6Vt73kXNnAw==": "https://api.new.livestream.com/accounts/27460990/events/8266916",
    "rLSDMCuvMdYRldovgozzTg==": "https://smithsonianaus-samsungau.amagi.tv",
    "geaN/NrJGHkqHlCdKfKESg==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxsoyummy/CDN",
    "yDvJGyxVCmKK5XA1uNvQvg==": "https://dai.google.com/linear/hls/event/VMzvtHhOQdOAzbV_hQKQbQ",
    "Z9jTNydLczfqrRko+K8iXA==": "https://stream.y5.hu/stream/stream_sorozatp",
    "U3mDd4qenLrtdHWEfFrqCg==": "https://soundviewcmt.secure.footprint.net/egress/bhandler/soundviewcmt/streama",
    "iBFoPcrrDiBb8YmgxQ1ggg==": "https://sparktv-samsunguk.amagi.tv",
    "J/UktgWmnJY43yvhVP33iA==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5d8d11baeb31c5a43b77bf59/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720/10&deviceVersion=unknown&embedPartner=samsung-tvplus&profileFloor=&profileLimit=&samsung_app_domain=https://play.google.com/store/apps",
    "XXAgPCDGbaMBXZJW4z6J0Q==": "https://cdnlive.myspirit.tv/LS-ATL-43240-2",
    "Q8KQf82V4K4Z/eumTV7kzg==": "http://sports.ashttp9.visionip.tv/live/visiontvuk-sports-sportstonightlive-hsslive-25f-4x3-SD",
    "qx2c5ecKH4rMYCzjy+xb4Q==": "https://dai.google.com/linear/hls/event/9FKrAqCfRvGfn3tPbVFO-g",
    "EkRGRNqcqDWeTcZm8EKhPA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-xumosportsgrid/CDN",
    "+8IYJJIoPn6LtDA634CWyQ==": "https://a.jsrdn.com/broadcast/fabeab4b08/+0000",
    "BL5pBH1MjmdnkQxwtNWzlg==": "http://cdn.tvmatic.net",
    "oSbWxjAqy6EQaoft36f5QQ==": "https://dai.google.com/linear/hls/event/8R__yZf7SR6yMb-oTXgbEQ",
    "jKi+C0r2BElzLGMEZA40Iw==": "https://ayozat-live.secure2.footprint.net/egress/bhandler/ayozat/sportystufftv",
    "JQ9cTDsbZ+bCSvVv4rpCVA==": "https://cdn3.wowza.com/5/cFh0V0QwUVc4SDl2/coloradosprings/G1424_002",
    "bQtr+vRM7GCiQCxtvzQ//A==": "https://simultv.s.llnwi.net/n4s4/Spydar",
    "mpLZ2S9Ds0G0Nx8hvtiGUQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1234A-stadiumsports/CDN",
    "drGQtrsOXzn6D8EPJrNWKQ==": "https://16live00.akamaized.net/START_TV",
    "fDPGEnYSCmf27BT2qGUJnQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-viziostingrayambiance/CDN",
    "Ak5NPATSAs2XGLQL/qZjtw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxstingrayclassicrock/CDN",
    "qy0sxDE9QAtpb/qD7InVjw==": "https://ott-linear-channels.stingray.com/v1/master/734895816ccb1e836f8c1e81f772244d9be0077c/115",
    "JDXmbDQ1tMC4Ley53bnD8A==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxstingraygreatesthits/CDN",
    "2KKnHcFUQPB3I+IRM2LTeg==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxstingrayhitlist/CDN",
    "KCuJVHgdnmXNZWrmsuljfw==": "https://stirr.ott-channels.stingray.com/155",
    "s90namCBmGvF2Xzyq7rdKQ==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxstingrayhotcountry/CDN",
    "ur9dDZQV4q4kDigFEizB6g==": "https://dai.google.com/linear/hls/event/5bqbG8j7T_6_qMONC1SDsg",
    "uLvS1d5KGMlhyEjgB6Qtng==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxstingraynaturescape/CDN",
    "AMCKGjc4wdUVw2WXSHUDAA==": "https://dai.google.com/linear/hls/event/6RPZlzksTCyB1euPqLcBZQ",
    "lfOGpBgUMwe2Tolvj1Mp9g==": "https://ott-linear-channels.stingray.com/v1/master/734895816ccb1e836f8c1e81f772244d9be0077c/104",
    "YTKWiYmpTWOtUzn5mKJNuw==": "https://ott-linear-channels.stingray.com/v1/master/734895816ccb1e836f8c1e81f772244d9be0077c/102",
    "8h0lCkn9qRDXxZQ9eIjQJg==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxstingraysoulstorm/CDN",
    "jWjluRo1fOG4CxYmaVrIPQ==": "https://ott-linear-channels.stingray.com/v1/master/734895816ccb1e836f8c1e81f772244d9be0077c/190",
    "q+detUm+YRrmT699YGQjrA==": "https://ott-linear-channels.stingray.com/v1/master/734895816ccb1e836f8c1e81f772244d9be0077c/133",
    "vVIli/5kCqgr/HL9qiRPDg==": "https://dai.google.com/linear/hls/event/uxPBn5ErTQ-FOjxIYle2PA",
    "KjOlqRQr6x/Z7szP+/tbtg==": "https://dai.google.com/linear/hls/event/fD3VBzTxRXGz-v7HV0vryQ",
    "HAwEhUUcVx6JhQpGbKNLbA==": "https://dai.google.com/linear/hls/event/qvOGhZEeQh-s6TMFz7dVcg",
    "l8INsSw68irVhrgNXXQ7Gg==": "https://dai.google.com/linear/hls/event/zDh7VBx8S7Sog5vzcXuehg",
    "if9eJ1Jy7KFdiMEXjb62mg==": "https://dai.google.com/linear/hls/event/-4GLQIcZTUWzP8vDAXNQsQ",
    "whjjM3MGHmFHJ5I/UeVO4g==": "https://dai.google.com/linear/hls/event/jCNW8TtPRe6lnJMMVBZWVA",
    "X17z7Eyt4KFpUVNMhyq2uQ==": "https://dai.google.com/linear/hls/event/kJPGlFKuS0itUoW7TfuDYQ",
    "WGulvvs5Rm4wT7vON72S4w==": "https://dai.google.com/linear/hls/event/FKoa3RaEQxyyrf8PfPbgkg",
    "4jEZ21kDTjbpvn/qS8ZlQg==": "https://dai.google.com/linear/hls/event/tlvrrqidRaG0KbLN4Hd5mg",
    "FsHgQQHtk7NMt+JgotWP0Q==": "https://dai.google.com/linear/hls/event/4RH6FntvSLOIv5FB-p4I8w",
    "MhOGgPPIPmpKYlnXVlFrkw==": "https://dai.google.com/linear/hls/event/EXltT2IOQvCIn8v23_15ow",
    "8IjlVlsElPDqXXEhBPTAHQ==": "https://dai.google.com/linear/hls/event/do9arGJBTD--KARQ056kpw",
    "Is1J1Uyom0Yb5xvpIOflOg==": "https://dai.google.com/linear/hls/event/zPJC-rOUTg28uymLdmYw5w",
    "NHju18vrhzPhJ4xQ069zVQ==": "https://dai.google.com/linear/hls/event/YLDvM8DGQyqsYnDsgxOBPQ",
    "xLguSXJu4hQEC2fej5GWHQ==": "https://dai.google.com/linear/hls/event/kMNMCCQsQYyyk2n2h_4cNw",
    "kGZ/+bhyYUNd2NYZvyyAhA==": "https://dai.google.com/linear/hls/event/fLqJePs_QR-FRTttC8fMIA",
    "8jGfOHDCBCOVtiWlQKSQHQ==": "https://dai.google.com/linear/hls/event/7_v7qMjnQWGZShy2eOvR5g",
    "YYdD38rbBW68e5VtA0fA0g==": "https://dai.google.com/linear/hls/event/sHnor7AERX60rGA1kR_wPA",
    "7w+o1cvDljnzf4RlD9iFVA==": "https://dai.google.com/linear/hls/event/ZaLvGYKiTfuSYgJuBZD67Q",
    "lkvztG8fQ4Qs2iUzHZPzXA==": "https://dai.google.com/linear/hls/event/btXotLiMRvmsa5J5AetBGQ",
    "nSZNlxlBBr1zCMIjTB5qNg==": "https://dai.google.com/linear/hls/event/nqvIiznDQO60CBNaJ5mmdQ",
    "vA+1uK/TbXaRkTOLcjhXIw==": "https://dai.google.com/linear/hls/event/6Ll-qQyAQlWgCt4PhH11Kw",
    "Vzqs4REZaauw9gDjURgDJA==": "https://dai.google.com/linear/hls/event/tFAJ7xPcTYaLKwIfUA-JIw",
    "6ZWeu2Ojuq0FRGN4XUGOMg==": "https://dai.google.com/linear/hls/event/Ybz6nJKqSS2fcQYflsmpRw",
    "li7JxU2pVWlILWIkGwXeHQ==": "https://dai.google.com/linear/hls/event/leOKmL9fQ6eZyhdoROSh5Q",
    "Y9qwYEnc6fzVjzzHIORdxw==": "https://dai.google.com/linear/hls/event/a6lsWNYDQwyM9fjytUCrcw",
    "V/02B06biyi88gKtwvHiVw==": "https://dai.google.com/linear/hls/event/trvuY4TqQCmrAKFTlr6tPQ",
    "mOgXMtyPV++ckSAiw8W8Yg==": "https://dai.google.com/linear/hls/event/B6RsXGIZSVqeVZGZIEZESg",
    "j+t+Fjs1/zq6qyAZ/UeEuQ==": "https://dai.google.com/linear/hls/event/W_NyV_9eQ-qa0XDSMfYkEg",
    "33zBVXOZI4ZxIs/wJW3upw==": "https://dai.google.com/linear/hls/event/xtKyBDIFSZa6cT4Of9yaGQ",
    "LQuPPMDiWNL8QYyyU28kIg==": "https://dai.google.com/linear/hls/event/BXZlH0kXTeGczlQ49-0QFQ",
    "5sAV94HbLqFrfub5FHhPHQ==": "https://dai.google.com/linear/hls/event/yDGZP35hTsqdf2rwaP1BGQ",
    "5s8Whq1jJTBp/Jw/A4H6pw==": "https://dai.google.com/linear/hls/event/knBsxnquSYqFXTP_UzcGgw",
    "Y2iScQX9k6rkhX2ovrY/SQ==": "https://dai.google.com/linear/hls/event/MqeaRgFBR2WJ_40ngbDruQ",
    "2+Fc5ol7I+2EqUDflMiIJQ==": "https://dai.google.com/linear/hls/event/n3PVAFmPTJSVYjdSVf7XZw",
    "IdORVkk/vRtjKVNmI7bHFw==": "https://dai.google.com/linear/hls/event/Fwm4J95UQi67l2FEV7N5kQ",
    "NGDIKhgSOyIJRAW7xDr82Q==": "https://dai.google.com/linear/hls/event/PPMxI7GZSRG6Kgkp2gSF1g",
    "u0uLxG5d1eHWjUSkkrCmAQ==": "https://dai.google.com/linear/hls/event/1g9qH9IOSIGGwAqw8fPzmw",
    "VuJ63kkzxkGr6XFdm8C7MQ==": "https://dai.google.com/linear/hls/event/jWaxnXHPQjGX1yTxuFxpuw",
    "2qqfL/O8XyT3jEA4vF0IKQ==": "https://dai.google.com/linear/hls/event/0P8RZiJkSBWfVDtjy-IiIQ",
    "XCI3wjeWN9jfVrzxw1dwVA==": "https://dai.google.com/linear/hls/event/ARX9M-X8RieADdAEYPXNuA",
    "37/eaPndnVdr5S2EGrh3oQ==": "https://dai.google.com/linear/hls/event/IG9ThaPaTwCojeoEWVNZRQ",
    "K5jK5Cc832jfmgdsO870ug==": "https://dai.google.com/linear/hls/event/pRd-k6tZSiCRsw_f51Vcvg",
    "8pkwuHCwiRUgc3M02j6tJA==": "https://dai.google.com/linear/hls/event/jH-4z3EkQO-fLYYgjX7d3g",
    "aIffcvdwtVyljdLFLl+hIg==": "https://dai.google.com/linear/hls/event/CAU96LSyR_e7MSeK6UTmGQ",
    "IgPaYvJ0S9rWFT3kDsY8vw==": "https://dai.google.com/linear/hls/event/qJU_NkxXQoCbACvG5BWrXQ",
    "cp72JD+5P9BDHSgbMhmfKA==": "https://dai.google.com/linear/hls/event/npdISdLWSIa1E_j7NCUDBg",
    "rAYRCf/bfG2HQR1qgOfmEw==": "https://dai.google.com/linear/hls/event/5hLTCUyrQcS3B-NF8fNp-g",
    "1CMO6OJN0a7F/PMHWCQlDg==": "https://dai.google.com/linear/hls/event/bjWdbDzwTMOMd8Wmxl4rwg",
    "uRlqGAKmvZ73IdWzrq1Tiw==": "https://dai.google.com/linear/hls/event/86JIujPNRWiVvtfzksp8QQ",
    "lAaWq49wcTjCWBDqpy3muA==": "https://dai.google.com/linear/hls/event/0Zb5SSQcTme6P7FYwwAwcQ",
    "1yNP61QFXR7lSEEwcUXY9w==": "https://dai.google.com/linear/hls/event/FftwN8CLTnaX1pFHztXlYw",
    "H094N8Yhysnn1zCZehTPuw==": "https://dai.google.com/linear/hls/event/1bMiswhQQxqH-X8D3qbmKQ",
    "RsihQ2aUlhrJUx1nyXM7WQ==": "https://dai.google.com/linear/hls/event/TIQuLmldSj2SqS8y2ud9Xg",
    "Ewi0lUPA2whZEGMMJb2NMA==": "https://dai.google.com/linear/hls/event/VLEduzwwQfGSwV4eNdkj0g",
    "VQo+Mu8U+ghU66eRndPPwg==": "https://dai.google.com/linear/hls/event/0Uj4AmiOSw6oTX9ilyV2rQ",
    "mUa54V4mwKVH1tgq2fkPsQ==": "https://dai.google.com/linear/hls/event/VGpvNIxIQRO7PXYRy7P0qw",
    "eOZ74URjpCQkxqHOhkw6Sg==": "https://dai.google.com/linear/hls/event/O5W1HC47QEKGc5tyscvsLw",
    "aOPz43QvxueJkIMGI9CEbA==": "https://dai.google.com/linear/hls/event/HSX_ZpxDQNy5aXzJHjhGGQ",
    "j1XKGasTd4Q/PbH32KbiKQ==": "https://dai.google.com/linear/hls/event/1QSZA8OjS1y2Q64uTl5vWQ",
    "qZtF7hd72XkR8NQJPyJS0g==": "https://dai.google.com/linear/hls/event/KPOafkGTRle7jOcRb9_KFw",
    "OAx9JaNCUSi7PsU82E7jnQ==": "https://dai.google.com/linear/hls/event/5kbHZRGGS--RHp41xaUJHQ",
    "gnu1iPcejz+9Te7Ylj4lhw==": "https://dai.google.com/linear/hls/event/_VmeKujXTf-nc9Lr2NO6tA",
    "OvvMjY8e4CuKI9mhWytEHg==": "https://dai.google.com/linear/hls/event/ji4LMCwtRCOw3TrRUKlQMQ",
    "evuPRq2Wt9HATOS91JX5kQ==": "https://dai.google.com/linear/hls/event/dcaYfE2nRnqC6eAvCFWfzQ",
    "l2mQQtwBqicNyFNwKzqzsQ==": "https://dai.google.com/linear/hls/event/jlf2tRLPTg2xjMtKe5ey-w",
    "MIOhaj4zW2nuzDuXun3RxQ==": "https://dai.google.com/linear/hls/event/8JiQCLfVQw6d7uCYt0qDJg",
    "AJvyHMg2wrNlK01SN/yyig==": "https://dai.google.com/linear/hls/event/fAFfTnCAT2K8d83sYsA-cw",
    "NS+dQ6zIc4ML/nrtg80QsA==": "https://dai.google.com/linear/hls/event/f-zA7b21Squ7M1_sabGfjA",
    "/fmWH5rM1atvPW5jFDGfAA==": "https://dai.google.com/linear/hls/event/dKG_ZFd_S82FPgNxHmhdJw",
    "VGg8aqm6vI5merAHD2MzrA==": "https://dai.google.com/linear/hls/event/r9VoxPU7TYmpydEn2ZR0jA",
    "mD9MMPVeXngEdnq2DDFHCQ==": "https://dai.google.com/linear/hls/event/YF2jfXh_QROPxoHEwp1Abw",
    "TRsQpq1nRKTSOgvYAH/Bbg==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://livestream.com/accounts/19628359/events/7940975",
    "rCNFphlRIgvRq/bhGOvbYw==": "https://cdn3.wowza.com/5/dk84U1p2UUdoMGxT/stockton/G0044_008",
    "uXNau5be5Ppy9k138OcGwQ==": "https://csm-e-stv.tls1.yospace.com/csm/live",
    "uXNau5be5Ppy9k138OcGwQ==": "https://csm-e-stv.tls1.yospace.com/csm/live",
    "lQ22WrE91DKQp8o40CDgTQ==": "https://bcovlive-a.akamaihd.net/4d972ec6f41241f2b4286f8bdcc8dae9/us-east-1/6240731308001",
    "h9zAtF2wg28Jy6i54oBMJA==": "https://6305c8676ce84.streamlock.net/live/live",
    "X6mu4+rGS5htTrBmaHm6JQ==": "https://lbs-us1.suprememastertv.com",
    "0Ad8W8uUM2qCFToaqk7GGQ==": "https://stream.swamiji.tv/YogaIPTV/smil:YogaStream.smil",
    "iDtvPkjzoPFCHjKBCwLc/A==": "https://a.jsrdn.com/broadcast/9e63a1b236/+0000",
    "h0EuNT5tij9ds8JReAlqIg==": "http://trn03.tulix.tv/teleup-syfy",
    "th6R7ZOSuDYb1iYkXoKHAw==": "http://172.96.160.37:9138/stream/live",
    "EhkNhcpL8T47I3z6lLav0w==": "https://cdn-ue1-prod.tsv2.amagi.tv/linear/amg00738-newsuk-talkradiotv-ono",
    "i2A9dNYRULYMxEgi80j5yg==": "https://reflect-tampa-bay-community.cablecast.tv/live-16/live",
    "skQD62gOCUrJX5wRVHfcZw==": "https://stream-us-east-1.getpublica.com",
    "b/OJXCN4vdBwrypU1WkNtA==": "https://stitcheraws.unreel.me/wse-node02.powr.com/live/5af61f59d5eeee7af3d1db8f",
    "dE8zdaEPLt27m0WWdaBT2Q==": "https://tastemade-freetv16min-plex.amagi.tv/hls/amagi_hls_data_tastemade-tastemadefreetv16-plex/CDN",
    "d1bjljILhDlsyesm8Dpk8w==": "https://tastemadeintaus-smindia.amagi.tv",
    "7gMhwSWJeOoJxbIPq7DOWQ==": "https://tastemadetravel-vizio.amagi.tv",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "b4gr0LpAIdbfCXMy9MPumQ==": "http://210.210.155.37/qwr9ew/s/s39",
    "pMmNzPgH6wXr8lj8ttTcnQ==": "https://api.new.livestream.com/accounts/27460990/events/8266909",
    "eMIU6uEnuHKtAXEvN8LmVg==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://api.new.livestream.com/accounts/28567990/events",
    "TT2vKK+frKrC70FY4VlA1w==": "https://api.new.livestream.com/accounts/27460990/events/8266920",
    "CWlWxUAGdvWUZiQmj2HPPg==": "http://62.32.67.187:1935/WEB_Ukraine24/Ukraine24.stream",
    "1m1eb+VSWH3Tuurd54wReg==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023172/tbseast/slate",
    "SNbn4BLFVB+tFmKjR7QwUw==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023174/tbswest/slate",
    "e6wUTj7CgTMe9CKmLEibbA==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023186/tcmeast/noslate",
    "5orMVjYjtaQbQCbc7c+dmw==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023187/tcmwest/noslate",
    "xUCAVajMFJ8wBn9J4M7phA==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://api.new.livestream.com/accounts/29565692/events/9276365",
    "hWC/92syzUd4k3yD8pp/Zw==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://api.new.livestream.com/accounts/29565692/events",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "Cga+4b6R9XcY4WoSbXIeow==": "https://livefta.malimarcdn.com/ftaedge00/teatv2.sdp",
    "/KN7tCUfECHAwRhaoUDRhg==": "https://cdn-telkomsel-01.akamaized.net/Content/HLS/Live/channel(abe4ead2-1a88-4330-9f41-382fcf94bba2)",
    "MJDk/Cd/LqDAl+jcKpK3Fw==": "https://eu-nl-012.worldcast.tv/dancetelevisionthree",
    "lrs1EhvvaiRY/vM56rFd9Q==": "https://cdn.appv.jagobd.com:444/c3VydmVyX8RpbEU9Mi8xNy8yMDE0GIDU6RgzQ6NTAgdEoaeFzbF92YWxIZTO0U0ezN1IzMyfvcGVMZEJCTEFWeVN3PTOmdFsaWRtaW51aiPhnPTI/tehelkatv.stream",
    "lXw4JoHMb1DzwNNmwA/5Ag==": "http://cdn.setar.aw:1935/Telearuba/smil:telearuba.smil",
    "Yw+wWlH3dDnMXleHtcU9fg==": "http://ott.streann.com:8080/loadbalancer/services/public/channels/5ed71e232cdc24a3d08cd6de",
    "8WK6c8d1SQG2i8W0qqHo/w==": "https://univision-live.cdn.vustreams.com/live/ce88b839-6376-4494-a2ee-83d66bc7cfc1/live.isml",
    "mTUti99nC3VZvYnWpz7VZg==": "https://github.com/LaneSh4d0w/IPTV_Exception/raw/master/channels/ve",
    "ZUPr2hnTrpbW8odbiKPGhg==": "https://8f720e1353ce43b8babcd780fe178755.mediatailor.us-east-1.amazonaws.com/v1/master/44f73ba4d03e9607dcd9bebdcb8494d86964f1d8/Samsung-gb_WildBrainPresentsTeletubbies",
    "44cxP6cofGg7i5gXUYIRZg==": "https://reflect-temecula.cablecast.tv/live-2/live",
    "jUiO1+REICNMtRhk9vTO0w==": "https://cdn3.wowza.com/5/cFh0V0QwUVc4SDl2/tempe/G0355_003",
    "1134x7nQsPfLhCr7ofPbRg==": "https://tennischannel-int-samsunguk.amagi.tv",
    "skQD62gOCUrJX5wRVHfcZw==": "https://stream-us-east-1.getpublica.com",
    "oF0r8QZVV9ZfiHgPxvL31A==": "https://ov.ottera.tv/live",
    "gLt9iPoNoYHlQCCQ8oebnA==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5cc81e793798650e4f7d9fd3",
    "11HvsltUhM8WhiZ4n6bvfw==": "https://d46c0ebf9ef94053848fdd7b1f2f6b90.mediatailor.eu-central-1.amazonaws.com/v1/master/81bfcafb76f9c947b24574657a9ce7fe14ad75c0/live-prod/14c063cc-8be5-11eb-a7de-bacfe1f83627/0",
    "XgVOjWQEHg8xPZqKJL8Z4A==": "https://bobross-xumous-ingest.cinedigm.com",
    "kUX10j3EHVECqo6/4+oiZg==": "https://csm-e-boxplus.tls1.yospace.com/csm/extlive/boxplus01,thebox-alldev.m3u8?yo.up=http://boxtv-origin-elb.cds1.yospace.com/uploads/thebox",
    "6XyzvQB8tBLaHGSGpPdbOA==": "https://carolburnett-roku.amagi.tv",
    "DdtggaYn/kfpV27H7SWbpw==": "https://cdn.appv.jagobd.com:444/c3VydmVyX8RpbEU9Mi8xNy8yMDE0GIDU6RgzQ6NTAgdEoaeFzbF92YWxIZTO0U0ezN1IzMyfvcGVMZEJCTEFWeVN3PTOmdFsaWRtaW51aiPhnPTI/thechanneltv.stream",
    "oCrCjU/4kfKUz/CgmnN/BA==": "https://endpnt.com/hls/tcn4k",
    "XJjghOgTJkiim9dTri2YAw==": "https://studio71-craftistry-roku.amagi.tv",
    "lG7M1/Fvlgzdd1Qt6ETReQ==": "https://16live00.akamaized.net/CW",
    "tK8Pa9risb0zJY+EHUp54Q==": "http://trn03.tulix.tv/teleup-cw-whp",
    "LrwGC0J0q+e7vvsOOrX85w==": "https://5e6cea03e25b6.streamlock.net/live/WTLHCW.stream",
    "t0COyzw0l/pOg6e+Lhzc7Q==": "https://livestreamdirect-edgetv.mediaworks.nz",
    "7MRfKWYzvuQiqUgl2p3C9w==": "https://dai.google.com/linear/hls/event/OYH9J7rZSK2fabKXWAYcfA",
    "RDMyFU78xOJqWl2s5D6Vpg==": "https://dai.google.com/linear/hls/event/nX39-giHRPuKQiVAhua0Kg",
    "ND8FJu0j80qUQ1eTfOiyBQ==": "https://bcovlive-a.akamaihd.net/1ad942d15d9643bea6d199b729e79e48/us-east-1/6183977686001",
    "/3OFCUQct2nIyMw81vePXA==": "http://daruttarbiyah.srfms.com:1935/daruttarbiyah/livestream",
    "skQD62gOCUrJX5wRVHfcZw==": "https://stream-us-east-1.getpublica.com",
    "aO1Nio6truhiz0iYEYZ63A==": "http://service-stitcher.clusters.pluto.tv/v1/stitch/embed/hls/channel/5aea40b35126c2157123aa64/master.m3u8?advertisingId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&appVersion=unknown&deviceDNT=0&deviceId=91a6ae51-6f9d-4fbb-adb0-bdfffa44693e&deviceLat=0&deviceLon=0&deviceMake=samsung&deviceModel=samsung&deviceType=samsung-tvplus&deviceUA=samsung/SM-T720/10&deviceVersion=unknown&embedPartner=samsung-tvplus&profileFloor=&profileLimit=&samsung_app_domain=https://play.google.com/store/apps",
    "T4mUtCVRRA6MMA6N9Ycz4w==": "https://link.frontlayer.com/services/hls2/fl619843",
    "JM6GXD2fCxDiin+bjvudjw==": "https://cloud.streamcomedia.com/parliamentarychannel/smil:parliamentarychannel_streams.smil",
    "ujTO1LFh53bR5IUonwe/1A==": "https://service-stitcher.clusters.pluto.tv/stitch/hls/channel/5bb1ad55268cae539bcedb08",
    "nDw41NunFd9boBJ++9ys0Q==": "https://5fd5567570c0e.streamlock.net/theretrochannel/stream",
    "6l0KyyOMNcWTQTxnRBmIgg==": "http://147.174.13.196/live/WIFI-1296k-540p",
    "XoERF7uUGklVxyGxNOY9rw==": "https://dai.google.com/linear/hls/event/v51OvZmXQOizl-KOgpXw1Q",
    "Nc6NdMIHi8Y1cwFZEavOyA==": "https://a.jsrdn.com/broadcast/e6bdcb5ae9/+0000",
    "Qo/RK5xOHz4U1G0nrSKqWQ==": "https://d155hi8td9k2ns.cloudfront.net/out/wapo-medialive3-rtmp",
    "qBMHFDgBmNFRiutOcDSmew==": "http://168.138.70.50:5080/channel/n104f84b1",
    "dGt83z61go5wyDKSSLF07w==": "https://tyt-xumo-us.amagi.tv/hls/amagi_hls_data_tytnetwor-tyt-xumo/CDN",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "HRRE3PCorYd4dFnk9i+QOg==": "https://cdn.igocast.com/channel11_hls",
    "apamHHyqfttv3yCbDSUZxw==": "https://reflect-thornton.cablecast.tv/live-4/live",
    "OmxbhYYp7XKi+yQ8d1N03g==": "https://livestreamdirect-three.mediaworks.nz",
    "JMic4obr3k/TKtbv3QAEeQ==": "https://3abn-live.akamaized.net/hls/live/2010543/3ABN",
    "ITZ54bhacykdOOy12bercg==": "https://3abn-live.akamaized.net/hls/live/2010544/International",
    "wPZJYk9frl26BUlJr9t+jw==": "https://3abn-live.akamaized.net/hls/live/2010550/Kids",
    "NpZW09x7/bvEOM/rvCVOig==": "https://3abn-live.akamaized.net/hls/live/2010551/Praise_Him",
    "Q++ftuXMMx2B+ITdBq1KXQ==": "http://210.210.155.37/qwr9ew/s/s34",
    "LgJHX54Cj6t2JYZe74zfzg==": "https://timeline-samsung-uk.amagi.tv",
    "uutO8BHj1SmFFChuR5jMfA==": "https://lds-timeline-samsungau.amagi.tv",
    "7dyjJCDkVloe1dBu6j4j1g==": "https://lds-timeline-plex.amagi.tv",
    "dV2wHIUqATDL4l25SpPKHQ==": "https://timesnow-lh.akamaihd.net/i/TNHD_1@129288",
    "jycyjBNGj/URGeSwrVqh5A==": "https://cdn-shop-lc-01.akamaized.net/Content/HLS_HLS/Live/channel(TJCOTT)",
    "Q9tlKmlqkWG6XnHZKWpjLg==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxtmz/CDN",
    "s/2l1qoeu++xlwkkcu8xCg==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023168/tnteast/slate",
    "a7Vj6RAHMnbLT0g2nsWmfw==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023170/tntwest/slate",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "PJDo1T/j1huKY/Bp+DVA1A==": "https://tscamd.akamaized.net/hls/live/503340/TSCLive",
    "QyHdLZoZfj4EwZFQAHrPxw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxtoongoggles/CDN",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "5kDBW7vG0V21ys+v+I9QXg==": "http://toronto3.live247stream.com/toronto360/tv",
    "sE2zQCfkNDB6ybb7ZFK2Cg==": "https://cdn3.wowza.com/5/dk84U1p2UUdoMGxT/torrance/G0057_005",
    "FNVGG4Xh0Dlj25XWGz6KPQ==": "http://185.234.217.27:8002/play/a02f",
    "b0E2AisnEfZpVe8z/MTaWA==": "http://tracesportstars-samsunges.amagi.tv/hls/amagi_hls_data_samsunguk-tracesport-samsungspain/CDN",
    "+wx3EE9gDY6cP5Q0AYCmbw==": "https://lightning-traceurban-samsungau.amagi.tv",
    "hGo++CTxUejgkZcGGgIDGA==": "https://cdn3.wowza.com/5/M0lyamVmM2JWcjhQ/tracy-ca/G0950_002",
    "wKl3YUyySzvs/R2jSfdo+Q==": "https://nrpus.bozztv.com/36bay2/gusa-moviemagictv",
    "bRR1gnW9OZDZou76tS7kUg==": "https://travelxp-travelxp-1-eu.rakuten.wurl.tv",
    "LHbhU8A5Ywk1NzGWLyxMiA==": "https://reflect-tacm.cablecast.tv/live-3/live",
    "39IXYycn1Sn4FLNFkqosFA==": "http://rtmp1.abnsat.com/hls",
    "7GF94qGWs0HSrxIzyotdZg==": "https://tv-trtbelgesel.medya.trt.com.tr",
    "t97JqpNyaK/GNWQZNrMZcw==": "https://tv-trtworld.live.trt.com.tr",
    "8ltGuPlXruZUZX9x/5i21g==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/channel/UCTlqstA2Wrt4fimd_VWKr8g",
    "1RMyenZGgSwaHSs6phs0eQ==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023176/trueast/slate",
    "kjeJpjV+2dUkGP1sjwYvvQ==": "https://tve-live-lln.warnermediacdn.com/hls/live/2023178/truwest/slate",
    "x1+35F4ptHFte7+E9DUa0Q==": "http://tstv-stream.tsm.utexas.edu/hls/livestream_hi",
    "b3+kMJAR2KdqvFXhMWFTEQ==": "https://alpha.tv.online.tm/hls",
    "b3+kMJAR2KdqvFXhMWFTEQ==": "https://alpha.tv.online.tm/hls",
    "JOBbQDl9rMYuXh3OoZt4LQ==": "http://rtmp.smartstream.video:1935/capco/tv29",
    "3w//XlTAhSwH27BAGuA0GQ==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.twitch.tv/tv47kenya",
    "9gv2Zn3UEx6//3fQOKp35Q==": "https://okkotv-live.cdnvideo.ru/channel",
    "7GU2JrrXX37gzgU9hY2llQ==": "https://brics.bonus-tv.ru/cdn/brics/english",
    "MPMGgpUlCZU6BvONldicRw==": "https://59f1cbe63db89.streamlock.net:1443/teste01/_definst_/teste01",
    "kWx6OI6BqkVUOqf/lCA2qw==": "https://tvce.gridpapaservers.com/TVCSEPT/ngrp:myStream_all",
    "Bo/jWfLt77DOtezNkOVZjA==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/c/tvcnewsnigeria",
    "QDv7i3S3c+GVsbVPTHOtEQ==": "http://210.210.155.37/dr9445/h/h20",
    "iPWuxHJFpck7WwbKFqlU+Q==": "https://d2ce82tpc3p734.cloudfront.net/v1/master/b1f4432f8f95be9e629d97baabfed15b8cacd1f8/TVNZ_1",
    "I7FuWvF8crw8LnzFPLjwzQ==": "https://duoak7vltfob0.cloudfront.net/v1/master/b1f4432f8f95be9e629d97baabfed15b8cacd1f8/TVNZ_2",
    "F2YfUwyUl4VoINa+OFw8ig==": "https://dayqb844napyo.cloudfront.net/v1/master/b1f4432f8f95be9e629d97baabfed15b8cacd1f8/TVNZ_Duke",
    "h2ulP37YyxkFETw8rUuAyw==": "http://118.97.50.107/Content/HLS/Live/Channel(TVRI3)",
    "ymP6A7faoZlPfKOlGyYzJg==": "https://rpn1.bozztv.com/36bay2/gusa-tvsboxing",
    "ruBgziIvp3UYaZaz1XCa7w==": "https://rpn1.bozztv.com/36bay2/gusa-tvsmystery",
    "Pe58o0W0pbhM9gE5i9qi6g==": "https://rpn1.bozztv.com/36bay2/gusa-tvsclassicmovies",
    "ShAnNtyJkwl4appqCPrHOQ==": "http://rpn1.bozztv.com/36bay2/gusa-tvs",
    "wVE85wEnZAjRaogDPjAv7w==": "https://rpn1.bozztv.com/36bay2/gusa-comedyclassics",
    "Pm7DX+pWvm/57ACXUHJeuw==": "https://rpn1.bozztv.com/36bay2/gusa-tvsdriveinmovie",
    "lKLkxxGMnR2Fqmw6Z1QcXA==": "https://rpn1.bozztv.com/36bay2/gusa-TVSFamilyChannel",
    "FStHYkpRwpEY5IWPMuizYg==": "https://rpn1.bozztv.com/36bay2/gusa-TVSFilmNoir",
    "ckF1d3y6Iimm7yqZYcZHoQ==": "https://rpn1.bozztv.com/36bay2/gusa-tvsfrontpagedetective",
    "4u+MPCtyPtWGWKCepKR/Xw==": "https://rpn1.bozztv.com/36bay2/gusa-hitops",
    "MefqWbE0pUMY7y19dIOigA==": "https://rpn1.bozztv.com/36bay2/gusa-tvshollywoohistory",
    "VyiYeeGczNc6TGmlSw8ETg==": "https://rpn1.bozztv.com/36bay2/gusa-tvshorror",
    "Fcr1xAiZ16BHGxfTbCowng==": "https://rpn1.bozztv.com/36bay2/gusa-TVSInspirationalNetwork",
    "+5wrHFMXcRxn2gEfpixLAA==": "https://rpn1.bozztv.com/36bay2/gusa-tvsmainst",
    "d34hgCA/pE9GSlZtR7JoPg==": "https://rpn1.bozztv.com/36bay2/gusa-tvsmusic",
    "b+7gRylDNXsBqd2ojNGdAA==": "https://rpn1.bozztv.com/36bay2/gusa-nostalgia",
    "d+HaY7jg4f02fdU6SuegSw==": "https://rpn1.bozztv.com/36bay2/gusa-tvsNostalgiaMovies",
    "z9ebV2WJTpWPYD6jH2f2uA==": "https://rpn1.bozztv.com/36bay2/gusa-petparadenetwork",
    "D7gQlY6zmMn/ET6Lm8nXIw==": "https://rpn1.bozztv.com/36bay2/gusa-TVSCartoonNetwork",
    "QRxMhkuMczZ4WsCyNYQp+g==": "https://rpn1.bozztv.com/36bay2/gusa-tvsgameshow",
    "uBYibTunWngz+Mvi+CvHRA==": "https://rpn1.bozztv.com/36bay2/gusa-tvsrarecollectibles",
    "XOCVZsqmCoqRLmYZShmnQA==": "https://rpn1.bozztv.com/36bay2/gusa-tvsselect",
    "YpA5TIxBVJcQy85yK57ung==": "https://rpn1.bozztv.com/36bay2/gusa-tvssilodiscount",
    "dqVtHq2bLvOYHysWCgcGCw==": "https://rpn1.bozztv.com/36bay2/gusa-tvssports",
    "8jeYJe/D9UfjzPN4vWFwLw==": "https://rpn1.bozztv.com/36bay2/gusa-tvssportsbureau",
    "kVFNt7b0m9NXI31NuhEYJA==": "https://rpn1.bozztv.com/36bay2/gusa-tvstallyho",
    "BGm18qMHCsc4WWtoo1fQBA==": "https://rpn1.bozztv.com/36bay2/gusa-tavern",
    "/ejVlAXxfLbm4xhGdyBxkA==": "https://rpn1.bozztv.com/36bay2/gusa-tvstn",
    "BgUolBYM7MoOqcbpb8xLBA==": "https://rpn1.bozztv.com/36bay2/gusa-TVSTodayHomeEntertainment",
    "Do0vdxsDdoorm5gW3vUALg==": "https://rpn1.bozztv.com/36bay2/gusa-tvstravel",
    "kQ0M/gQQ4XKROjZYzSvBZw==": "https://rpn1.bozztv.com/36bay2/gusa-tvsturbo",
    "YJ0nOkSF5KN7OHD/h2rM3g==": "https://rpn1.bozztv.com/36bay2/gusa-tvswesternmovies",
    "0NYH9vjX3gbVx+AWMxRRWg==": "https://rpn1.bozztv.com/36bay2/gusa-tvswsn",
    "ibFcByhBx6ZOe1zNLpAF7A==": "https://tvsnhlslivetest.akamaized.net/hls/live/2034711/TVSN-MSL4",
    "3q41tqc0iaxIMNTwWW8WMA==": "https://54627d4fc5996.streamlock.net/tzik/tzik",
    "8tGH0hrmODDBXmiXN/+/dA==": "https://vblive-c.viebit.com/65ea794b-dd82-41ce-8e98-a9177289a063",
    "2x0KbBOM9aVsZTV4pV3MGQ==": "https://59e8e1c60a2b2.streamlock.net/509/509.stream",
    "V0abrzOtmdDRHmnDYQ208w==": "https://cdnapi.kaltura.com/p/2503451/sp/250345100/playManifest/entryId/1_gb6tjmle/protocol/https/format/applehttp",
    "6jt17vfRkxa1bXAlPriM6A==": "https://unbeaten-roku.amagi.tv",
    "RLwNyw4F+dU6Vo8DiKqhOQ==": "https://unidfp-nlds164.global.ssl.fastly.net/nlds/univisionnow/unimas_east2/as/live",
    "ISEW61NG3chMXX61TnUO8w==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://www.youtube.com/channel/UCy_G4ljF7HkUtSx_YMnf_Wg",
    "y3grMjw+ot721mkM5EN2/w==": "https://unidfp-nlds155.global.ssl.fastly.net/nlds/univisionnow/univision_east2/as/live",
    "xH3q5tUfAfK8cPMpnt0dfQ==": "https://cdn.untvweb.com/live-stream",
    "u1/zQh3A/GonTxsLbTkngw==": "https://dai.google.com/linear/hls/event/gJJhuFTCRo-HAHYsffb3Xg",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "tnED3vQSXznmS/WUFR/oDQ==": "http://dee7mwgg9dzvl.cloudfront.net/hls/uvagut",
    "1B7GZk8ec/IMn+0y9dZfvQ==": "https://abr.de1se01.v2beat.live",
    "bkWyQnHU8EfdJ+DsjsPNSw==": "https://cdn3.wowza.com/5/RXJNMFI3VlVkOEFP/vacaville/G0228_002",
    "EUfQuYrf7IZxS57W76bdNQ==": "https://vallejo.cablecast.tv/live-3/live",
    "2vMfjwjqpT4npaeqTnzYPg==": "https://reflect-vsctv.cablecast.tv/live-3/live",
    "0+9F7NJZ5p5J0rrCf287EA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxvanityfair/CDN",
    "i7r6NG2RrAhEp2pzUNW4PQ==": "https://d39v9xz8f7n8tk.cloudfront.net/hls/clr4ctv_vsnthm",
    "IJ5X8D5j42NHzgrhSZP8ew==": "http://free.fullspeed.tv/iptv-query?streaming-ip=https://livestream.com/accounts/30337923/events/9488449",
    "FbJcx7Zff+o9CSu03cIrtw==": "https://venntv-samsungau.amagi.tv",
    "NgLziQBwyzBgENDnRgNpvQ==": "https://d80z5qf1qyhbf.cloudfront.net",
    "igmXKvuebqgbdO/ItoYNfw==": "https://csm-e-eb.csm.tubi.video/csm/extlive",
    "4MUK2N0l+RL7iJlCkvCDrA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxvevo80s/CDN",
    "AzEryqNxoKuItDy9ITVV8w==": "https://5dcc6a54d90e8c5dc4345c16-s-4.ssai.zype.com/5dcc6a54d90e8c5dc4345c16-s-4",
    "Y9NHK9HFe6sjl7jEIhHAEw==": "https://5dcc6a9f1621dc5dd511ca14-s-5.ssai.zype.com/5dcc6a9f1621dc5dd511ca14-s-5",
    "A4USrf3DwAOWGSvyuMpNcQ==": "https://5f3491c50b093e00015a3c4c-samsung.eu.ssai.zype.com/5f3491c50b093e00015a3c4c_samsung_eu",
    "9gv2Zn3UEx6//3fQOKp35Q==": "https://okkotv-live.cdnvideo.ru/channel",
    "9gv2Zn3UEx6//3fQOKp35Q==": "https://okkotv-live.cdnvideo.ru/channel",
    "qmuVg8rnWi+kSsR5HVaXuA==": "https://d2do1g43aq7264.cloudfront.net",
    "LjezahVxbkUsJSQFbvDSmw==": "https://2-fss-1.streamhoster.com/pl_122/201794-1414514-1",
    "qwRSbwPhEsDCJoHLx1e7hg==": "http://184.173.179.163:1935/victorytelevisionnetwork/victorytelevisionnetwork",
    "dvUbvKoZKNZJQlDmYHyocw==": "http://50.7.220.74:8278/videolandsport",
    "eKwF7B3z+lUlonnQ88J9xQ==": "http://188.40.68.167/russia/vip_comedy",
    "VJ9uoGiQsYtJwWNCEevdXw==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxvogue/CDN",
    "ReAZ5WJG0mjvbX2Bjf4roA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxvoyager/CDN",
    "oxrpee4ycYGjH662uJqQTQ==": "https://stream.rcncdn.com/live",
    "biGM1b75wlQHJolUi+AMOA==": "https://api.new.livestream.com/accounts/15669040/events/4554297",
    "5Y/qr428UQF/GrynjDWB2g==": "https://vips-livecdn.fptplay.net/hda1/vtv1hd_vhls.smil",
    "ocvfmISTG8CeEfy1K14Tjg==": "https://vips-livecdn.fptplay.net/hda1/vtv6hd_vhls.smil",
    "DFeq07dgT0r7K7t3QdJfZA==": "https://stream.wairarapatv.co.nz/Broadband_High",
    "maPz9qmIVm5tR5SIFTQgQA==": "https://newproxy3.vidivu.tv/waptv",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "fz9sqkSBseOE6qhleqTAwQ==": "https://dai.google.com/linear/hls/event/im0MqOKRTHy9nVa1sirQSg",
    "fluLczKNDOth9+2HJfoVhQ==": "https://wazobia.live:8333/channel",
    "fluLczKNDOth9+2HJfoVhQ==": "https://wazobia.live:8333/channel",
    "fluLczKNDOth9+2HJfoVhQ==": "https://wazobia.live:8333/channel",
    "+zK/mqUmqze4uumzyPm8fQ==": "https://dai.google.com/linear/hls/event/HZ3JdLVcQ463l3b1BLXmmQ",
    "Kf+MA4zCt9rHJhu9ofxu5Q==": "https://dai.google.com/linear/hls/event/qLrnhs3RQUa2zMw9UBkroQ",
    "FJslzUMLmYoZrOeDceOuEg==": "https://worcester.vod.castus.tv/live",
    "XtT8c/Cs0/AMyr8kuwKgqw==": "https://wowzastream.westmancom.com/wcgtvlive/wcgtvPSA.stream",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "POvMySTFvszxLjicJ4oarw==": "https://player-api.new.livestream.com/accounts/27442514/events/8305246",
    "J6/8t2ML7zSR7+JKlJjDYA==": "http://dai.google.com/linear/hls/event/iVH_b5kWTteyRCy-YCoHOw",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "ancYC1yf+9EBk7Wp3y6D2Q==": "https://jukin-weatherspy-2-ca.samsung.wurl.com/manifest",
    "esRZfj2pillaCKq9EQdANA==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxweatherspy/CDN",
    "2A/kU7Vijkxl7e49+2eA1A==": "https://jukin-weatherspy-2-eu.rakuten.wurl.tv",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "8+aetTmj9OU7ntb4x69uUQ==": "https://cdn3.wowza.com/5/M0lyamVmM2JWcjhQ/weho/G0161_004",
    "tQJ3F6G1UxRo2b74PkXyEA==": "https://cdn3.wowza.com/5/cHYzekYzM2kvTVFH/westlakevillage/G0133_004",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "WHIe9yLIrl0GKPy9GOnlQw==": "https://unidfp-nlds154.global.ssl.fastly.net/nlds/univisionnow/univision_chi2/as/live",
    "GT45QGKBVjiDAVVW+pg82g==": "https://stream.swagit.com/live-edge/whiteplainsny/smil:std-4x3-1-b",
    "TAPCq3rGIBe8bwImYh2atQ==": "https://cdn-unified-hls.streamspot.com/ingest1/89cbf0c54c",
    "hU8UmlvSkDP+KLzfJHgbBg==": "https://frontdoor.wcat-tv.org:8787/live",
    "2WdWFlL0oWekYUVTkYvacg==": "https://edu-wcat.azureedge.net/live",
    "jEoL822Oj/y2w4zz2WTQ0w==": "https://frontdoor.wcat-tv.org:8686/live",
    "N4hLefilD/Dw7LpEiiVj8w==": "http://210.210.155.37/uq2663/h/h91",
    "0ebdu7dzV3fwy/TTtBkr9Q==": "https://dai2.xumo.com/amagi_hls_data_xumo1212A-redboxwired/CDN",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "3ePHaf4WQiI7NvRM8ucVRQ==": "https://edge-f.swagit.com/live/wilmingtonde/smil:std-4x3-1-a",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "vOlIafmV2MPFDhriEVJMuA==": "https://nbculocallive.akamaized.net/hls/live/2037499/puertorico/stream1",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "26g8riZJZK5xqCiUAn8PoA==": "http://wlngstudiowebcam.srfms.com:1935/wlngstudiowebcam/livestream",
    "IesloB707NBGTeYbNVf1DQ==": "https://content.uplynk.com/channel/ext/aac37e2c66614e699fb189ab391084ff",
    "5kXm5XvKVrmwzVQRu/uy2g==": "https://dai.google.com/linear/hls/event/ygKx2LkmRQCZ_orwBQhfFw",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "L7oJRPLLC0m+Rh7STvBU1Q==": "https://5a5c57d042315.streamlock.net/live11704001/ngrp:government_all",
    "96zY013Km/VYTCRZdarcFQ==": "https://lds-wonder-plex.amagi.tv",
    "89SWCz5DN4Fg9kXFrdg41A==": "https://wfcint.mediacdn.ru/cdn/wfcintweb",
    "2laK6pIlU8E710eXc1iPSA==": "https://597865f6e4114.streamlock.net/live/leseaorigin.stream",
    "+jDVJkwQ4kefQlOE/VmZHQ==": "https://d3w4n3hhseniak.cloudfront.net/v1/master/9d062541f2ff39b5c0f48b743c6411d25f62fc25/WPT-DistroTV",
    "QS76EljA7nEvnHPQoXQgzA==": "https://streams.helnix.com/autoHLS/ce3a40274f01c8fc",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "Q6GBpLm56Uk+E6LBWfqDjw==": "https://securestream3.champds.com/hlssstc/WestportCTLIVE",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "HjXHDnfhVxTVvHe8RgPTHw==": "https://live-news-manifest.tubi.video/live-news-manifest/csm/extlive",
    "D6F8t5R8dDpVXedWGYEEMw==": "https://content.uplynk.com/channel/ext/10b98e7c615f43a98b180d51797e74aa",
    "5+g9q6LjSAbpX3wIigGzHg==": "https://content.uplynk.com/channel/ext/f05837c508c44712aa7129d531f7dbe6",
    "HStntjnUMNnfXPBafmszjw==": "https://dai.google.com/linear/hls/event/7xSxXPG1RqKkNva1wIWlVw",
    "KU+UPnOyWXyCyOWL6pXKUg==": "https://content.uplynk.com/channel",
    "skQD62gOCUrJX5wRVHfcZw==": "https://stream-us-east-1.getpublica.com",
    "T30b7dnSblHmnbcGMo2SZQ==": "https://dai.google.com/linear/hls/event/A7CgcBYNTuKfvFvW8rmiJA",
    "VcIA7HB8hZuzWAsvcFksgA==": "https://dai.google.com/linear/hls/event/cJXgmHHTQIGMhSzDk7TBsA",
    "ewjoEa8ZVmcuJ+9TPxKfyw==": "https://simultv.s.llnwi.net/n4s4/xcorps",
    "SRKpPQdB1iuJ8U5mnJK4yg==": "http://xlpore-samsungus.amagi.tv",
    "ZlsRry7ZsqBan8APkO4txA==": "https://d46c0ebf9ef94053848fdd7b1f2f6b90.mediatailor.eu-central-1.amazonaws.com/v1/master/81bfcafb76f9c947b24574657a9ce7fe14ad75c0/live-prod/1ecb875d-8be7-11eb-a7de-bacfe1f83627/0",
    "aZVKtQw6oFWfaWUOWkry7A==": "https://d1ewctnvcwvvvu.cloudfront.net",
    "ZKv6jnBOc67IKgojPoBQhA==": "https://tvsantacruz.secure.footprint.net/egress/bhandler/tvsantacruz/streama",
    "ZhgSxzMO7Vr+cT4F4ryFFg==": "https://younghollywood-rakuten-samsung.amagi.tv",
    "mYoKXqxSlahDy7qTIikOPw==": "https://thegateway.app/YouToo/CueTones",
    "AL150IPsNZUfvOg46aHnxg==": "https://securestream6.champds.com/hlssstc/YumaCoAZLIVE",
    "CZfUv+VetfydnC7yQwyIGA==": "https://yuma-az.secure.footprint.net/egress/bhandler/yumaaz/streama",
    "L7/TzYlifQUCtQ1YkJui+g==": "https://yuma-az.secure.footprint.net/egress/bhandler/yumaaz/streamb",
    "7hpeYnGlYBKRjH4VA7rrlw==": "https://cloud.streamcomedia.com/znstv/smil:znstv_streams.smil",
    "mDVtvDDtHspEZXYLCkQzLA==": "https://amg01553-blueantmediaasi-zoomoonz-samsungnz-rdufn.amagi.tv/playlist/amg01553-blueantmediaasi-zoomoonz-samsungnz",
    "qqRha1+pui7UX7OwDtYfIQ==": "https://zoomoo-samsungau.amagi.tv",
    "Eu5tXAy7dx6HZV7Et9pUBg==": "https://sc.id-tv.kz",
    "Q7xU9oZ4g01WLg6/RGicHQ==": "http://62.32.67.187:1935/WEB_TBN/TBN.stream",
    "GUahU1xqN/oegZjkCXCdbA==": "http://185.97.150.19:8082",
    "Mjt4cNbQXzW9fhTHmLJVFg==": "http://www.rtvcdn.com.au:8082"
};

const cn_hostnames = [
    'weibo.com',                // Weibo - A popular social media platform
    'www.baidu.com',            // Baidu - The largest search engine in China
    'www.qq.com',               // QQ - A widely used instant messaging platform
    'www.taobao.com',           // Taobao - An e-commerce website owned by Alibaba Group
    'www.jd.com',               // JD.com - One of the largest online retailers in China
    'www.sina.com.cn',          // Sina - A Chinese online media company
    'www.sohu.com',             // Sohu - A Chinese internet service provider
    'www.tmall.com',            // Tmall - An online retail platform owned by Alibaba Group
    'www.163.com',              // NetEase Mail - One of the major email providers in China
    'www.zhihu.com',            // Zhihu - A popular question-and-answer website
    'www.youku.com',            // Youku - A Chinese video sharing platform
    'www.xinhuanet.com',        // Xinhua News Agency - Official news agency of China
    'www.douban.com',           // Douban - A Chinese social networking service
    'www.meituan.com',          // Meituan - A Chinese group buying website for local services
    'www.toutiao.com',          // Toutiao - A news and information content platform
    'www.ifeng.com',            // iFeng - A popular news website in China
    'www.autohome.com.cn',      // Autohome - A leading Chinese automobile online platform
    'www.360.cn',               // 360 - A Chinese internet security company
    'www.douyin.com',           // Douyin - A Chinese short video platform
    'www.kuaidi100.com',        // Kuaidi100 - A Chinese express delivery tracking service
    'www.wechat.com',           // WeChat - A popular messaging and social media app
    'www.csdn.net',             // CSDN - A Chinese technology community website
    'www.imgo.tv',              // ImgoTV - A Chinese live streaming platform
    'www.aliyun.com',           // Alibaba Cloud - A Chinese cloud computing company
    'www.eyny.com',             // Eyny - A Chinese multimedia resource-sharing website
    'www.mgtv.com',             // MGTV - A Chinese online video platform
    'www.xunlei.com',           // Xunlei - A Chinese download manager and torrent client
    'www.hao123.com',           // Hao123 - A Chinese web directory service
    'www.bilibili.com',         // Bilibili - A Chinese video sharing and streaming platform
    'www.youth.cn',             // Youth.cn - A China Youth Daily news portal
    'www.hupu.com',             // Hupu - A Chinese sports community and forum
    'www.youzu.com',            // Youzu Interactive - A Chinese game developer and publisher
    'www.panda.tv',             // Panda TV - A Chinese live streaming platform
    'www.tudou.com',            // Tudou - A Chinese video-sharing website
    'www.zol.com.cn',           // ZOL - A Chinese electronics and gadgets website
    'www.toutiao.io',           // Toutiao - A news and information app
    'www.tiktok.com',           // TikTok - A Chinese short-form video app
    'www.netease.com',          // NetEase - A Chinese internet technology company
    'www.cnki.net',             // CNKI - China National Knowledge Infrastructure, an information aggregator
    'www.zhibo8.cc',            // Zhibo8 - A website providing live sports streams
    'www.zhangzishi.cc',        // Zhangzishi - Personal website of Zhang Zishi, a public intellectual in China
    'www.xueqiu.com',           // Xueqiu - A Chinese online social platform for investors and traders
    'www.qqgongyi.com',         // QQ Gongyi - Tencent's charitable foundation platform
    'www.ximalaya.com',         // Ximalaya - A Chinese online audio platform
    'www.dianping.com',         // Dianping - A Chinese online platform for finding and reviewing local businesses
    'www.suning.com',           // Suning - A leading Chinese online retailer
    'www.zhaopin.com',          // Zhaopin - A Chinese job recruitment platform
    'www.jianshu.com',          // Jianshu - A Chinese online writing platform
    'www.mafengwo.cn',          // Mafengwo - A Chinese travel information sharing platform
    'www.51cto.com',            // 51CTO - A Chinese IT technical community website
    'www.qidian.com',           // Qidian - A Chinese web novel platform
    'www.ctrip.com',            // Ctrip - A Chinese travel services provider
    'www.pconline.com.cn',      // PConline - A Chinese technology news and review website
    'www.cnzz.com',             // CNZZ - A Chinese web analytics service provider
    'www.telegraph.co.uk',      // The Telegraph - A British newspaper website	
    'www.ynet.com',             // Ynet - A Chinese news portal
    'www.ted.com',              // TED - A platform for ideas worth spreading
    'www.renren.com',           // Renren - A Chinese social networking service
    'www.pptv.com',             // PPTV - A Chinese online video streaming platform
    'www.liepin.com',           // Liepin - A Chinese online recruitment website
    'www.881903.com',           // 881903 - A Hong Kong radio station website
    'www.aipai.com',            // Aipai - A Chinese online video sharing platform
    'www.ttpaihang.com',        // Ttpaihang - A Chinese celebrity popularity ranking website
    'www.quyaoya.com',          // Quyaoya - A Chinese online ticketing platform
    'www.91.com',               // 91.com - A Chinese software download website
    'www.dianyou.cn',           // Dianyou - A Chinese game information website
    'www.tmtpost.com',          // TMTPost - A Chinese technology media platform
    'www.douban.com',           // Douban - A Chinese social networking service
    'www.guancha.cn',           // Guancha - A Chinese news and commentary website
    'www.so.com',               // So.com - A Chinese search engine
    'www.58.com',               // 58.com - A Chinese classified advertising website
    'www.cnblogs.com',          // Cnblogs - A Chinese technology blog community
    'www.cntv.cn',              // CCTV - China Central Television official website
    'www.secoo.com',            // Secoo - A Chinese luxury e-commerce platform
];
