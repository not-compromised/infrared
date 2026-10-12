package infrared

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/haveachin/infrared/protocol"
	"github.com/haveachin/infrared/protocol/handshaking"
	"github.com/haveachin/infrared/protocol/status"
	"github.com/pires/go-proxyproto"
)

var serverDomain string = "infrared.gateway"

type testError struct {
	Error   error
	Message string
}

func gatewayPort(portEnd int) int {
	return 30000 + portEnd
}

func gatewayAddr(portEnd int) string {
	return portToAddr(gatewayPort(portEnd))
}

func serverPort(portEnd int) int {
	return 20000 + portEnd
}

func serverAddr(portEnd int) string {
	return portToAddr(serverPort(portEnd))
}

func dialerPort(portEnd int) int {
	return 10000 + portEnd
}

func portToAddr(port int) string {
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func routeVersionName(index int) string {
	return fmt.Sprintf("infrared.gateway-%d", index)
}

func getIpFromAddr(addr net.Addr) string {
	return strings.Split(addr.String(), ":")[0]
}

func proxyConfigWithPortEnd(portEnd int) *ProxyConfig {
	serverAddr := serverAddr(portEnd)
	gatewayAddr := gatewayAddr(portEnd)
	return createBasicProxyConfig(serverDomain, gatewayAddr, serverAddr)
}

func createBasicProxyConfig(serverDomain, gatewayAddr, serverAddr string) *ProxyConfig {
	return &ProxyConfig{
		DomainName: serverDomain,
		ListenTo:   gatewayAddr,
		ProxyTo:    serverAddr,
	}
}

func createProxyProtocolConfig(portEnd int, proxyproto bool) *ProxyConfig {
	config := proxyConfigWithPortEnd(portEnd)
	config.ProxyProtocol = proxyproto
	return config
}

func statusHandshakePort(portEnd int) protocol.Packet {
	gatewayPort := gatewayPort(portEnd)
	return serverHandshake(serverDomain, gatewayPort)
}

func serverHandshake(domain string, port int) protocol.Packet {
	hs := handshaking.ServerBoundHandshake{
		ProtocolVersion: 574,
		ServerAddress:   protocol.String(domain),
		ServerPort:      protocol.UnsignedShort(port),
		NextState:       1,
	}
	return hs.Marshal()
}

func legacyString(s string) []byte {
	var buf bytes.Buffer
	encoded := utf16.Encode([]rune(s))
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(encoded)))
	for _, r := range encoded {
		_ = binary.Write(&buf, binary.BigEndian, r)
	}
	return buf.Bytes()
}

func legacy16Handshake(username, domain string, port uint32) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x02)
	buf.WriteByte(78)
	buf.Write(legacyString(username))
	buf.Write(legacyString(domain))
	_ = binary.Write(&buf, binary.BigEndian, port)
	return buf.Bytes()
}

func configToProxies(config *ProxyConfig) []*Proxy {
	proxyConfigs := make([]*ProxyConfig, 0)
	proxyConfigs = append(proxyConfigs, config)
	return configsToProxies(proxyConfigs)
}

func configsToProxies(config []*ProxyConfig) []*Proxy {
	var proxies []*Proxy
	for _, c := range config {
		proxy := &Proxy{Config: c}
		proxies = append(proxies, proxy)
	}
	return proxies
}

func sendHandshake(conn Conn, pk protocol.Packet) *testError {
	if err := conn.WritePacket(pk); err != nil {
		return &testError{err, "Can't write handshake"}
	}
	return nil
}

func statusPKWithVersion(name string) StatusConfig {
	samples := make([]PlayerSample, 0)
	return StatusConfig{VersionName: name, ProtocolNumber: 754,
		MaxPlayers: 20, PlayersOnline: 0, PlayerSamples: samples, MOTD: "Server MOTD"}
}

func sendProxyProtocolHeader(rconn Conn) *testError {
	header := createProxyProtocolHeader()
	if _, err := header.WriteTo(rconn); err != nil {
		return &testError{err, "Can't write proxy protocol header"}
	}
	return nil
}

var serverVersionName = "Infrared-test-online"

var onlineStatus = StatusConfig{
	VersionName:    "Infrared 1.16.5 Online",
	ProtocolNumber: 754,
	MaxPlayers:     20,
	MOTD:           "Powered by Infrared",
}

var offlineStatus = StatusConfig{
	VersionName:    "Infrared 1.16.5 Offline",
	ProtocolNumber: 754,
	MaxPlayers:     20,
	MOTD:           "Powered by Infrared",
}

type statusListenerConfig struct {
	id     int
	addr   string
	status StatusConfig
}

func statusListen(c statusListenerConfig, errorCh chan *testError) {
	listener, err := Listen(c.addr)
	if err != nil {
		errorCh <- &testError{err, fmt.Sprintf("Can't listen to %v", c.addr)}
	}

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				errorCh <- &testError{err, "Can't accept connection on listener"}
			}
			pk, err := c.status.StatusResponsePacket()
			if err != nil {
				errorCh <- &testError{err, "Can't create status response packet"}
			}
			go func() {
				if err := conn.WritePacket(pk); err != nil {
					errorCh <- &testError{err, "Can't write status response packet on connection"}
				}
			}()
		}
	}()
}

type statusDialConfig struct {
	pk                      protocol.Packet
	gatewayAddr             string
	dialerPort              int
	sendProxyProtocolHeader bool
	useProxyProtocol        bool
}

func statusDial(c statusDialConfig) (string, *testError) {
	var conn Conn
	var err error
	if c.useProxyProtocol {
		conn, err = createConnWithFakeIP(c.dialerPort, c.gatewayAddr)
	} else {
		conn, err = Dialer{}.Dial(c.gatewayAddr)
	}

	if err != nil {
		return "", &testError{err, "Can't make a connection with gateway"}
	}
	defer conn.Close()

	if c.sendProxyProtocolHeader {
		if err := sendProxyProtocolHeader(conn); err != nil {
			return "", err
		}
	}

	if err := sendHandshake(conn, c.pk); err != nil {
		return "", err
	}

	statusPk := status.ServerBoundRequest{}.Marshal()
	if err := conn.WritePacket(statusPk); err != nil {
		return "", &testError{err, "Can't write status request packet"}
	}

	receivedPk, err := conn.ReadPacket()
	if err != nil {
		return "", &testError{err, "Can't read status reponse packet"}
	}

	response, err := status.UnmarshalClientBoundResponse(receivedPk)
	if err != nil {
		return "", &testError{err, "Can't unmarshal status reponse packet"}
	}

	res := &status.ResponseJSON{}
	json.Unmarshal([]byte(response.JSONResponse), &res)
	return res.Version.Name, nil
}

func createConnWithFakeIP(dialerPort int, gatewayAddr string) (Conn, error) {
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: dialerPort,
		},
	}
	netConn, err := dialer.Dial("tcp", gatewayAddr)
	if err != nil {
		return nil, err
	}
	return wrapConn(netConn), nil
}

func createProxyProtocolHeader() proxyproto.Header {
	return proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr: &net.TCPAddr{
			IP:   net.ParseIP("109.226.143.210"),
			Port: 0,
		},
		DestinationAddr: &net.TCPAddr{
			IP:   net.ParseIP("210.223.216.109"),
			Port: 0,
		},
	}
}

func proxyProtoListen(portEnd int) (string, *testError) {
	listenAddr := serverAddr(portEnd)
	listener, err := Listen(listenAddr)
	if err != nil {
		return "", &testError{err, fmt.Sprintf("Can't listen to %v", listenAddr)}
	}
	defer listener.Close()

	proxyListener := &proxyproto.Listener{Listener: listener.Listener}
	defer proxyListener.Close()

	conn, err := proxyListener.Accept()
	if err != nil {
		return "", &testError{err, "Can't accept connection on listener"}
	}
	defer conn.Close()
	return getIpFromAddr(conn.RemoteAddr()), nil
}

func TestStatusRequest(t *testing.T) {
	tt := []struct {
		name            string
		portEnd         int
		onlineStatus    StatusConfig
		offlineStatus   StatusConfig
		activeServer    bool
		expectedVersion string
	}{
		{
			name:            "ServerOnlineWithoutConfig",
			portEnd:         570,
			activeServer:    true,
			expectedVersion: serverVersionName,
		},
		{
			name:            "ServerOfflineWithoutConfig",
			portEnd:         571,
			activeServer:    false,
			expectedVersion: "",
		},
		{
			name:            "ServerOnlineWithConfig",
			portEnd:         572,
			onlineStatus:    onlineStatus,
			offlineStatus:   offlineStatus,
			activeServer:    true,
			expectedVersion: onlineStatus.VersionName,
		},
		{
			name:            "ServerOfflineWithConfig",
			portEnd:         573,
			onlineStatus:    onlineStatus,
			offlineStatus:   offlineStatus,
			activeServer:    false,
			expectedVersion: offlineStatus.VersionName,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			wg := &sync.WaitGroup{}
			errorCh := make(chan *testError)
			resultCh := make(chan bool)
			wg.Add(1)
			go func(wg *sync.WaitGroup) {
				config := proxyConfigWithPortEnd(tc.portEnd)
				config.OnlineStatus = tc.onlineStatus
				config.OfflineStatus = tc.offlineStatus

				gateway := Gateway{}
				proxies := configToProxies(config)
				if err := gateway.ListenAndServe(proxies); err != nil {
					errorCh <- &testError{err, "Can't start gateway"}
				}
				wg.Done()
				gateway.KeepProcessActive()
			}(wg)

			if tc.activeServer {
				wg.Add(1)
				serverCfg := statusListenerConfig{}
				serverCfg.status = statusPKWithVersion(serverVersionName)
				serverCfg.addr = serverAddr(tc.portEnd)
				go func() {
					statusListen(serverCfg, errorCh)
					wg.Done()
				}()
			}

			wg.Wait()
			go func() {
				pk := statusHandshakePort(tc.portEnd)
				config := statusDialConfig{
					pk:          pk,
					gatewayAddr: gatewayAddr(tc.portEnd),
					dialerPort:  dialerPort(tc.portEnd),
				}
				receivedVersion, err := statusDial(config)
				if err != nil {
					errorCh <- err
					return
				}

				resultCh <- receivedVersion == tc.expectedVersion
			}()

			select {
			case err := <-errorCh:
				t.Fatalf("Unexpected Error in test: %s\n%v", err.Message, err.Error)
			case r := <-resultCh:
				if !r {
					t.Fail()
				}
			}
		})
	}
}

func TestProxyProtocol(t *testing.T) {
	tt := []struct {
		name              string
		proxyproto        bool
		receiveProxyproto bool
		portEnd           int
		shouldMatch       bool
		expectingIp       string
	}{
		{
			name:              "ProxyProtocolOn",
			proxyproto:        true,
			receiveProxyproto: false,
			portEnd:           581,
			shouldMatch:       true,
			expectingIp:       "127.0.0.1",
		},
		{
			name:              "ProxyProtocolOff",
			proxyproto:        false,
			receiveProxyproto: false,
			portEnd:           582,
			shouldMatch:       true,
			expectingIp:       "127.0.0.1",
		},
		{
			name:              "ProxyProtocol Receive",
			proxyproto:        true,
			receiveProxyproto: true,
			portEnd:           583,
			shouldMatch:       true,
			expectingIp:       "109.226.143.210",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			errorCh := make(chan *testError)
			resultCh := make(chan bool)
			wg := &sync.WaitGroup{}

			wg.Add(1)
			go func(wg *sync.WaitGroup) {
				config := createProxyProtocolConfig(tc.portEnd, tc.proxyproto)
				gateway := Gateway{
					ReceiveProxyProtocol: tc.receiveProxyproto,
				}
				proxies := configToProxies(config)
				if err := gateway.ListenAndServe(proxies); err != nil {
					errorCh <- &testError{err, "Can't start gateway"}
				}
				wg.Done()
				gateway.KeepProcessActive()
			}(wg)

			go func() {
				ip, err := proxyProtoListen(tc.portEnd)
				if err != nil {
					errorCh <- err
					return
				}
				resultCh <- ip == tc.expectingIp
			}()
			wg.Wait()
			go func() {

				pk := statusHandshakePort(tc.portEnd)
				config := statusDialConfig{
					pk:                      pk,
					gatewayAddr:             gatewayAddr(tc.portEnd),
					dialerPort:              dialerPort(tc.portEnd),
					useProxyProtocol:        tc.proxyproto,
					sendProxyProtocolHeader: tc.receiveProxyproto,
				}

				_, err := statusDial(config)
				if err != nil {
					errorCh <- err
				}
			}()

			select {
			case err := <-errorCh:
				t.Fatalf("Unexpected Error in test: %s\n%v", err.Message, err.Error)
			case r := <-resultCh:
				if r != tc.shouldMatch {
					t.Errorf("got: %v; want: %v", r, tc.shouldMatch)
				}
			}

		})
	}
}

func TestLegacy16HandshakeRoutesToBackend(t *testing.T) {
	portEnd := 590
	handshake := legacy16Handshake("LegacyUser", serverDomain, uint32(gatewayPort(portEnd)))
	receivedCh := make(chan []byte, 1)
	errorCh := make(chan *testError, 1)

	gateway := Gateway{}
	if err := gateway.ListenAndServe(configToProxies(proxyConfigWithPortEnd(portEnd))); err != nil {
		t.Fatalf("Can't start gateway: %v", err)
	}
	defer gateway.Close()

	listener, err := Listen(serverAddr(portEnd))
	if err != nil {
		t.Fatalf("Can't listen to backend: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errorCh <- &testError{err, "Can't accept backend connection"}
			return
		}
		defer conn.Close()

		received := make([]byte, len(handshake))
		if _, err := io.ReadFull(conn, received); err != nil {
			errorCh <- &testError{err, "Can't read legacy handshake from backend connection"}
			return
		}
		receivedCh <- received
	}()

	conn, err := Dialer{}.Dial(gatewayAddr(portEnd))
	if err != nil {
		t.Fatalf("Can't connect to gateway: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write(handshake); err != nil {
		t.Fatalf("Can't write legacy handshake to gateway: %v", err)
	}

	select {
	case err := <-errorCh:
		t.Fatalf("Unexpected Error in test: %s\n%v", err.Message, err.Error)
	case received := <-receivedCh:
		if !bytes.Equal(received, handshake) {
			t.Fatalf("got: %v; want: %v", received, handshake)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for backend to receive legacy handshake")
	}
}

func TestRouting(t *testing.T) {
	wg := &sync.WaitGroup{}
	errorCh := make(chan *testError)

	basePort := 540
	routingConfig := make([]*ProxyConfig, 0)
	serverConfigs := make([]statusListenerConfig, 0)

	servers := []struct {
		id      int
		domain  string
		portEnd int
	}{
		{
			id:      0,
			domain:  "infrared",
			portEnd: 530,
		},
		{
			id:      9,
			domain:  "infrared",
			portEnd: 531,
		},
		{
			id:      1,
			domain:  "infrared-dash",
			portEnd: 530,
		},
		{
			id:      2,
			domain:  ".dottedInfrared.",
			portEnd: 530,
		},
	}

	tt := []struct {
		name          string
		expectedId    int
		requestDomain string
		portEnd       int
		expectError   bool
		shouldMatch   bool
	}{
		{
			name:          "Single word domain",
			expectedId:    0,
			requestDomain: "infrared",
			portEnd:       530,
			expectError:   false,
			shouldMatch:   true,
		},
		{
			name:          "Single word domain but wrong id",
			expectedId:    1,
			requestDomain: "infrared",
			portEnd:       530,
			expectError:   false,
			shouldMatch:   false,
		},
		{
			name:          "duplicated domain but other port",
			expectedId:    9,
			requestDomain: "infrared",
			portEnd:       531,
			expectError:   false,
			shouldMatch:   true,
		},
		{
			name:          "Domain with a dash",
			expectedId:    1,
			requestDomain: "infrared-dash",
			portEnd:       530,
			expectError:   false,
			shouldMatch:   true,
		},
		{
			name:          "Domain with points at both ends",
			expectedId:    2,
			requestDomain: ".dottedInfrared.",
			portEnd:       530,
			expectError:   true,
			shouldMatch:   false,
		},
	}

	for i, server := range servers {
		port := basePort + i
		proxyC := &ProxyConfig{}
		serverC := statusListenerConfig{}

		serverAddr := serverAddr(port)
		proxyC.ListenTo = gatewayAddr(server.portEnd)
		proxyC.ProxyTo = serverAddr
		proxyC.DomainName = server.domain
		routingConfig = append(routingConfig, proxyC)

		serverC.id = server.id
		serverC.addr = serverAddr
		serverC.status = statusPKWithVersion(routeVersionName(server.id))
		serverConfigs = append(serverConfigs, serverC)
	}

	wg.Add(1)
	go func() {
		gateway := Gateway{}
		proxies := configsToProxies(routingConfig)
		if err := gateway.ListenAndServe(proxies); err != nil {
			errorCh <- &testError{err, "Can't start gateway"}
		}
		wg.Done()
		gateway.KeepProcessActive()
	}()

	for _, c := range serverConfigs {
		wg.Add(1)
		go func(config statusListenerConfig) {
			statusListen(config, errorCh)
			wg.Done()
		}(c)
	}

	wg.Wait()

	select {
	case err := <-errorCh:
		t.Fatalf("Unexpected Error before tests: %s\n%v", err.Message, err.Error)
	default:
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			resultCh := make(chan bool)

			go func() {
				expectedName := routeVersionName(tc.expectedId)
				pk := serverHandshake(tc.requestDomain, tc.portEnd)
				config := statusDialConfig{
					pk:          pk,
					gatewayAddr: gatewayAddr(tc.portEnd),
					dialerPort:  dialerPort(tc.portEnd),
				}

				receivedVersion, err := statusDial(config)
				if err != nil {
					errorCh <- err
					return
				}
				resultCh <- receivedVersion == expectedName
			}()

			select {
			case err := <-errorCh:
				if !tc.expectError {
					t.Fatalf("Unexpected Error in test: %s\n%v", err.Message, err.Error)
				}
			case r := <-resultCh:
				if r != tc.shouldMatch {
					t.Fail()
				}
			}
		})
	}
}

func TestProxyBind(t *testing.T) {
	// TODO: Figure out a way to test this
}

// fakeContainer stands in for the Docker container a route wakes and stops.
type fakeContainer struct {
	mu      sync.Mutex
	running bool
	starts  int
	stops   int
}

func (c *fakeContainer) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = true
	c.starts++
	return nil
}

func (c *fakeContainer) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	c.stops++
	return nil
}

func (c *fakeContainer) IsRunning() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running, nil
}

func (c *fakeContainer) counts() (starts, stops int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.starts, c.stops
}

func managedRoute(domain string, portEnd int, backend string, container *fakeContainer, name string, idle time.Duration) *ProxyConfig {
	config := createBasicProxyConfig(domain, gatewayAddr(portEnd), backend)
	config.Docker.ContainerName = name
	config.Docker.Timeout = int(idle / time.Millisecond)
	config.process = container
	return config
}

func startGateway(t *testing.T, configs ...*ProxyConfig) {
	t.Helper()
	gateway := Gateway{}
	if err := gateway.ListenAndServe(configsToProxies(configs)); err != nil {
		t.Fatalf("Can't start gateway: %v", err)
	}
	t.Cleanup(gateway.Close)
}

// runningBackend accepts and holds connections open, like a running server.
func runningBackend(t *testing.T, addr string) {
	t.Helper()
	listener, err := Listen(addr)
	if err != nil {
		t.Fatalf("Can't listen to backend: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, conn)
		}
	}()
}

func dialGateway(t *testing.T, portEnd int) Conn {
	t.Helper()
	conn, err := Dialer{}.Dial(gatewayAddr(portEnd))
	if err != nil {
		t.Fatalf("Can't connect to gateway: %v", err)
	}
	return conn
}

// joinAs logs a modern client in through the given hostname and keeps it connected.
func joinAs(t *testing.T, domain string, portEnd int, username string) Conn {
	t.Helper()
	conn := dialGateway(t, portEnd)
	hs := handshaking.ServerBoundHandshake{
		ProtocolVersion: 754,
		ServerAddress:   protocol.String(domain),
		ServerPort:      protocol.UnsignedShort(gatewayPort(portEnd)),
		NextState:       handshaking.ServerBoundHandshakeLoginState,
	}
	if err := conn.WritePacket(hs.Marshal()); err != nil {
		t.Fatalf("Can't write login handshake: %v", err)
	}
	if err := conn.WritePacket(protocol.MarshalPacket(0x00, protocol.String(username))); err != nil {
		t.Fatalf("Can't write login start: %v", err)
	}
	return conn
}

// pingOnce sends a server-list ping through the given hostname and hangs up.
func pingOnce(t *testing.T, domain string, portEnd int) {
	t.Helper()
	conn := dialGateway(t, portEnd)
	defer conn.Close()
	if err := conn.WritePacket(serverHandshake(domain, gatewayPort(portEnd))); err != nil {
		t.Fatalf("Can't write status handshake: %v", err)
	}
	if err := conn.WritePacket(status.ServerBoundRequest{}.Marshal()); err != nil {
		t.Fatalf("Can't write status request: %v", err)
	}
}

func waitForStops(container *fakeContainer, want int, within time.Duration) int {
	deadline := time.Now().Add(within)
	for {
		_, stops := container.counts()
		if stops >= want || time.Now().After(deadline) {
			return stops
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Two hostnames route to one container (live: mc.pmserver.us and the tailnet IP
// both reach Meat Castle). The container is one server: activity through either
// alias must keep it awake, and it stops only once nobody is on it.
func TestSharedAliasPlayerKeepsContainerAwake(t *testing.T) {
	const idle = 300 * time.Millisecond
	const settle = 100 * time.Millisecond

	t.Run("ping on one alias does not stop a server with a player on the other", func(t *testing.T) {
		portEnd := 610
		container := &fakeContainer{running: true}
		runningBackend(t, serverAddr(portEnd))
		startGateway(t,
			managedRoute("mc.pmserver.test", portEnd, serverAddr(portEnd), container, "mc-shared-ping", idle),
			managedRoute("100.116.108.52", portEnd, serverAddr(portEnd), container, "mc-shared-ping", idle),
		)

		player := joinAs(t, "mc.pmserver.test", portEnd, "Steve")
		time.Sleep(settle)
		pingOnce(t, "100.116.108.52", portEnd)
		time.Sleep(3 * idle)
		if _, stops := container.counts(); stops != 0 {
			t.Fatalf("container stopped %d time(s) while a player was connected through the other alias", stops)
		}

		player.Close()
		if stops := waitForStops(container, 1, 5*idle); stops != 1 {
			t.Fatalf("container stopped %d time(s) after the last player left; want 1", stops)
		}
	})

	t.Run("join on one alias cancels the idle stop armed by the other", func(t *testing.T) {
		portEnd := 611
		container := &fakeContainer{running: true}
		runningBackend(t, serverAddr(portEnd))
		startGateway(t,
			managedRoute("mc.pmserver.test", portEnd, serverAddr(portEnd), container, "mc-shared-rejoin", idle),
			managedRoute("100.116.108.52", portEnd, serverAddr(portEnd), container, "mc-shared-rejoin", idle),
		)

		first := joinAs(t, "mc.pmserver.test", portEnd, "Steve")
		time.Sleep(settle)
		first.Close()
		time.Sleep(idle / 3)
		second := joinAs(t, "100.116.108.52", portEnd, "Alex")
		time.Sleep(3 * idle)
		if _, stops := container.counts(); stops != 0 {
			t.Fatalf("container stopped %d time(s) while a player was connected through the other alias", stops)
		}

		second.Close()
		if stops := waitForStops(container, 1, 5*idle); stops != 1 {
			t.Fatalf("container stopped %d time(s) after the last player left; want 1", stops)
		}
	})
}

func legacy16Ping(domain string, port uint32) []byte {
	var host bytes.Buffer
	host.WriteByte(78)
	host.Write(legacyString(domain))
	_ = binary.Write(&host, binary.BigEndian, port)

	var buf bytes.Buffer
	buf.Write([]byte{0xfe, 0x01, 0xfa})
	buf.Write(legacyString("MC|PingHost"))
	_ = binary.Write(&buf, binary.BigEndian, uint16(host.Len()))
	buf.Write(host.Bytes())
	return buf.Bytes()
}

// readLegacyKick reads the 0xFF kick packet a 1.6 client gets for a ping reply or disconnect.
func readLegacyKick(conn Conn) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var header [3]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", err
	}
	if header[0] != 0xff {
		return "", fmt.Errorf("packet id %#x; want 0xff", header[0])
	}
	chars := make([]uint16, binary.BigEndian.Uint16(header[1:]))
	if err := binary.Read(conn, binary.BigEndian, chars); err != nil {
		return "", err
	}
	return string(utf16.Decode(chars)), nil
}

// recordingBackend reports the first n bytes of every connection the backend receives.
func recordingBackend(t *testing.T, addr string, n int) <-chan []byte {
	t.Helper()
	listener, err := Listen(addr)
	if err != nil {
		t.Fatalf("Can't listen to backend: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	received := make(chan []byte, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, n)
				if _, err := io.ReadFull(conn, buf); err == nil {
					received <- buf
				}
			}()
		}
	}()
	return received
}

func sendLegacy(t *testing.T, portEnd int, packet []byte) Conn {
	t.Helper()
	conn := dialGateway(t, portEnd)
	t.Cleanup(func() { conn.Close() })
	if _, err := conn.Write(packet); err != nil {
		t.Fatalf("Can't write legacy packet: %v", err)
	}
	return conn
}

func expectBackendReceives(t *testing.T, received <-chan []byte, want []byte) {
	t.Helper()
	select {
	case got := <-received:
		if !bytes.Equal(got, want) {
			t.Fatalf("backend got %v; want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("backend never received the legacy handshake")
	}
}

// Minecraft 1.6 clients (Meat Castle) speak the pre-Netty protocol. They must
// reach the server their hostname names, wake it when it sleeps, and see its
// server-list status, exactly as modern clients do. Hostname checks repeat
// because a gateway ignoring the hostname would pick a route at random.
func TestLegacy16ClientsReachTheirServerByHostname(t *testing.T) {
	const rounds = 4

	t.Run("login routes by hostname among routes sharing a port", func(t *testing.T) {
		portEnd := 620
		mcBackend, sfBackend := serverAddr(620), serverAddr(621)
		startGateway(t,
			createBasicProxyConfig("mc.pmserver.test", gatewayAddr(portEnd), mcBackend),
			createBasicProxyConfig("sf.pmserver.test", gatewayAddr(portEnd), sfBackend),
		)

		mcHandshake := legacy16Handshake("LegacyUser", "mc.pmserver.test", uint32(gatewayPort(portEnd)))
		sfHandshake := legacy16Handshake("LegacyUser", "sf.pmserver.test", uint32(gatewayPort(portEnd)))
		mcReceived := recordingBackend(t, mcBackend, len(mcHandshake))
		sfReceived := recordingBackend(t, sfBackend, len(sfHandshake))
		for i := 0; i < rounds; i++ {
			sendLegacy(t, portEnd, sfHandshake)
			expectBackendReceives(t, sfReceived, sfHandshake)
			sendLegacy(t, portEnd, mcHandshake)
			expectBackendReceives(t, mcReceived, mcHandshake)
		}
	})

	t.Run("login with an unconfigured hostname falls back to the port's route", func(t *testing.T) {
		portEnd := 622
		startGateway(t, createBasicProxyConfig("mc.pmserver.test", gatewayAddr(portEnd), serverAddr(portEnd)))

		handshake := legacy16Handshake("LegacyUser", "203.0.113.7", uint32(gatewayPort(portEnd)))
		received := recordingBackend(t, serverAddr(portEnd), len(handshake))
		sendLegacy(t, portEnd, handshake)
		expectBackendReceives(t, received, handshake)
	})

	t.Run("server-list ping shows the named server's status", func(t *testing.T) {
		portEnd := 623
		mc := createBasicProxyConfig("mc.pmserver.test", gatewayAddr(portEnd), serverAddr(623))
		mc.OfflineStatus = StatusConfig{VersionName: "1.6.4", ProtocolNumber: 78, MaxPlayers: 10, MOTD: "Meat Castle is asleep"}
		sf := createBasicProxyConfig("sf.pmserver.test", gatewayAddr(portEnd), serverAddr(624))
		sf.OfflineStatus = StatusConfig{VersionName: "1.6.4", ProtocolNumber: 78, MaxPlayers: 10, MOTD: "SkyFactory is asleep"}
		startGateway(t, mc, sf)

		for i := 0; i < rounds; i++ {
			for _, route := range []*ProxyConfig{sf, mc} {
				conn := sendLegacy(t, portEnd, legacy16Ping(route.DomainName, uint32(gatewayPort(portEnd))))
				reply, err := readLegacyKick(conn)
				if err != nil {
					t.Fatalf("no legacy status reply for %s: %v", route.DomainName, err)
				}
				fields := strings.Split(reply, "\x00")
				if len(fields) != 6 || fields[0] != "\u00a71" {
					t.Fatalf("reply %q is not a 1.6 status response", reply)
				}
				if fields[3] != route.OfflineStatus.MOTD {
					t.Fatalf("%s status MOTD %q; want %q", route.DomainName, fields[3], route.OfflineStatus.MOTD)
				}
			}
		}
	})

	t.Run("login to a sleeping server wakes it and tells the player", func(t *testing.T) {
		portEnd := 625
		container := &fakeContainer{}
		route := managedRoute("mc.pmserver.test", portEnd, serverAddr(portEnd), container, "mc-legacy-wake", time.Minute)
		route.DisconnectMessage = "Server is starting"
		startGateway(t, route)

		conn := sendLegacy(t, portEnd, legacy16Handshake("LegacyUser", "mc.pmserver.test", uint32(gatewayPort(portEnd))))
		reply, err := readLegacyKick(conn)
		if err != nil {
			t.Fatalf("no legacy disconnect: %v", err)
		}
		if reply != "Server is starting" {
			t.Fatalf("disconnect %q; want the configured message", reply)
		}
		if starts, _ := container.counts(); starts != 1 {
			t.Fatalf("container started %d time(s); want 1", starts)
		}
	})
}
