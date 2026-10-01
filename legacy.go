package infrared

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/haveachin/infrared/callback"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	legacyLoginPacketID byte = 0x02
	legacyPingPacketID  byte = 0xfe
)

type legacyRequestKind int

const (
	legacyRequestLogin legacyRequestKind = iota
	legacyRequestPing
)

type legacyRequest struct {
	Kind            legacyRequestKind
	Raw             []byte
	ProtocolVersion byte
	Username        string
	ServerAddress   string
	ServerPort      uint32
}

type legacyPacketReader struct {
	reader *bufio.Reader
	raw    bytes.Buffer
}

func isLegacyPacket(reader *bufio.Reader) bool {
	b, err := reader.Peek(1)
	if err != nil {
		return false
	}
	return b[0] == legacyLoginPacketID || b[0] == legacyPingPacketID
}

func readLegacyRequest(reader *bufio.Reader) (legacyRequest, error) {
	r := &legacyPacketReader{reader: reader}
	packetID, err := r.readByte()
	if err != nil {
		return legacyRequest{}, err
	}

	switch packetID {
	case legacyLoginPacketID:
		return r.readLegacyLogin()
	case legacyPingPacketID:
		return r.readLegacyPing()
	default:
		return legacyRequest{}, errors.New("unsupported legacy packet")
	}
}

func (r *legacyPacketReader) readLegacyLogin() (legacyRequest, error) {
	protocolVersion, err := r.readByte()
	if err != nil {
		return legacyRequest{}, err
	}

	username, err := r.readString()
	if err != nil {
		return legacyRequest{}, err
	}

	serverAddress, err := r.readString()
	if err != nil {
		return legacyRequest{}, err
	}

	serverPort, err := r.readUint32()
	if err != nil {
		return legacyRequest{}, err
	}

	return legacyRequest{
		Kind:            legacyRequestLogin,
		Raw:             r.raw.Bytes(),
		ProtocolVersion: protocolVersion,
		Username:        username,
		ServerAddress:   strings.Trim(serverAddress, "."),
		ServerPort:      serverPort,
	}, nil
}

func (r *legacyPacketReader) readLegacyPing() (legacyRequest, error) {
	kind, err := r.readByte()
	if err != nil {
		return legacyRequest{}, err
	}
	if kind != 0x01 {
		return legacyRequest{}, errors.New("unsupported legacy ping")
	}

	channelPacketID, err := r.readByte()
	if err != nil {
		return legacyRequest{}, err
	}
	if channelPacketID != 0xfa {
		return legacyRequest{}, errors.New("unsupported legacy ping plugin packet")
	}

	channel, err := r.readString()
	if err != nil {
		return legacyRequest{}, err
	}
	if channel != "MC|PingHost" {
		return legacyRequest{}, errors.New("unsupported legacy ping channel")
	}

	if _, err := r.readUint16(); err != nil {
		return legacyRequest{}, err
	}

	protocolVersion, err := r.readByte()
	if err != nil {
		return legacyRequest{}, err
	}

	serverAddress, err := r.readString()
	if err != nil {
		return legacyRequest{}, err
	}

	serverPort, err := r.readUint32()
	if err != nil {
		return legacyRequest{}, err
	}

	return legacyRequest{
		Kind:            legacyRequestPing,
		Raw:             r.raw.Bytes(),
		ProtocolVersion: protocolVersion,
		ServerAddress:   strings.Trim(serverAddress, "."),
		ServerPort:      serverPort,
	}, nil
}

func (r *legacyPacketReader) readByte() (byte, error) {
	b, err := r.reader.ReadByte()
	if err != nil {
		return 0, err
	}
	r.raw.WriteByte(b)
	return b, nil
}

func (r *legacyPacketReader) readUint16() (uint16, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r.reader, buf[:]); err != nil {
		return 0, err
	}
	r.raw.Write(buf[:])
	return binary.BigEndian.Uint16(buf[:]), nil
}

func (r *legacyPacketReader) readUint32() (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r.reader, buf[:]); err != nil {
		return 0, err
	}
	r.raw.Write(buf[:])
	return binary.BigEndian.Uint32(buf[:]), nil
}

func (r *legacyPacketReader) readString() (string, error) {
	length, err := r.readUint16()
	if err != nil {
		return "", err
	}

	data := make([]byte, int(length)*2)
	if _, err := io.ReadFull(r.reader, data); err != nil {
		return "", err
	}
	r.raw.Write(data)

	chars := make([]uint16, length)
	for i := range chars {
		chars[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
	}
	return string(utf16.Decode(chars)), nil
}

func (proxy *Proxy) handleLegacyRequest(conn Conn, connRemoteAddr net.Addr, request legacyRequest) error {
	proxyDomain := proxy.DomainName()
	proxyTo := proxy.ProxyTo()
	proxyUID := proxy.UID()

	dialer, err := proxy.Dialer()
	if err != nil {
		return err
	}

	rconn, err := dialer.Dial(proxyTo)
	if err != nil {
		log.Printf("[i] %s did not respond to ping; is the target offline?", proxyTo)
		if request.Kind == legacyRequestPing {
			return proxy.writeLegacyStatus(conn, false, request.ProtocolVersion)
		}
		if err := proxy.startProcessIfNotRunning(); err != nil {
			return err
		}
		proxy.timeoutProcess()
		return proxy.writeLegacyDisconnect(conn, request, connRemoteAddr)
	}
	defer rconn.Close()

	if request.Kind == legacyRequestPing && proxy.IsOnlineStatusConfigured() {
		return proxy.writeLegacyStatus(conn, true, request.ProtocolVersion)
	}

	if proxy.ProxyProtocol() {
		header := &proxyproto.Header{
			Version:           2,
			Command:           proxyproto.PROXY,
			TransportProtocol: proxyproto.TCPv4,
			SourceAddr:        connRemoteAddr,
			DestinationAddr:   rconn.RemoteAddr(),
		}

		if _, err = header.WriteTo(rconn); err != nil {
			return err
		}
	}

	if _, err := rconn.Write(request.Raw); err != nil {
		return err
	}

	if request.Kind == legacyRequestPing {
		_, err := io.Copy(conn, rconn)
		return err
	}

	proxy.cancelProcessTimeout()
	proxy.addPlayer(conn, request.Username)
	proxy.logEvent(callback.PlayerJoinEvent{
		Username:      request.Username,
		RemoteAddress: connRemoteAddr.String(),
		TargetAddress: proxyTo,
		ProxyUID:      proxyUID,
	})
	playersConnected.With(prometheus.Labels{"host": proxyDomain}).Inc()

	go pipe(rconn, conn)
	pipe(conn, rconn)

	proxy.logEvent(callback.PlayerLeaveEvent{
		Username:      request.Username,
		RemoteAddress: connRemoteAddr.String(),
		TargetAddress: proxyTo,
		ProxyUID:      proxyUID,
	})
	playersConnected.With(prometheus.Labels{"host": proxyDomain}).Dec()

	remainingPlayers := proxy.removePlayer(conn)
	if remainingPlayers <= 0 {
		proxy.timeoutProcess()
	}
	return nil
}

func (proxy *Proxy) writeLegacyDisconnect(conn Conn, request legacyRequest, connRemoteAddr net.Addr) error {
	message := proxy.DisconnectMessage()
	templates := map[string]string{
		"username":      request.Username,
		"now":           time.Now().Format(time.RFC822),
		"remoteAddress": connRemoteAddr.String(),
		"localAddress":  conn.LocalAddr().String(),
		"domain":        proxy.DomainName(),
		"proxyTo":       proxy.ProxyTo(),
		"listenTo":      proxy.ListenTo(),
	}

	for key, value := range templates {
		message = strings.Replace(message, fmt.Sprintf("{{%s}}", key), value, -1)
	}

	return writeLegacyStringPacket(conn, 0xff, message)
}

func (proxy *Proxy) writeLegacyStatus(conn Conn, online bool, protocolVersion byte) error {
	status := proxy.legacyStatus(online)
	if status.ProtocolNumber == 0 {
		status.ProtocolNumber = int(protocolVersion)
	}
	if status.VersionName == "" {
		status.VersionName = "Minecraft"
	}

	message := fmt.Sprintf("\u00a71\x00%d\x00%s\x00%s\x00%d\x00%d",
		status.ProtocolNumber,
		status.VersionName,
		status.MOTD,
		status.PlayersOnline,
		status.MaxPlayers,
	)
	return writeLegacyStringPacket(conn, 0xff, message)
}

func (proxy *Proxy) legacyStatus(online bool) StatusConfig {
	proxy.Config.Lock()
	defer proxy.Config.Unlock()
	if online {
		return proxy.Config.OnlineStatus
	}
	return proxy.Config.OfflineStatus
}

func writeLegacyStringPacket(w io.Writer, packetID byte, value string) error {
	var buf bytes.Buffer
	buf.WriteByte(packetID)
	writeLegacyString(&buf, value)
	_, err := w.Write(buf.Bytes())
	return err
}

func writeLegacyString(w io.Writer, value string) {
	encoded := utf16.Encode([]rune(value))
	_ = binary.Write(w, binary.BigEndian, uint16(len(encoded)))
	for _, r := range encoded {
		_ = binary.Write(w, binary.BigEndian, r)
	}
}
