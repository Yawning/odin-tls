package tls

import "base:runtime"
import "core:io"
import "core:net"
import "core:time"
import "core:sync"
import "core:sync/chan"

// Error is the common error returned from all TLS calls.
Error :: union #shared_nil {
	runtime.Allocator_Error,
	io.Error,
	net.TCP_Send_Error,
	net.TCP_Recv_Error,

	General_Error,
	Protocol_Error,
}

// Protocol_Error is errors translated from TLS protocol layer alerts.
Protocol_Error :: enum {
	None,

	// Alerts
	Close_Notify,
	Unexpected_Message,
	Bad_Record_Mac,
	Record_Overflow,
	Handshake_Failure,
	Bad_Certificate,
	Unsupported_Certificate,
	Certificate_Revoked,
	Certificate_Expired,
	Certificate_Unknown,
	Illegal_Parameter,
	Unknown_Ca,
	Access_Denied,
	Decode_Error,
	Decrypt_Error,
	Protocol_Version,
	Insufficient_Security,
	Internal_Error,
	Inappropriate_Fallback,
	User_Canceled,
	Missing_Extension,
	Unsupported_Extension,
	Unrecognized_Name,
	Bad_Certificate_Status_Response,
	Unknown_Psk_Identity,
	Certificate_Required,
	General_Error,
	No_Application_Protocol,
}

// General_Error are errors related to the implementation.
General_Error :: enum {
	Invalid_SNI_Hostname,
	Failed_Key_Share_Generation,
	Unsupported_Fragmented_Handshake_Message,
	Unsupported_Client_Certificate_Requested,
}

// Socket is a TLS socket.  It MUST NOT be copied as the internal state
// contains thread synchronization primitives.
Socket :: struct {
	fd:            net.TCP_Socket,
	cipher_suite:  Cipher_Suite,
	alpn_protocol: Alpn_Protocols,

	_state: Socket_State,
}

@(private)
Socket_State :: struct {
	err:      Error,
	err_lock: sync.Benaphore,

	secrets: Connection_Secrets,

	rx_closed:  bool,
	handshaked: bool,

	done:         sync.Wait_Group,
	tx_chan:      chan.Chan(Worker_Req),
	tx_resp_chan: chan.Chan(Worker_Resp),
	rx_chan:      chan.Chan(Worker_Req),
	rx_resp_chan: chan.Chan(Worker_Resp),

	allocator: runtime.Allocator,
}

// close will close a Socket, and release related resources.  This will
// also close the underlying TCP socket.
//
// Warning: Once a Socket is successfully initialized, close MUST be
// called to free resources and sanitize secrets.
close :: proc(socket: ^Socket, max_close_wait := 100 * time.Millisecond) {
	orig_err := socket_error(socket)
	if orig_err == nil {
		orig_err = io.Error.Closed
	}

	if !socket._state.handshaked {
		net.close(socket.fd)

		socket.fd = net.TCP_Socket{}
		clear_connection_secrets(&socket._state.secrets)

		socket_set_error(socket, orig_err)
		return
	}

	// Try to send a Close_Notify.
	worker_send_alert(socket, .Close_Notify)

	// Close the channels so the worker threads will terminate,
	// assuming they are not blocked on send/recv.
	chan.close(socket._state.tx_chan)
	chan.close(socket._state.rx_chan)

	// Wait for the workers to terminate.
	ok := sync.wait_with_timeout(&socket._state.done, max_close_wait)

	// Well, we waited, yeet the socket.
	net.close(socket.fd)

	if !ok {
		// The threads did not terminate when we closed the channels,
		// so they must have been blocked on send/recv.  Now that the
		// socket got yeeted off to Narnia to chill with the Lion,
		// we can wait, because the threads will error out.
		sync.wait(&socket._state.done)
	}

	socket.fd = net.TCP_Socket{}
	clear_connection_secrets(&socket._state.secrets)
	chan.destroy(socket._state.tx_chan)
	chan.destroy(socket._state.tx_resp_chan)
	chan.destroy(socket._state.rx_chan)
	chan.destroy(socket._state.rx_resp_chan)

	// Restore the original error, or set it to Closed.
	socket_set_error(socket, orig_err)
}

// send transmits data over an established connection, and returns the
// number of bytes sent and an error if any.
//
// Note: Errors should be treated as fatal, and close should be called
// on the connection.
@(require_results)
send :: proc(socket: ^Socket, buf: []byte) -> (n: int, err: Error) {
	if !socket._state.handshaked {
		return 0, io.Error.Closed
	}
	if err = socket_error(socket); err != nil {
		return
	}
	if len(buf) == 0 {
		return
	}

	req := Worker_Req{
		op = .Transfer,
		data = buf,
	}
	if !chan.send(socket._state.tx_chan, req) {
		err = socket_error(socket)
		if err == nil {
			err = io.Error.Unknown
		}
		return
	}

	resp, ok := chan.recv(socket._state.tx_resp_chan)
	if !ok {
		// Unlikely to happen.
		err = socket_error(socket)
		if err == nil {
			err = io.Error.Unknown
		}
		return
	}

	return resp.n, resp.err
}

// recv receives data from an established Socket into the provided buffer,
// returning the actual number of bytes received and an error if any.
//
// Notes: Partial reads are to be expected, so `n` MUST be checked.
// An error of `Protocol_Error.Close_Notify` indicates that the peer will
// not send anymore data, however it still is possible to send data to
// the peer.
@(require_results)
recv :: proc(socket: ^Socket, buf: []byte) -> (n: int, err: Error) {
	if !socket._state.handshaked {
		return 0, io.Error.Closed
	}
	if err = socket_error(socket); err != nil {
		return
	}
	if socket._state.rx_closed == true {
		return 0, Protocol_Error.Close_Notify
	}

	l := len(buf)
	if l == 0 {
		return 0, nil
	}

	req := Worker_Req{
		op = .Transfer,
		data = buf,
	}
	if !chan.send(socket._state.rx_chan, req) {
		err = socket_error(socket)
		if err == nil {
			err = io.Error.Unknown
		}
		return
	}

	resp, ok := chan.recv(socket._state.rx_resp_chan)
	if !ok {
		// Should NEVER happen.
		err = socket_error(socket)
		if err == nil {
			err = io.Error.Unknown
		}
		return
	}

	if resp.err == Protocol_Error.Close_Notify {
		socket._state.rx_closed = true
	}

	return resp.n, resp.err
}

// socket_error returns the error status of a Socket.
@(require_results)
socket_error :: proc(socket: ^Socket) -> (err: Error) {
	if sync.guard(&socket._state.err_lock) {
		err = socket._state.err
	}
	return
}

@(private)
socket_set_error :: proc(socket: ^Socket, err: Error) -> Error {
	if sync.guard(&socket._state.err_lock) {
		// Preserve the exiting error.
		if socket._state.err == nil {
			socket._state.err = err
		}
	}
	return err
}
