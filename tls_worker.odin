#+private
package tls

import "core:io"
import "core:sync"
import "core:sync/chan"

Worker_Op :: enum {
	Transfer,
	Alert,
	Key_Update,
}

Worker_Req :: struct {
	op:    Worker_Op,
	alert: Alert_Description,
	data:  []byte,
}

Worker_Resp :: struct {
	n:   int,
	err: Error,
}

worker_sender :: proc(socket: ^Socket) {
	defer sync.wait_group_done(&socket._state.done)
	defer chan.close(&socket._state.tx_chan)
	defer chan.close(&socket._state.tx_resp_chan)

	// Record buffer.
	tx_data: [TLS13_MAX_RECORD_SIZE+TLS13_MAX_AEAD_OVERHEAD]byte = ---
	tx_buf: Buffer
	buffer_init(&tx_buf, tx_data[:])

	resp: Worker_Resp = ---
	for {
		req, ok := chan.recv(socket._state.tx_chan)
		if !ok {
			return
		}

		switch req.op {
		case .Transfer:
		case .Alert:
			_ = buffer_send_alert(&tx_buf, socket, req.alert)
			return
		case .Key_Update:
			if err := buffer_send_key_update(&tx_buf, socket, .Update_Not_Requested); err != nil {
				socket_set_error(socket, err)
				return
			}
			update_connection_secret(&socket._state.secrets, true)
		}

		n: int
		l := len(req.data)
		for l - n > 0 {
			sz := min(TLS13_MAX_PAYLOAD_SIZE, l - n)

			// None of these can fail.
			buffer_clear(&tx_buf)
			_ = buffer_write_u8(&tx_buf, u8(Content_Type.Application_Data))
			_ = buffer_write_u16(&tx_buf, TLS12_PROTOCOL_VERSION)
			_ = buffer_write_u16(&tx_buf, u16(sz + TLS13_AEAD_OVERHEAD))

			_ = buffer_write_bytes(&tx_buf, req.data[n:n+sz])
			_ = buffer_write_u8(&tx_buf, u8(Content_Type.Application_Data))

			if err := buffer_send_record(&tx_buf, socket); err != nil {
				socket_set_error(socket, err)
				resp.n = n
				resp.err = err
				chan.send(socket._state.tx_resp_chan, resp)
				return
			}

			n += sz
		}

		resp.n = n
		resp.err = nil
		chan.send(socket._state.tx_resp_chan, resp)
	}
}

worker_receiver :: proc(socket: ^Socket) {
	defer sync.wait_group_done(&socket._state.done)
	defer chan.close(&socket._state.rx_chan)
	defer chan.close(&socket._state.rx_resp_chan)

	// Remaining unconsumed data.
	data: [TLS13_MAX_PAYLOAD_SIZE]byte
	data_buf: Buffer
	buffer_init(&data_buf, data[:])

	// Record buffer.
	rx_data: [TLS13_MAX_RECORD_SIZE+TLS13_MAX_AEAD_OVERHEAD]byte
	rx_buf: Buffer
	buffer_init(&rx_buf, rx_data[:])

	resp: Worker_Resp = ---
	peer_closed: bool
	resp_ch := socket._state.rx_resp_chan
msg_loop:
	for {
		req, ok := chan.recv(socket._state.rx_chan)
		if !ok {
			return
		}

		assert(req.op == .Transfer)
		assert(len(req.data) > 0)

		if l := buffer_unread_len(&data_buf); l > 0 {
			resp.n = min(l, len(req.data))
			resp.err = buffer_read_bytes(&data_buf, req.data[:resp.n])
			chan.send(resp_ch, resp)
			continue
		}

		assert(buffer_unread_len(&data_buf) == 0)

		if peer_closed {
			resp.n = 0
			resp.err = Protocol_Error.Close_Notify
			chan.send(resp_ch, resp)
			continue
		}

		useless_record_count: int
		for {
			// Error out on a spam of empty records or `user_canceled` alerts.
			MAX_USELESS_RECORDS :: 16
			if useless_record_count >= MAX_USELESS_RECORDS {
				resp.n = 0
				resp.err = io.Error.No_Progress
				chan.send(resp_ch, resp)
				return
			}

			content_type, err := buffer_recv_record(&rx_buf, socket, socket._state.secrets.is_client)

			// See: https://bugs.openjdk.org/browse/JDK-8323517
			if content_type == .Alert && err == Protocol_Error.User_Canceled {
				useless_record_count += 1
				continue
			}

			if err != nil {
				if err == Protocol_Error.Close_Notify {
					peer_closed = true
					resp.n = 0
					resp.err = Protocol_Error.Close_Notify
					chan.send(resp_ch, resp)
					continue msg_loop
				}

				worker_send_alert(socket, error_to_alert(err))
				socket_set_error(socket, err)
				return
			}

			#partial switch content_type {
			case .Application_Data:
			case .Handshake:
				l := buffer_unread_len(&rx_buf) - 1
				if l < 4 {
					worker_send_alert(socket, .Decode_Error)
					socket_set_error(socket, Protocol_Error.Decode_Error)
					return
				}
				payload := buffer_unread_bytes(&rx_buf)[:l]
				if payload[0] == u8(Handshake_Type.Key_Update) {
					if l != 5 || unchecked_get_u24be(payload[1:]) != 1 {
						worker_send_alert(socket, .Decode_Error)
						socket_set_error(socket, Protocol_Error.Decode_Error)
						return
					}
					switch Key_Update_Request(payload[4]) {
					case .Update_Not_Requested:
					case .Update_Requested:
						chan.send(socket._state.tx_chan, Worker_Req{op = .Key_Update})
					case:
						worker_send_alert(socket, .Illegal_Parameter)
						socket_set_error(socket, Protocol_Error.Illegal_Parameter)
						return
					}

					update_connection_secret(&socket._state.secrets, false)
					continue
				}

				// We should not get `new_session_ticket`s for now.
				worker_send_alert(socket, .Internal_Error)
				socket_set_error(socket, err)
				return
			case:
				worker_send_alert(socket, .Unexpected_Message)
				socket_set_error(socket, Protocol_Error.Unexpected_Message)
				return
			}

			resp.n = buffer_unread_len(&rx_buf) - 1
			if resp.n <= 0 {
				useless_record_count += 1
				continue
			}
			assert(rx_buf.b[rx_buf.off-1] == u8(content_type))
			_ = buffer_trim(&rx_buf, 1) // Trim off the `content_type`.

			resp.err = nil
			resp.n = min(resp.n, len(req.data))
			_ = buffer_read_bytes(&rx_buf, req.data[:resp.n])

			if buffer_unread_len(&rx_buf) > 0 {
				buffer_clear(&data_buf)
				_ = buffer_write_bytes(&data_buf, buffer_unread_bytes(&rx_buf))
			}

			chan.send(resp_ch, resp)
			break
		}
	}
}

worker_send_alert :: proc(socket: ^Socket, alert: Alert_Description) {
	req := Worker_Req{
		op = .Alert,
		alert = alert,
	}

	// Sending an alert is best-effort.
	_ = chan.try_send(socket._state.tx_chan, req)
}
