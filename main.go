// main.go - Vortex DFS Gateway
//
// Implementa o protocolo binário Vortex em paridade com o lado Rust:
//   - Parse seguro via encoding/binary (sem cast de ponteiro)
//   - Validação de CRC-32 idêntica ao Rust (IEEE, little-endian)
//   - Limites de tamanho antes de qualquer alocação
//   - Sem chave hardcoded — configuração via variável de ambiente
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
)

// ================================================================
// Protocolo binário Vortex
// Layout: [SyncWord:2][Cmd:2][Len:4][CRC:4][Payload:Len]
//         tudo little-endian, alinhado — paridade com Rust repr(C)
// ================================================================

const (
	SyncWord    uint16 = 0x5654
	HeaderSize         = 12              // 2+2+4+4
	MaxPayload         = 65535           // igual ao lado Rust
	MaxBodySize        = 1 * 1024 * 1024 // 1 MB — igual ao vortex_guard.rs
)

// Packet representa um pacote Vortex já parseado e validado.
type Packet struct {
	SyncWord uint16
	Cmd      uint16
	Len      uint32
	CRC      uint32
	Payload  []byte
}

// ParseError descreve por que o parse falhou — espelha ParseError do Rust.
type ParseError struct {
	Kind    string
	Message string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("ParseError[%s]: %s", e.Kind, e.Message)
}

var (
	ErrBufferTooSmall  = &ParseError{"BufferTooSmall", "buffer menor que o header mínimo"}
	ErrBadSyncWord     = &ParseError{"BadSyncWord", "sync word inválido"}
	ErrPayloadTooLarge = &ParseError{"PayloadTooLarge", "payload excede limite máximo"}
	ErrBodyTooLarge    = &ParseError{"BodyTooLarge", "body excede limite de segurança"}
)

// crcTable usa o polinômio IEEE — idêntico ao crc32fast do Rust.
var crcTable = crc32.MakeTable(crc32.IEEE)

// computeCRC calcula CRC-32 sobre os primeiros 8 bytes do header + payload.
// Espelha exatamente a lógica do Rust:
//   h.update(&buf[0..8]); h.update(payload);
func computeCRC(header8 []byte, payload []byte) uint32 {
	h := crc32.New(crcTable)
	h.Write(header8)
	h.Write(payload)
	return h.Sum32()
}

// ParsePacket lê um pacote Vortex de bytes brutos de forma segura.
//
// ANTES (rascunho original): struct sem lógica — Go aceitava qualquer coisa.
// AGORA:
//   - Leitura via encoding/binary (sem cast de ponteiro, sem unsafe)
//   - Validação de sync word
//   - Validação de CRC antes de processar o payload
//   - Limites de tamanho em duas camadas (MaxBodySize + MaxPayload)
func ParsePacket(buf []byte) (*Packet, error) {
	// Camada 1: limite de segurança total
	if len(buf) > MaxBodySize {
		return nil, ErrBodyTooLarge
	}

	// Camada 2: buffer mínimo para o header
	if len(buf) < HeaderSize {
		return nil, ErrBufferTooSmall
	}

	// Leitura segura via encoding/binary — sem unsafe, sem cast de ponteiro
	syncWord := binary.LittleEndian.Uint16(buf[0:2])
	cmd := binary.LittleEndian.Uint16(buf[2:4])
	payloadLen := binary.LittleEndian.Uint32(buf[4:8])
	crc := binary.LittleEndian.Uint32(buf[8:12])

	// Validação de sync word
	if syncWord != SyncWord {
		return nil, ErrBadSyncWord
	}

	// Validação de tamanho do payload
	if payloadLen > MaxPayload {
		return nil, ErrPayloadTooLarge
	}

	plen := int(payloadLen)
	if len(buf) < HeaderSize+plen {
		return nil, ErrBufferTooSmall
	}

	payload := buf[HeaderSize : HeaderSize+plen]

	// Validação de CRC — igual ao Rust: CRC sobre header[0:8] + payload
	computed := computeCRC(buf[0:8], payload)
	if computed != crc {
		return nil, &ParseError{
			Kind:    "CrcMismatch",
			Message: fmt.Sprintf("esperado 0x%08x, calculado 0x%08x", crc, computed),
		}
	}

	return &Packet{
		SyncWord: syncWord,
		Cmd:      cmd,
		Len:      payloadLen,
		CRC:      crc,
		Payload:  payload,
	}, nil
}

// BuildPacket monta um pacote Vortex com CRC calculado automaticamente.
// Paridade com build_packet() do Rust.
func BuildPacket(cmd uint16, payload []byte) []byte {
	payloadLen := uint32(len(payload))
	buf := make([]byte, HeaderSize+len(payload))

	binary.LittleEndian.PutUint16(buf[0:2], SyncWord)
	binary.LittleEndian.PutUint16(buf[2:4], cmd)
	binary.LittleEndian.PutUint32(buf[4:8], payloadLen)
	// buf[8:12] = CRC (preenchido abaixo)
	copy(buf[HeaderSize:], payload)

	crc := computeCRC(buf[0:8], payload)
	binary.LittleEndian.PutUint32(buf[8:12], crc)

	return buf
}

// ================================================================
// HMAC-SHA256 — paridade com intent_hash.rs
// ================================================================

// LoadHMACKey carrega a chave HMAC da variável de ambiente.
//
// ANTES: chave hardcoded no fonte (b"SECRET_KEY_DO_SISTEMA").
// AGORA: nunca toca o código.
//   export VORTEX_HMAC_KEY="$(openssl rand -hex 32)"
func LoadHMACKey() ([]byte, error) {
	key := os.Getenv("VORTEX_HMAC_KEY")
	if key == "" {
		return nil, errors.New("VORTEX_HMAC_KEY não definida no ambiente")
	}
	return []byte(key), nil
}

// SignPayload gera HMAC-SHA256 do payload — paridade com sign_payload() do Rust.
func SignPayload(payload, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifica HMAC-SHA256 em tempo constante.
// Paridade com verify_signature() do Rust (subtle::ConstantTimeEq).
// hmac.Equal() do Go já usa comparação em tempo constante internamente.
func VerifySignature(payload []byte, signatureHex string, secret []byte) error {
	provided, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("hex inválido: %w", err)
	}

	if len(provided) != 32 {
		return fmt.Errorf("tamanho de assinatura inválido: esperado 32 bytes, recebido %d", len(provided))
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	expected := mac.Sum(nil)

	// hmac.Equal usa comparação em tempo constante — proteção contra timing attack
	if !hmac.Equal(expected, provided) {
		return errors.New("assinatura inválida")
	}

	return nil
}

// ================================================================
// TESTES
// ================================================================

type testResult struct {
	name   string
	passed bool
	err    string
}

func check(name string, condition bool, msg string) testResult {
	if condition {
		fmt.Printf("[OK] %s\n", name)
		return testResult{name, true, ""}
	}
	fmt.Printf("[FAIL] %s: %s\n", name, msg)
	return testResult{name, false, msg}
}

func runTests() bool {
	results := []testResult{}
	testKey := []byte("chave-de-teste-nao-usar-em-producao")

	// ---- ParsePacket: caminho feliz ---------------------------

	payload := []byte("vortex:telemetria")
	buf := BuildPacket(0x0001, payload)
	pkt, err := ParsePacket(buf)
	results = append(results, check(
		"parse_valid_packet",
		err == nil && pkt.SyncWord == SyncWord && string(pkt.Payload) == string(payload),
		fmt.Sprintf("err=%v", err),
	))

	// ---- ParsePacket: sync word inválido ----------------------

	bad := make([]byte, len(buf))
	copy(bad, buf)
	bad[0] = 0xFF
	_, err = ParsePacket(bad)
	results = append(results, check(
		"parse_bad_sync_word",
		err != nil && errors.Is(err, ErrBadSyncWord),
		fmt.Sprintf("err=%v", err),
	))

	// ---- ParsePacket: CRC corrompido --------------------------

	badCRC := make([]byte, len(buf))
	copy(badCRC, buf)
	badCRC[8] ^= 0xFF
	_, err = ParsePacket(badCRC)
	results = append(results, check(
		"parse_crc_mismatch",
		err != nil,
		fmt.Sprintf("err=%v", err),
	))

	// ---- ParsePacket: buffer pequeno demais -------------------

	_, err = ParsePacket(buf[:5])
	results = append(results, check(
		"parse_buffer_too_small",
		errors.Is(err, ErrBufferTooSmall),
		fmt.Sprintf("err=%v", err),
	))

	// ---- ParsePacket: body gigante bloqueado antes de alocar --

	// Simula header com payload_len enorme mas buf curto
	giant := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint16(giant[0:2], SyncWord)
	binary.LittleEndian.PutUint32(giant[4:8], uint32(MaxPayload)+1)
	_, err = ParsePacket(giant)
	results = append(results, check(
		"parse_payload_too_large",
		errors.Is(err, ErrPayloadTooLarge),
		fmt.Sprintf("err=%v", err),
	))

	// ---- BuildPacket + ParsePacket: ida e volta ---------------

	original := []byte{0x9a, 0x99, 0xcc, 0x3d, 0x9a, 0x99, 0xcc, 0x3d}
	roundtrip := BuildPacket(0x0042, original)
	pkt2, err := ParsePacket(roundtrip)
	results = append(results, check(
		"build_parse_roundtrip",
		err == nil && string(pkt2.Payload) == string(original) && pkt2.Cmd == 0x0042,
		fmt.Sprintf("err=%v", err),
	))

	// ---- HMAC: assinatura válida ------------------------------

	sig := SignPayload(payload, testKey)
	err = VerifySignature(payload, sig, testKey)
	results = append(results, check(
		"hmac_valid_signature",
		err == nil,
		fmt.Sprintf("err=%v", err),
	))

	// ---- HMAC: chave errada -----------------------------------

	err = VerifySignature(payload, sig, []byte("chave-errada"))
	results = append(results, check(
		"hmac_wrong_key_rejected",
		err != nil,
		"deveria rejeitar",
	))

	// ---- HMAC: payload adulterado ----------------------------

	err = VerifySignature([]byte("adulterado"), sig, testKey)
	results = append(results, check(
		"hmac_tampered_payload_rejected",
		err != nil,
		"deveria rejeitar",
	))

	// ---- HMAC: hex inválido ----------------------------------

	err = VerifySignature(payload, "nao-e-hex!!", testKey)
	results = append(results, check(
		"hmac_invalid_hex_rejected",
		err != nil,
		"deveria rejeitar",
	))

	// ---- HMAC: tamanho errado --------------------------------

	err = VerifySignature(payload, "deadbeef", testKey) // 4 bytes, não 32
	results = append(results, check(
		"hmac_wrong_length_rejected",
		err != nil,
		"deveria rejeitar",
	))

	// ---- Resultado final -------------------------------------
	failed := 0
	for _, r := range results {
		if !r.passed {
			failed++
		}
	}
	return failed == 0
}

func main() {
	fmt.Println("\n=== Vortex DFS Gateway — Go ===\n")
	if runTests() {
		fmt.Println("\n✓ Todos os testes passaram.\n")
	} else {
		fmt.Println("\n✗ Há testes falhando.\n")
		os.Exit(1)
	}
}
