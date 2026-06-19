// "A sabedoria edificou a sua casa; preparou a sua mesa." — Provérbios 9:1–2
//
// Este módulo não busca atalhos. Cada fundamento é assentado com ordem:
//   — o arquivo abre com escrita explícita, não em modo `append` (que torna o seek inútil);
//   — o cabeçalho persiste o ponteiro de escrita para sobreviver a reinicializações;
//   — o alinhamento é guardado: a rotação só ocorre em fronteiras de registro;
//   — o flush é chamado, pois dados não gravados no disco não existem.

use std::fs::{File, OpenOptions};
use std::io::{Read, Result, Seek, SeekFrom, Write};
use std::path::Path;

/// Tamanho fixo de cada registro de alerta (bytes):
///   8 bytes → timestamp (u64, little-endian)
///   1 byte  → category_id (u8)
///   1 byte  → risk_level  (u8)
const RECORD_SIZE: u64 = 10;

/// Tamanho do cabeçalho binário no início do arquivo:
///   8 bytes → posição atual de escrita (u64, little-endian)
///
/// "A prudência habita com a sabedoria." — Provérbios 8:12
const HEADER_SIZE: u64 = 8;

/// Logger binário rotativo para alertas de segurança.
///
/// O arquivo é organizado assim:
///
///   [ cabeçalho: 8 bytes ][ registro 0 ][ registro 1 ] … [ registro N ]
///
/// Quando a posição de escrita alcança `data_capacity`, ela retorna ao
/// primeiro registro — sobrescrevendo os mais antigos — sem jamais
/// fragmentar um registro na fronteira da rotação.
pub struct BinaryRotaryLogger {
    file: File,
    /// Capacidade útil para dados (excluindo o cabeçalho), alinhada a RECORD_SIZE.
    data_capacity: u64,
    /// Posição de escrita atual dentro da área de dados (relativa ao fim do cabeçalho).
    write_offset: u64,
}

impl BinaryRotaryLogger {
    /// Abre ou cria o arquivo de log.
    ///
    /// `max_size` é a capacidade **total** desejada (cabeçalho + dados).
    /// Deve comportar pelo menos um registro além do cabeçalho.
    ///
    /// "Estabeleceu os fundamentos da terra. Estava ao seu lado como artífice." — Pv 8:29–30
    pub fn new<P: AsRef<Path>>(path: P, max_size: u64) -> Result<Self> {
        // Sabedoria: verificar antes de agir.
        if max_size <= HEADER_SIZE + RECORD_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "max_size insuficiente para comportar ao menos um registro",
            ));
        }

        // Capacidade de dados alinhada: apenas registros completos cabem.
        let raw_data = max_size - HEADER_SIZE;
        let data_capacity = (raw_data / RECORD_SIZE) * RECORD_SIZE;

        // Abrimos com `write` explícito — não `append`.
        // Em modo `append`, o SO ignora qualquer `seek` antes de escrever,
        // tornando a rotação impossível. A prudência escolhe a ferramenta certa.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let write_offset = Self::restore_or_init_header(&mut file, data_capacity)?;

        Ok(Self {
            file,
            data_capacity,
            write_offset,
        })
    }

    /// Grava um alerta no log.
    ///
    /// Se a posição de escrita atingiu o fim da área de dados,
    /// ela retorna ao início — sobrescrevendo o registro mais antigo.
    ///
    /// "Não transpasses os limites antigos que teus pais estabeleceram." — Pv 22:28
    pub fn write_alert(
        &mut self,
        timestamp: u64,
        category_id: u8,
        risk_level: u8,
    ) -> Result<()> {
        // Rotação no limite exato — nunca no meio de um registro.
        if self.write_offset >= self.data_capacity {
            self.write_offset = 0;
        }

        // Posição absoluta no arquivo: depois do cabeçalho.
        let abs_pos = HEADER_SIZE + self.write_offset;
        self.file.seek(SeekFrom::Start(abs_pos))?;

        // Registro de 10 bytes.
        let mut buffer = [0u8; RECORD_SIZE as usize];
        buffer[0..8].copy_from_slice(&timestamp.to_le_bytes());
        buffer[8] = category_id;
        buffer[9] = risk_level;

        self.file.write_all(&buffer)?;
        self.write_offset += RECORD_SIZE;

        // Persiste o novo offset no cabeçalho imediatamente.
        // "A casa da sabedoria é edificada; o descuidado a destrói." — adaptado de Pv 14:1
        self.persist_header()?;

        // Flush: dados no buffer do SO não são dados no disco.
        self.file.flush()?;

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Funções internas — os pilares ocultos que sustentam a casa.
    // -------------------------------------------------------------------------

    /// Lê o cabeçalho do arquivo para recuperar o offset de escrita.
    /// Se o arquivo for novo (tamanho zero), inicializa o cabeçalho com zero.
    fn restore_or_init_header(file: &mut File, data_capacity: u64) -> Result<u64> {
        let file_len = file.seek(SeekFrom::End(0))?;

        if file_len == 0 {
            // Arquivo recém-criado: escreve cabeçalho inicial.
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&0u64.to_le_bytes())?;
            file.flush()?;
            return Ok(0);
        }

        if file_len < HEADER_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "arquivo corrompido: cabeçalho incompleto",
            ));
        }

        // Lê os 8 bytes do cabeçalho.
        file.seek(SeekFrom::Start(0))?;
        let mut header_buf = [0u8; 8];
        file.read_exact(&mut header_buf)?;
        let stored_offset = u64::from_le_bytes(header_buf);

        // Valida o offset recuperado: deve ser múltiplo de RECORD_SIZE e dentro dos limites.
        if stored_offset % RECORD_SIZE != 0 || stored_offset > data_capacity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "arquivo corrompido: offset de escrita inválido no cabeçalho",
            ));
        }

        Ok(stored_offset)
    }

    /// Persiste o offset de escrita atual no cabeçalho do arquivo.
    fn persist_header(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.write_offset.to_le_bytes())?;
        Ok(())
    }
}
