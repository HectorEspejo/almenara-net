//! Compilador y evaluador de filtros BPF clásico para la captura de Almenara.
//!
//! El filtro `[capture].filter` se escribe con una gramática mínima inspirada en
//! tcpdump y se compila a instrucciones BPF clásico reales (equivalentes a
//! `struct sock_filter`) que el socket AF_PACKET adjunta con `SO_ATTACH_FILTER`.
//! El mismo programa se puede evaluar en espacio de usuario con
//! [BpfProgram::matches]: eso permite probar la compilación sin privilegios y
//! reutilizar el programa en el replay de ficheros pcap de una fase posterior.
//!
//! Gramática (tokens separados por espacios, sin distinguir mayúsculas):
//!
//! ```text
//!     expr   := or
//!     or     := and ("or" and)*            // también "||"
//!     and    := unary ("and" unary)*       // también "&&"
//!     unary  := "not" unary | "!" unary | "(" expr ")" | prim
//!     prim   := ["src"|"dst"] proto
//!             | ["src"|"dst"] "port" NUM
//!             | ["src"|"dst"] "portrange" NUM "-" NUM
//!             | ["src"|"dst"] "host" IPV4
//!             | ["src"|"dst"] "net" CIDR
//!     proto  := "tcp" | "udp" | "icmp" | "icmp6" | "ip" | "ip6" | "arp"
//! ```
//!
//! Sin calificador `src`/`dst`, `port`, `host` y `net` casan en el origen
//! **o** en el destino. Los calificadores sobre un protocolo (por ejemplo
//! `src tcp`) se aceptan por gramática pero no tienen efecto: el protocolo es
//! una propiedad del paquete completo, no de un extremo.
//!
//! Limitaciones asumidas y documentadas:
//!
//! - El filtro se aplica sobre la trama Ethernet completa (EN10MB) y solo
//!   entiende IPv4 e IPv6 con cabecera fija. Los puertos de IPv6 se buscan a
//!   partir de la cabecera fija (offset 54): con cabeceras de extensión el
//!   filtro no casa por puerto y es el parser quien resuelve el paquete.
//! - `host` y `net` solo admiten IPv4, tal y como fija la gramática.
//! - No se comprueba el bit de fragmentación: un fragmento no inicial puede
//!   casar por puerto aunque sus puertos no sean válidos; el parser lo descarta
//!   después como error ignorable.

// La captura en vivo de F3 solo usa el compilador y attach; el intérprete
// (matches) y la inspección de instrucciones se usan en las pruebas y se
// reutilizarán en el replay de ficheros pcap de una fase posterior. Al ser un
// binario, el análisis de código muerto los marcaría fuera de los tests.
#![allow(dead_code)]

use std::fmt;
use std::os::fd::RawFd;

/// Códigos de instrucción del BPF clásico (`linux/filter.h`).
///
/// Se definen aquí, y no se toman de libc, para que el compilador y el
/// intérprete sean independientes del enlace con el sistema; el programa se
/// convierte a `libc::sock_filter` solo al adjuntarlo.
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_MSH: u16 = 0xa0;

const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_XOR: u16 = 0xa0;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;
const BPF_A: u16 = 0x10;

const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

/// Máscaras de decodificación de una instrucción BPF clásica.
const BPF_CLASE_MASCARA: u16 = 0x07;
const BPF_TAMANO_MASCARA: u16 = 0x18;
const BPF_MODO_MASCARA: u16 = 0xe0;
const BPF_OPERACION_MASCARA: u16 = 0xf0;
const BPF_RETORNO_MASCARA: u16 = 0x18;

/// Número de palabras de memoria temporal del intérprete (`BPF_MEMWORDS`).
const BPF_MEMWORDS: usize = 16;
/// Longitud máxima de un programa filtro clásico (`BPF_MAXINSNS`).
const BPF_MAXINSNS: usize = 4096;

/// Desplazamientos fijos dentro de la trama Ethernet (EN10MB).
const OFFSET_ETHERTYPE: u32 = 12;
const OFFSET_IPV4_IHL: u32 = 14;
const OFFSET_IPV6_SIGUIENTE: u32 = 20;
const OFFSET_IPV4_PROTOCOLO: u32 = 23;
const OFFSET_IPV4_ORIGEN: u32 = 26;
const OFFSET_IPV4_DESTINO: u32 = 30;
const OFFSET_PUERTO_ORIGEN_IPV4: u32 = 14;
const OFFSET_PUERTO_DESTINO_IPV4: u32 = 16;
const OFFSET_PUERTO_ORIGEN_IPV6: u32 = 54;
const OFFSET_PUERTO_DESTINO_IPV6: u32 = 56;

/// EtherTypes que conoce el filtro.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_ARP: u16 = 0x0806;

/// Números de protocolo IP que conoce el filtro.
const PROTOCOLO_ICMP: u8 = 1;
const PROTOCOLO_TCP: u8 = 6;
const PROTOCOLO_UDP: u8 = 17;
const PROTOCOLO_ICMPV6: u8 = 58;

/// Una instrucción BPF clásica, equivalente a `struct sock_filter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    /// Código de operación (clase, tamaño, modo y operación).
    pub code: u16,
    /// Salto si la condición se cumple (solo en saltos condicionales).
    pub jt: u8,
    /// Salto si la condición no se cumple (solo en saltos condicionales).
    pub jf: u8,
    /// Constante u operando de la instrucción.
    pub k: u32,
}

/// Programa BPF clásico ya compilado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfProgram {
    instrucciones: Vec<BpfInsn>,
}

/// Error de compilación de un filtro BPF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfError {
    /// Mensaje legible en castellano.
    pub message: String,
}

impl BpfError {
    fn nuevo(mensaje: impl Into<String>) -> Self {
        Self {
            message: mensaje.into(),
        }
    }
}

impl fmt::Display for BpfError {
    fn fmt(&self, formateador: &mut fmt::Formatter<'_>) -> fmt::Result {
        formateador.write_str(&self.message)
    }
}

impl std::error::Error for BpfError {}

impl BpfProgram {
    /// Compila una expresión de filtro a instrucciones BPF clásico.
    pub fn compile(expresion: &str) -> Result<Self, BpfError> {
        compile(expresion)
    }

    /// Instrucciones del programa, listas para adjuntar al socket.
    pub fn instructions(&self) -> &[BpfInsn] {
        &self.instrucciones
    }

    /// Indica si el programa no tiene instrucciones (nunca tras compilar).
    pub fn is_empty(&self) -> bool {
        self.instrucciones.is_empty()
    }

    /// Adjunta el programa al socket indicado con `SO_ATTACH_FILTER`.
    ///
    /// Un programa vacío no se adjunta y se considera correcto (no hay filtro).
    pub fn attach(&self, fd: RawFd) -> std::io::Result<()> {
        if self.instrucciones.is_empty() {
            return Ok(());
        }
        let mut filtros: Vec<libc::sock_filter> = self
            .instrucciones
            .iter()
            .map(|instruccion| libc::sock_filter {
                code: instruccion.code,
                jt: instruccion.jt,
                jf: instruccion.jf,
                k: instruccion.k,
            })
            .collect();
        let programa = libc::sock_fprog {
            len: u16::try_from(filtros.len()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "el programa BPF es demasiado largo para el kernel",
                )
            })?,
            filter: filtros.as_mut_ptr(),
        };
        let resultado = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                std::ptr::addr_of!(programa).cast::<libc::c_void>(),
                std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        };
        if resultado < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Evalúa el programa sobre una trama Ethernet completa.
    ///
    /// Es un intérprete de BPF clásico que cubre todos los opcodes que genera
    /// [compile] (y también los habituales de tcpdump): cargas absolutas,
    /// indirectas, inmediatas, longitud y memoria; aritmética; saltos y
    /// retorno. Una carga fuera de la trama, una división por cero o un opcode
    /// desconocido hacen que la trama no case, igual que en el kernel. Nunca
    /// hace panic.
    pub fn matches(&self, trama: &[u8]) -> bool {
        let mut acumulador: u32 = 0;
        let mut indice_x: u32 = 0;
        let mut memoria = [0u32; BPF_MEMWORDS];
        let mut pc: usize = 0;
        let mut pasos: usize = 0;
        let limite_pasos = self
            .instrucciones
            .len()
            .saturating_mul(4)
            .saturating_add(64);
        loop {
            let Some(instruccion) = self.instrucciones.get(pc) else {
                return false;
            };
            pasos += 1;
            if pasos > limite_pasos {
                return false;
            }
            let clase = instruccion.code & BPF_CLASE_MASCARA;
            let tamano = instruccion.code & BPF_TAMANO_MASCARA;
            let modo = instruccion.code & BPF_MODO_MASCARA;
            let mut siguiente = pc + 1;
            match clase {
                BPF_LD => {
                    acumulador = match modo {
                        BPF_IMM => {
                            if tamano != BPF_W {
                                return false;
                            }
                            instruccion.k
                        }
                        BPF_ABS => match leer(trama, u64::from(instruccion.k), tamano) {
                            Some(valor) => valor,
                            None => return false,
                        },
                        BPF_IND => {
                            let desplazamiento = u64::from(indice_x) + u64::from(instruccion.k);
                            match leer(trama, desplazamiento, tamano) {
                                Some(valor) => valor,
                                None => return false,
                            }
                        }
                        BPF_MEM => match memoria.get(instruccion.k as usize) {
                            Some(valor) => *valor,
                            None => return false,
                        },
                        BPF_LEN => {
                            if tamano != BPF_W {
                                return false;
                            }
                            u32::try_from(trama.len()).unwrap_or(u32::MAX)
                        }
                        _ => return false,
                    };
                }
                BPF_LDX => {
                    indice_x = match modo {
                        BPF_IMM => {
                            if tamano != BPF_W {
                                return false;
                            }
                            instruccion.k
                        }
                        BPF_MEM => match memoria.get(instruccion.k as usize) {
                            Some(valor) => *valor,
                            None => return false,
                        },
                        BPF_LEN => {
                            if tamano != BPF_W {
                                return false;
                            }
                            u32::try_from(trama.len()).unwrap_or(u32::MAX)
                        }
                        BPF_MSH => {
                            if tamano != BPF_B {
                                return false;
                            }
                            match leer(trama, u64::from(instruccion.k), BPF_B) {
                                Some(valor) => 4 * (valor & 0x0f),
                                None => return false,
                            }
                        }
                        _ => return false,
                    };
                }
                BPF_ST => {
                    let Some(casilla) = memoria.get_mut(instruccion.k as usize) else {
                        return false;
                    };
                    *casilla = acumulador;
                }
                BPF_STX => {
                    let Some(casilla) = memoria.get_mut(instruccion.k as usize) else {
                        return false;
                    };
                    *casilla = indice_x;
                }
                BPF_ALU => {
                    let operacion = instruccion.code & BPF_OPERACION_MASCARA;
                    if operacion == BPF_NEG {
                        if (instruccion.code & BPF_X) != 0 {
                            return false;
                        }
                        acumulador = acumulador.wrapping_neg();
                    } else {
                        let operando = if (instruccion.code & BPF_X) != 0 {
                            indice_x
                        } else {
                            instruccion.k
                        };
                        acumulador = match operacion {
                            BPF_ADD => acumulador.wrapping_add(operando),
                            BPF_SUB => acumulador.wrapping_sub(operando),
                            BPF_MUL => acumulador.wrapping_mul(operando),
                            BPF_DIV => {
                                if operando == 0 {
                                    return false;
                                }
                                acumulador / operando
                            }
                            BPF_OR => acumulador | operando,
                            BPF_AND => acumulador & operando,
                            BPF_LSH => acumulador.wrapping_shl(operando),
                            BPF_RSH => acumulador.wrapping_shr(operando),
                            BPF_MOD => {
                                if operando == 0 {
                                    return false;
                                }
                                acumulador % operando
                            }
                            BPF_XOR => acumulador ^ operando,
                            _ => return false,
                        };
                    }
                }
                BPF_JMP => {
                    let operacion = instruccion.code & BPF_OPERACION_MASCARA;
                    if operacion == BPF_JA {
                        siguiente = pc + 1 + instruccion.k as usize;
                    } else {
                        let operando = if (instruccion.code & BPF_X) != 0 {
                            indice_x
                        } else {
                            instruccion.k
                        };
                        let condicion = match operacion {
                            BPF_JEQ => acumulador == operando,
                            BPF_JGT => acumulador > operando,
                            BPF_JGE => acumulador >= operando,
                            BPF_JSET => (acumulador & operando) != 0,
                            _ => return false,
                        };
                        let salto = if condicion {
                            instruccion.jt
                        } else {
                            instruccion.jf
                        };
                        siguiente = pc + 1 + usize::from(salto);
                    }
                }
                BPF_RET => {
                    return match instruccion.code & BPF_RETORNO_MASCARA {
                        BPF_K => instruccion.k != 0,
                        BPF_A => acumulador != 0,
                        _ => false,
                    };
                }
                BPF_MISC => match instruccion.code {
                    codigo if codigo == (BPF_MISC | BPF_TAX) => indice_x = acumulador,
                    codigo if codigo == (BPF_MISC | BPF_TXA) => acumulador = indice_x,
                    _ => return false,
                },
                _ => return false,
            }
            pc = siguiente;
        }
    }
}

/// Lee un entero big-endian de la trama; `None` si la carga se sale de ella.
fn leer(trama: &[u8], inicio: u64, tamano: u16) -> Option<u32> {
    let bytes = match tamano {
        BPF_W => 4usize,
        BPF_H => 2,
        BPF_B => 1,
        _ => return None,
    };
    let inicio = usize::try_from(inicio).ok()?;
    let fin = inicio.checked_add(bytes)?;
    let datos = trama.get(inicio..fin)?;
    let mut valor = 0u32;
    for byte in datos {
        valor = (valor << 8) | u32::from(*byte);
    }
    Some(valor)
}

// ---------------------------------------------------------------------------
// Compilación: gramática, análisis y ensamblado
// ---------------------------------------------------------------------------

/// Compila una expresión de filtro a un programa BPF clásico.
///
/// La cadena vacía (o solo espacios) es un error: el caso "sin filtro" lo
/// gestiona `Capture` antes de llamar aquí.
pub fn compile(expresion: &str) -> Result<BpfProgram, BpfError> {
    let mut analizador = Analizador::nuevo(expresion);
    if analizador.esta_vacio() {
        return Err(BpfError::nuevo("el filtro BPF está vacío"));
    }
    let arbol = analizador.parsear()?;

    let mut ensamblador = Ensamblador::nuevo();
    let aceptar = ensamblador.nueva_etiqueta();
    let rechazar = ensamblador.nueva_etiqueta();
    ensamblador.compilar(&arbol, aceptar, rechazar)?;
    ensamblador.marcar(aceptar)?;
    ensamblador.emitir(retorno(BPF_K, u32::MAX));
    ensamblador.marcar(rechazar)?;
    ensamblador.emitir(retorno(BPF_K, 0));

    Ok(BpfProgram {
        instrucciones: ensamblador.resolver()?,
    })
}

/// Calificador de extremo de una primitiva.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Calificador {
    /// Casa en origen o destino.
    Cualquiera,
    /// Solo en el origen.
    Origen,
    /// Solo en el destino.
    Destino,
}

/// Comprobación de puerto que emite una primitiva.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComprobacionPuerto {
    /// Puerto exacto.
    Puerto(u16),
    /// Rango inclusivo.
    Rango(u16, u16),
}

/// Protocolo reconocido por la gramática.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocolo {
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    Ip,
    Ip6,
    Arp,
}

/// Primitiva del filtro.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Primitiva {
    Protocolo(Protocolo),
    Puerto {
        calificador: Calificador,
        puerto: u16,
    },
    RangoPuertos {
        calificador: Calificador,
        desde: u16,
        hasta: u16,
    },
    Host {
        calificador: Calificador,
        ip: u32,
    },
    Red {
        calificador: Calificador,
        red: u32,
        mascara: u32,
    },
}

/// Árbol sintáctico de una expresión de filtro.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expresion {
    Primitiva(Primitiva),
    Y(Box<Expresion>, Box<Expresion>),
    O(Box<Expresion>, Box<Expresion>),
    No(Box<Expresion>),
}

/// Analizador descendente recursivo de la gramática del filtro.
struct Analizador {
    tokens: Vec<String>,
    posicion: usize,
}

impl Analizador {
    fn nuevo(expresion: &str) -> Self {
        Self {
            tokens: tokenizar(expresion),
            posicion: 0,
        }
    }

    fn esta_vacio(&self) -> bool {
        self.tokens.is_empty()
    }

    fn ver(&self) -> Option<&str> {
        self.tokens.get(self.posicion).map(String::as_str)
    }

    fn consumir(&mut self) -> Option<String> {
        let token = self.tokens.get(self.posicion).cloned();
        if token.is_some() {
            self.posicion += 1;
        }
        token
    }

    fn siguiente_token(&mut self, descripcion: &str) -> Result<String, BpfError> {
        self.consumir().ok_or_else(|| {
            BpfError::nuevo(format!(
                "se esperaba {descripcion} al final de la expresión BPF"
            ))
        })
    }

    fn parsear(&mut self) -> Result<Expresion, BpfError> {
        let expresion = self.parsear_o()?;
        if let Some(sobrante) = self.ver() {
            return Err(BpfError::nuevo(format!(
                "sobra «{sobrante}» al final de la expresión BPF"
            )));
        }
        Ok(expresion)
    }

    fn parsear_o(&mut self) -> Result<Expresion, BpfError> {
        let mut izquierda = self.parsear_y()?;
        while matches!(self.ver(), Some("or" | "||")) {
            self.posicion += 1;
            let derecha = self.parsear_y()?;
            izquierda = Expresion::O(Box::new(izquierda), Box::new(derecha));
        }
        Ok(izquierda)
    }

    fn parsear_y(&mut self) -> Result<Expresion, BpfError> {
        let mut izquierda = self.parsear_unario()?;
        while matches!(self.ver(), Some("and" | "&&")) {
            self.posicion += 1;
            let derecha = self.parsear_unario()?;
            izquierda = Expresion::Y(Box::new(izquierda), Box::new(derecha));
        }
        Ok(izquierda)
    }

    fn parsear_unario(&mut self) -> Result<Expresion, BpfError> {
        let token = match self.consumir() {
            Some(token) => token,
            None => return Err(BpfError::nuevo("se esperaba una expresión de filtro BPF")),
        };
        match token.as_str() {
            "not" | "!" => Ok(Expresion::No(Box::new(self.parsear_unario()?))),
            "and" | "or" | "&&" | "||" => Err(BpfError::nuevo(format!(
                "se esperaba una expresión antes de «{token}» en el filtro BPF"
            ))),
            "(" => {
                let interna = self.parsear_o()?;
                match self.consumir().as_deref() {
                    Some(")") => Ok(interna),
                    _ => Err(BpfError::nuevo(
                        "falta el paréntesis de cierre de la expresión BPF",
                    )),
                }
            }
            ")" => Err(BpfError::nuevo(
                "paréntesis de cierre sin abrir en la expresión BPF",
            )),
            _ => self.parsear_primitiva(token),
        }
    }

    fn parsear_primitiva(&mut self, token: String) -> Result<Expresion, BpfError> {
        if let Some(protocolo) = protocolo_desde(&token) {
            return Ok(Expresion::Primitiva(Primitiva::Protocolo(protocolo)));
        }
        let calificador = match token.as_str() {
            "src" => Calificador::Origen,
            "dst" => Calificador::Destino,
            _ => return self.parsear_primitiva_con(Calificador::Cualquiera, token),
        };
        let siguiente = self.siguiente_token(
            "un protocolo, «port», «portrange», «host» o «net» después de «src» o «dst»",
        )?;
        if let Some(protocolo) = protocolo_desde(&siguiente) {
            // El calificador no aplica al protocolo; se acepta por gramática.
            return Ok(Expresion::Primitiva(Primitiva::Protocolo(protocolo)));
        }
        self.parsear_primitiva_con(calificador, siguiente)
    }

    fn parsear_primitiva_con(
        &mut self,
        calificador: Calificador,
        token: String,
    ) -> Result<Expresion, BpfError> {
        match token.as_str() {
            "port" => {
                let puerto = self.parsear_puerto()?;
                Ok(Expresion::Primitiva(Primitiva::Puerto {
                    calificador,
                    puerto,
                }))
            }
            "portrange" => {
                let (desde, hasta) = self.parsear_rango()?;
                Ok(Expresion::Primitiva(Primitiva::RangoPuertos {
                    calificador,
                    desde,
                    hasta,
                }))
            }
            "host" => {
                let texto = self.siguiente_token("una dirección IPv4 después de «host»")?;
                let ip = ipv4_desde(&texto)?;
                Ok(Expresion::Primitiva(Primitiva::Host { calificador, ip }))
            }
            "net" => {
                let texto =
                    self.siguiente_token("una red CIDR (por ejemplo 10.0.0.0/8) después de «net»")?;
                let (red, mascara) = red_desde(&texto)?;
                Ok(Expresion::Primitiva(Primitiva::Red {
                    calificador,
                    red,
                    mascara,
                }))
            }
            _ => Err(BpfError::nuevo(format!(
                "token no reconocido en el filtro BPF: «{token}»"
            ))),
        }
    }

    fn parsear_puerto(&mut self) -> Result<u16, BpfError> {
        let texto = self.siguiente_token("un número de puerto después de «port»")?;
        numero_puerto(&texto)
    }

    fn parsear_rango(&mut self) -> Result<(u16, u16), BpfError> {
        let token = self.siguiente_token("un rango de puertos después de «portrange»")?;
        let (desde, hasta) = match token.split_once('-') {
            Some((desde, hasta)) => (numero_puerto(desde)?, numero_puerto(hasta)?),
            None => {
                let desde = numero_puerto(&token)?;
                let guion = self.siguiente_token("«-» entre los dos puertos del rango")?;
                if guion != "-" {
                    return Err(BpfError::nuevo(format!(
                        "se esperaba «-» en el rango de puertos: «{guion}»"
                    )));
                }
                let hasta = self.siguiente_token("el puerto final del rango")?;
                (desde, numero_puerto(&hasta)?)
            }
        };
        if desde > hasta {
            return Err(BpfError::nuevo(format!(
                "rango de puertos invertido: {desde}-{hasta}"
            )));
        }
        Ok((desde, hasta))
    }
}

/// Divide la expresión en tokens; los paréntesis son tokens por sí mismos.
fn tokenizar(expresion: &str) -> Vec<String> {
    fn cerrar(tokens: &mut Vec<String>, actual: &mut String) {
        if !actual.is_empty() {
            tokens.push(std::mem::take(actual));
        }
    }
    let mut tokens = Vec::new();
    let mut actual = String::new();
    for caracter in expresion.chars() {
        if caracter.is_whitespace() {
            cerrar(&mut tokens, &mut actual);
        } else if caracter == '(' || caracter == ')' {
            cerrar(&mut tokens, &mut actual);
            tokens.push(caracter.to_string());
        } else {
            actual.push(caracter);
        }
    }
    cerrar(&mut tokens, &mut actual);
    tokens
        .into_iter()
        .map(|token| token.to_lowercase())
        .collect()
}

/// Reconoce una palabra clave de protocolo.
fn protocolo_desde(token: &str) -> Option<Protocolo> {
    match token {
        "tcp" => Some(Protocolo::Tcp),
        "udp" => Some(Protocolo::Udp),
        "icmp" => Some(Protocolo::Icmp),
        "icmp6" => Some(Protocolo::Icmp6),
        "ip" => Some(Protocolo::Ip),
        "ip6" => Some(Protocolo::Ip6),
        "arp" => Some(Protocolo::Arp),
        _ => None,
    }
}

/// Convierte un token en un número de puerto válido.
fn numero_puerto(texto: &str) -> Result<u16, BpfError> {
    let valor: u32 = texto
        .parse()
        .map_err(|_| BpfError::nuevo(format!("se esperaba un número de puerto: «{texto}»")))?;
    u16::try_from(valor)
        .map_err(|_| BpfError::nuevo(format!("puerto fuera de rango (0-65535): {valor}")))
}

/// Parsea una dirección IPv4 y la devuelve como entero big-endian.
fn ipv4_desde(texto: &str) -> Result<u32, BpfError> {
    let direccion: std::net::Ipv4Addr = texto
        .parse()
        .map_err(|_| BpfError::nuevo(format!("dirección IPv4 no válida: «{texto}»")))?;
    Ok(u32::from_be_bytes(direccion.octets()))
}

/// Parsea una red CIDR y devuelve (red, máscara) como enteros big-endian.
fn red_desde(texto: &str) -> Result<(u32, u32), BpfError> {
    let (direccion, prefijo) = match texto.split_once('/') {
        Some((direccion, prefijo)) => (direccion, Some(prefijo)),
        None => (texto, None),
    };
    let ip = ipv4_desde(direccion)?;
    let prefijo: u32 = match prefijo {
        Some(texto_prefijo) => texto_prefijo
            .parse()
            .map_err(|_| BpfError::nuevo(format!("prefijo CIDR no válido: «{texto_prefijo}»")))?,
        None => 32,
    };
    if prefijo > 32 {
        return Err(BpfError::nuevo(format!(
            "prefijo CIDR fuera de rango (0-32): {prefijo}"
        )));
    }
    let mascara = if prefijo == 0 {
        0
    } else {
        u32::MAX << (32 - prefijo)
    };
    Ok((ip & mascara, mascara))
}

// ---------------------------------------------------------------------------
// Ensamblado: etiquetas y generación de instrucciones
// ---------------------------------------------------------------------------

/// Elemento del programa en ensamblaje: instrucción concreta o salto a etiqueta.
enum Elemento {
    Instruccion(BpfInsn),
    Salto(usize),
}

/// Ensamblador con etiquetas simbólicas; resuelve los saltos al final.
///
/// Todos los saltos que genera la compilación van hacia delante, por lo que se
/// emiten como `BPF_JA` con desplazamiento de 32 bits. Los saltos
/// condicionales se encapsulan en la secuencia
/// `condicional; JA verdadero; JA falso` con `jt = 0` y `jf = 1`, así nunca
/// se supera el límite de 8 bits de `jt`/`jf`.
struct Ensamblador {
    elementos: Vec<Elemento>,
    etiquetas: Vec<Option<usize>>,
}

impl Ensamblador {
    fn nuevo() -> Self {
        Self {
            elementos: Vec::new(),
            etiquetas: Vec::new(),
        }
    }

    fn nueva_etiqueta(&mut self) -> usize {
        let etiqueta = self.etiquetas.len();
        self.etiquetas.push(None);
        etiqueta
    }

    fn marcar(&mut self, etiqueta: usize) -> Result<(), BpfError> {
        let posicion = self.elementos.len();
        let Some(casilla) = self.etiquetas.get_mut(etiqueta) else {
            return Err(BpfError::nuevo(
                "etiqueta interna desconocida en el filtro BPF",
            ));
        };
        if casilla.is_some() {
            return Err(BpfError::nuevo(
                "etiqueta interna duplicada en el filtro BPF",
            ));
        }
        *casilla = Some(posicion);
        Ok(())
    }

    fn emitir(&mut self, instruccion: BpfInsn) {
        self.elementos.push(Elemento::Instruccion(instruccion));
    }

    fn emitir_salto(&mut self, etiqueta: usize) {
        self.elementos.push(Elemento::Salto(etiqueta));
    }

    /// Emite "si se cumple la condición salta a `si`, si no a `no`".
    fn emitir_condicional(&mut self, operacion: u16, k: u32, si: usize, no: usize) {
        self.emitir(condicional(operacion, k));
        self.emitir_salto(si);
        self.emitir_salto(no);
    }

    fn compilar(&mut self, expresion: &Expresion, si: usize, no: usize) -> Result<(), BpfError> {
        match expresion {
            Expresion::Primitiva(primitiva) => self.compilar_primitiva(primitiva, si, no),
            Expresion::Y(izquierda, derecha) => {
                let intermedia = self.nueva_etiqueta();
                self.compilar(izquierda, intermedia, no)?;
                self.marcar(intermedia)?;
                self.compilar(derecha, si, no)
            }
            Expresion::O(izquierda, derecha) => {
                let intermedia = self.nueva_etiqueta();
                self.compilar(izquierda, si, intermedia)?;
                self.marcar(intermedia)?;
                self.compilar(derecha, si, no)
            }
            Expresion::No(interna) => self.compilar(interna, no, si),
        }
    }

    fn compilar_primitiva(
        &mut self,
        primitiva: &Primitiva,
        si: usize,
        no: usize,
    ) -> Result<(), BpfError> {
        match primitiva {
            Primitiva::Protocolo(protocolo) => match protocolo {
                Protocolo::Ip => {
                    self.comprobar_ethertype(ETHERTYPE_IPV4, si, no);
                    Ok(())
                }
                Protocolo::Ip6 => {
                    self.comprobar_ethertype(ETHERTYPE_IPV6, si, no);
                    Ok(())
                }
                Protocolo::Arp => {
                    self.comprobar_ethertype(ETHERTYPE_ARP, si, no);
                    Ok(())
                }
                Protocolo::Icmp => self.comprobar_protocolo(
                    ETHERTYPE_IPV4,
                    OFFSET_IPV4_PROTOCOLO,
                    PROTOCOLO_ICMP,
                    si,
                    no,
                ),
                Protocolo::Icmp6 => self.comprobar_protocolo(
                    ETHERTYPE_IPV6,
                    OFFSET_IPV6_SIGUIENTE,
                    PROTOCOLO_ICMPV6,
                    si,
                    no,
                ),
                Protocolo::Tcp => self.comprobar_transporte(PROTOCOLO_TCP, si, no),
                Protocolo::Udp => self.comprobar_transporte(PROTOCOLO_UDP, si, no),
            },
            Primitiva::Puerto {
                calificador,
                puerto,
            } => self.compilar_puerto(*calificador, *puerto, si, no),
            Primitiva::RangoPuertos {
                calificador,
                desde,
                hasta,
            } => self.compilar_rango_puertos(*calificador, *desde, *hasta, si, no),
            Primitiva::Host { calificador, ip } => {
                self.compilar_direccion(*calificador, *ip, u32::MAX, si, no)
            }
            Primitiva::Red {
                calificador,
                red,
                mascara,
            } => self.compilar_direccion(*calificador, *red, *mascara, si, no),
        }
    }

    /// Comprueba el EtherType de la trama.
    fn comprobar_ethertype(&mut self, ethertype: u16, si: usize, no: usize) {
        self.emitir(cargar_abs(BPF_H, OFFSET_ETHERTYPE));
        self.emitir_condicional(BPF_JEQ, u32::from(ethertype), si, no);
    }

    /// Comprueba un EtherType concreto y un protocolo de la cabecera IP fija.
    fn comprobar_protocolo(
        &mut self,
        ethertype: u16,
        desplazamiento: u32,
        protocolo: u8,
        si: usize,
        no: usize,
    ) -> Result<(), BpfError> {
        let cabecera = self.nueva_etiqueta();
        self.comprobar_ethertype(ethertype, cabecera, no);
        self.marcar(cabecera)?;
        self.emitir(cargar_abs(BPF_B, desplazamiento));
        self.emitir_condicional(BPF_JEQ, u32::from(protocolo), si, no);
        Ok(())
    }

    /// Comprueba TCP o UDP tanto en IPv4 como en IPv6.
    fn comprobar_transporte(
        &mut self,
        protocolo: u8,
        si: usize,
        no: usize,
    ) -> Result<(), BpfError> {
        let ipv4 = self.nueva_etiqueta();
        let ipv6 = self.nueva_etiqueta();
        self.despachar_familias(ipv4, ipv6, no)?;
        self.marcar(ipv4)?;
        self.emitir(cargar_abs(BPF_B, OFFSET_IPV4_PROTOCOLO));
        self.emitir_condicional(BPF_JEQ, u32::from(protocolo), si, no);
        self.marcar(ipv6)?;
        self.emitir(cargar_abs(BPF_B, OFFSET_IPV6_SIGUIENTE));
        self.emitir_condicional(BPF_JEQ, u32::from(protocolo), si, no);
        Ok(())
    }

    /// Separa el flujo según IPv4/IPv6 y salta a las etiquetas indicadas.
    fn despachar_familias(&mut self, ipv4: usize, ipv6: usize, no: usize) -> Result<(), BpfError> {
        let siguiente = self.nueva_etiqueta();
        self.emitir(cargar_abs(BPF_H, OFFSET_ETHERTYPE));
        self.emitir_condicional(BPF_JEQ, u32::from(ETHERTYPE_IPV4), ipv4, siguiente);
        self.marcar(siguiente)?;
        self.emitir_condicional(BPF_JEQ, u32::from(ETHERTYPE_IPV6), ipv6, no);
        Ok(())
    }

    /// Comprueba que la cabecera fija sea TCP o UDP y salta al bloque de puertos.
    fn despachar_protocolo(
        &mut self,
        ipv4: bool,
        destino: usize,
        no: usize,
    ) -> Result<(), BpfError> {
        let siguiente = self.nueva_etiqueta();
        let desplazamiento = if ipv4 {
            OFFSET_IPV4_PROTOCOLO
        } else {
            OFFSET_IPV6_SIGUIENTE
        };
        self.emitir(cargar_abs(BPF_B, desplazamiento));
        self.emitir_condicional(BPF_JEQ, u32::from(PROTOCOLO_TCP), destino, siguiente);
        self.marcar(siguiente)?;
        self.emitir_condicional(BPF_JEQ, u32::from(PROTOCOLO_UDP), destino, no);
        Ok(())
    }

    /// Prepara el registro X con la longitud de la cabecera IPv4 (MSH).
    fn cargar_longitud_ipv4(&mut self) {
        self.emitir(cargar_msh(OFFSET_IPV4_IHL));
    }

    fn compilar_puerto(
        &mut self,
        calificador: Calificador,
        puerto: u16,
        si: usize,
        no: usize,
    ) -> Result<(), BpfError> {
        let ipv4 = self.nueva_etiqueta();
        let ipv6 = self.nueva_etiqueta();
        let protocolo4 = self.nueva_etiqueta();
        let protocolo6 = self.nueva_etiqueta();
        self.despachar_familias(ipv4, ipv6, no)?;
        self.marcar(ipv4)?;
        self.despachar_protocolo(true, protocolo4, no)?;
        self.marcar(protocolo4)?;
        self.cargar_longitud_ipv4();
        self.comprobar_puerto(
            calificador,
            true,
            OFFSET_PUERTO_ORIGEN_IPV4,
            OFFSET_PUERTO_DESTINO_IPV4,
            ComprobacionPuerto::Puerto(puerto),
            si,
            no,
        )?;
        self.marcar(ipv6)?;
        self.despachar_protocolo(false, protocolo6, no)?;
        self.marcar(protocolo6)?;
        self.comprobar_puerto(
            calificador,
            false,
            OFFSET_PUERTO_ORIGEN_IPV6,
            OFFSET_PUERTO_DESTINO_IPV6,
            ComprobacionPuerto::Puerto(puerto),
            si,
            no,
        )?;
        Ok(())
    }

    /// Comprueba un puerto exacto o un rango en uno o en los dos extremos.
    #[allow(clippy::too_many_arguments)]
    fn comprobar_puerto(
        &mut self,
        calificador: Calificador,
        indirecto: bool,
        origen: u32,
        destino: u32,
        comprobacion: ComprobacionPuerto,
        si: usize,
        no: usize,
    ) -> Result<(), BpfError> {
        let comprobar = |ensamblador: &mut Self,
                         desplazamiento: u32,
                         acierto: usize,
                         fallo: usize|
         -> Result<(), BpfError> {
            ensamblador.emitir(cargar_puerto(indirecto, desplazamiento));
            match comprobacion {
                ComprobacionPuerto::Puerto(puerto) => {
                    ensamblador.emitir_condicional(BPF_JEQ, u32::from(puerto), acierto, fallo);
                }
                ComprobacionPuerto::Rango(desde, hasta) => {
                    let en_rango = ensamblador.nueva_etiqueta();
                    ensamblador.emitir_condicional(BPF_JGE, u32::from(desde), en_rango, fallo);
                    ensamblador.marcar(en_rango)?;
                    // JGT invertido: si el puerto es mayor que el máximo, falla.
                    ensamblador.emitir_condicional(BPF_JGT, u32::from(hasta), fallo, acierto);
                }
            }
            Ok(())
        };
        match calificador {
            Calificador::Origen => comprobar(self, origen, si, no),
            Calificador::Destino => comprobar(self, destino, si, no),
            Calificador::Cualquiera => {
                let segundo = self.nueva_etiqueta();
                comprobar(self, origen, si, segundo)?;
                self.marcar(segundo)?;
                comprobar(self, destino, si, no)
            }
        }
    }

    fn compilar_rango_puertos(
        &mut self,
        calificador: Calificador,
        desde: u16,
        hasta: u16,
        si: usize,
        no: usize,
    ) -> Result<(), BpfError> {
        let ipv4 = self.nueva_etiqueta();
        let ipv6 = self.nueva_etiqueta();
        let protocolo4 = self.nueva_etiqueta();
        let protocolo6 = self.nueva_etiqueta();
        self.despachar_familias(ipv4, ipv6, no)?;
        self.marcar(ipv4)?;
        self.despachar_protocolo(true, protocolo4, no)?;
        self.marcar(protocolo4)?;
        self.cargar_longitud_ipv4();
        self.comprobar_puerto(
            calificador,
            true,
            OFFSET_PUERTO_ORIGEN_IPV4,
            OFFSET_PUERTO_DESTINO_IPV4,
            ComprobacionPuerto::Rango(desde, hasta),
            si,
            no,
        )?;
        self.marcar(ipv6)?;
        self.despachar_protocolo(false, protocolo6, no)?;
        self.marcar(protocolo6)?;
        self.comprobar_puerto(
            calificador,
            false,
            OFFSET_PUERTO_ORIGEN_IPV6,
            OFFSET_PUERTO_DESTINO_IPV6,
            ComprobacionPuerto::Rango(desde, hasta),
            si,
            no,
        )?;
        Ok(())
    }

    /// Comprueba una dirección IPv4 o una red contra el origen y/o el destino.
    fn compilar_direccion(
        &mut self,
        calificador: Calificador,
        red: u32,
        mascara: u32,
        si: usize,
        no: usize,
    ) -> Result<(), BpfError> {
        let ipv4 = self.nueva_etiqueta();
        self.comprobar_ethertype(ETHERTYPE_IPV4, ipv4, no);
        self.marcar(ipv4)?;
        match calificador {
            Calificador::Origen => {
                self.comprobar_red(OFFSET_IPV4_ORIGEN, red, mascara, si, no);
                Ok(())
            }
            Calificador::Destino => {
                self.comprobar_red(OFFSET_IPV4_DESTINO, red, mascara, si, no);
                Ok(())
            }
            Calificador::Cualquiera => {
                let segundo = self.nueva_etiqueta();
                self.comprobar_red(OFFSET_IPV4_ORIGEN, red, mascara, si, segundo);
                self.marcar(segundo)?;
                self.comprobar_red(OFFSET_IPV4_DESTINO, red, mascara, si, no);
                Ok(())
            }
        }
    }

    /// Carga una dirección IPv4, aplica la máscara y la compara.
    fn comprobar_red(&mut self, desplazamiento: u32, red: u32, mascara: u32, si: usize, no: usize) {
        self.emitir(cargar_abs(BPF_W, desplazamiento));
        if mascara != u32::MAX {
            self.emitir(enmascarar(mascara));
        }
        self.emitir_condicional(BPF_JEQ, red, si, no);
    }

    /// Sustituye los saltos simbólicos por instrucciones con desplazamiento real.
    fn resolver(self) -> Result<Vec<BpfInsn>, BpfError> {
        if self.elementos.len() > BPF_MAXINSNS {
            return Err(BpfError::nuevo(format!(
                "el filtro BPF es demasiado largo ({} instrucciones, máximo {})",
                self.elementos.len(),
                BPF_MAXINSNS
            )));
        }
        let mut instrucciones = Vec::with_capacity(self.elementos.len());
        for (indice, elemento) in self.elementos.iter().enumerate() {
            match elemento {
                Elemento::Instruccion(instruccion) => instrucciones.push(*instruccion),
                Elemento::Salto(etiqueta) => {
                    let destino = self
                        .etiquetas
                        .get(*etiqueta)
                        .copied()
                        .flatten()
                        .ok_or_else(|| {
                            BpfError::nuevo("etiqueta interna del filtro BPF sin resolver")
                        })?;
                    if destino <= indice {
                        return Err(BpfError::nuevo(
                            "salto hacia atrás no soportado en el filtro BPF",
                        ));
                    }
                    let desplazamiento = destino - indice - 1;
                    instrucciones.push(BpfInsn {
                        code: BPF_JMP | BPF_JA | BPF_K,
                        jt: 0,
                        jf: 0,
                        k: u32::try_from(desplazamiento).map_err(|_| {
                            BpfError::nuevo("salto demasiado largo en el filtro BPF")
                        })?,
                    });
                }
            }
        }
        Ok(instrucciones)
    }
}

// ---------------------------------------------------------------------------
// Ayudas de codificación de instrucciones
// ---------------------------------------------------------------------------

fn cargar_abs(tamano: u16, desplazamiento: u32) -> BpfInsn {
    BpfInsn {
        code: BPF_LD | tamano | BPF_ABS,
        jt: 0,
        jf: 0,
        k: desplazamiento,
    }
}

/// Carga el puerto de un extremo: indirecta (IPv4, según IHL en X) o absoluta.
fn cargar_puerto(indirecto: bool, desplazamiento: u32) -> BpfInsn {
    BpfInsn {
        code: BPF_LD | BPF_H | (if indirecto { BPF_IND } else { BPF_ABS }),
        jt: 0,
        jf: 0,
        k: desplazamiento,
    }
}

fn cargar_msh(desplazamiento: u32) -> BpfInsn {
    BpfInsn {
        code: BPF_LDX | BPF_B | BPF_MSH,
        jt: 0,
        jf: 0,
        k: desplazamiento,
    }
}

fn enmascarar(mascara: u32) -> BpfInsn {
    BpfInsn {
        code: BPF_ALU | BPF_AND | BPF_K,
        jt: 0,
        jf: 0,
        k: mascara,
    }
}

fn retorno(modo: u16, k: u32) -> BpfInsn {
    BpfInsn {
        code: BPF_RET | modo,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Plantilla de salto condicional: verdadero cae a la siguiente instrucción
/// (que será un `JA` al destino real) y falso salta una.
fn condicional(operacion: u16, k: u32) -> BpfInsn {
    BpfInsn {
        code: BPF_JMP | operacion | BPF_K,
        jt: 0,
        jf: 1,
        k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Construcción de tramas sintéticas ---------------------------------

    fn trama_ethernet(ethertype: u16) -> Vec<u8> {
        let mut trama = vec![0u8; 14];
        trama[12..14].copy_from_slice(&ethertype.to_be_bytes());
        trama
    }

    fn trama_ipv4(protocolo: u8, origen: [u8; 4], destino: [u8; 4], transporte: &[u8]) -> Vec<u8> {
        let longitud_total = 20 + transporte.len();
        let mut trama = trama_ethernet(ETHERTYPE_IPV4);
        let mut cabecera = [0u8; 20];
        cabecera[0] = 0x45;
        cabecera[2..4].copy_from_slice(&(longitud_total as u16).to_be_bytes());
        cabecera[8] = 64;
        cabecera[9] = protocolo;
        cabecera[12..16].copy_from_slice(&origen);
        cabecera[16..20].copy_from_slice(&destino);
        trama.extend_from_slice(&cabecera);
        trama.extend_from_slice(transporte);
        trama
    }

    fn trama_ipv6(
        siguiente_cabecera: u8,
        origen: [u8; 16],
        destino: [u8; 16],
        transporte: &[u8],
    ) -> Vec<u8> {
        let mut trama = trama_ethernet(ETHERTYPE_IPV6);
        let mut cabecera = [0u8; 40];
        cabecera[0] = 0x60;
        cabecera[4..6].copy_from_slice(&(transporte.len() as u16).to_be_bytes());
        cabecera[6] = siguiente_cabecera;
        cabecera[7] = 64;
        cabecera[8..24].copy_from_slice(&origen);
        cabecera[24..40].copy_from_slice(&destino);
        trama.extend_from_slice(&cabecera);
        trama.extend_from_slice(transporte);
        trama
    }

    fn transporte_tcp(origen: u16, destino: u16) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&origen.to_be_bytes());
        tcp[2..4].copy_from_slice(&destino.to_be_bytes());
        tcp[12] = 0x50;
        tcp
    }

    fn transporte_udp(origen: u16, destino: u16) -> Vec<u8> {
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&origen.to_be_bytes());
        udp[2..4].copy_from_slice(&destino.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        udp
    }

    fn trama_tcp(origen: u16, destino: u16) -> Vec<u8> {
        trama_ipv4(
            PROTOCOLO_TCP,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &transporte_tcp(origen, destino),
        )
    }

    fn trama_udp(origen: u16, destino: u16) -> Vec<u8> {
        trama_ipv4(
            PROTOCOLO_UDP,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &transporte_udp(origen, destino),
        )
    }

    fn trama_icmp() -> Vec<u8> {
        trama_ipv4(
            PROTOCOLO_ICMP,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &[8, 0, 0, 0, 0, 0, 0, 0],
        )
    }

    fn trama_tcp_ipv6(origen: u16, destino: u16) -> Vec<u8> {
        let mut origen_ip = [0u8; 16];
        origen_ip[0] = 0xfe;
        origen_ip[1] = 0x80;
        let mut destino_ip = [0u8; 16];
        destino_ip[0] = 0xfe;
        destino_ip[1] = 0x80;
        destino_ip[15] = 2;
        trama_ipv6(
            PROTOCOLO_TCP,
            origen_ip,
            destino_ip,
            &transporte_tcp(origen, destino),
        )
    }

    fn trama_icmp6() -> Vec<u8> {
        trama_ipv6(
            PROTOCOLO_ICMPV6,
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            &[128, 0, 0, 0, 0, 0, 0, 0],
        )
    }

    fn trama_arp() -> Vec<u8> {
        let mut trama = trama_ethernet(ETHERTYPE_ARP);
        trama.extend_from_slice(&[0u8; 28]);
        trama
    }

    // --- Compilación y evaluación de primitivas ----------------------------

    #[test]
    fn el_programa_compilado_no_esta_vacio_y_termina_en_retorno() {
        let programa = compile("port 80").expect("«port 80» debe compilar");
        assert!(!programa.is_empty());
        assert!(!programa.instructions().is_empty());
        let ultima = programa.instructions().last().expect("hay instrucciones");
        assert_eq!(ultima.code, BPF_RET | BPF_K);
        assert_eq!(ultima.k, 0);
        assert_eq!(
            BpfProgram::compile("tcp").expect("compila tcp"),
            compile("tcp").expect("compila tcp")
        );
    }

    #[test]
    fn protocolo_tcp_casa_solo_tramas_tcp() {
        let programa = compile("tcp").expect("«tcp» debe compilar");
        assert!(programa.matches(&trama_tcp(1234, 80)));
        assert!(programa.matches(&trama_tcp_ipv6(1234, 80)));
        assert!(!programa.matches(&trama_udp(1234, 80)));
        assert!(!programa.matches(&trama_icmp()));
        assert!(!programa.matches(&trama_arp()));
    }

    #[test]
    fn protocolo_udp_casa_solo_tramas_udp() {
        let programa = compile("udp").expect("«udp» debe compilar");
        assert!(programa.matches(&trama_udp(53, 5353)));
        assert!(!programa.matches(&trama_tcp(53, 5353)));
    }

    #[test]
    fn protocolos_icmp_icmp6_ip_ip6_y_arp() {
        let icmp = compile("icmp").expect("compila icmp");
        assert!(icmp.matches(&trama_icmp()));
        assert!(!icmp.matches(&trama_icmp6()));
        assert!(!icmp.matches(&trama_tcp(1, 2)));

        let icmp6 = compile("icmp6").expect("compila icmp6");
        assert!(icmp6.matches(&trama_icmp6()));
        assert!(!icmp6.matches(&trama_icmp()));

        let ip = compile("ip").expect("compila ip");
        assert!(ip.matches(&trama_tcp(1, 2)));
        assert!(!ip.matches(&trama_tcp_ipv6(1, 2)));
        assert!(!ip.matches(&trama_arp()));

        let ip6 = compile("ip6").expect("compila ip6");
        assert!(ip6.matches(&trama_tcp_ipv6(1, 2)));
        assert!(!ip6.matches(&trama_tcp(1, 2)));

        let arp = compile("arp").expect("compila arp");
        assert!(arp.matches(&trama_arp()));
        assert!(!arp.matches(&trama_tcp(1, 2)));
    }

    #[test]
    fn puerto_sin_calificador_casa_en_origen_o_destino() {
        let programa = compile("port 80").expect("compila port 80");
        assert!(programa.matches(&trama_tcp(1234, 80)));
        assert!(programa.matches(&trama_tcp(80, 1234)));
        assert!(!programa.matches(&trama_tcp(1234, 443)));
        assert!(programa.matches(&trama_udp(53, 80)));
        assert!(!programa.matches(&trama_icmp()));
    }

    #[test]
    fn puerto_con_calificador_solo_mira_un_extremo() {
        let origen = compile("src port 80").expect("compila src port 80");
        assert!(origen.matches(&trama_tcp(80, 1234)));
        assert!(!origen.matches(&trama_tcp(1234, 80)));

        let destino = compile("dst port 80").expect("compila dst port 80");
        assert!(destino.matches(&trama_tcp(1234, 80)));
        assert!(!destino.matches(&trama_tcp(80, 1234)));

        let ipv6 = compile("dst port 443").expect("compila dst port 443");
        assert!(ipv6.matches(&trama_tcp_ipv6(50000, 443)));
        assert!(!ipv6.matches(&trama_tcp_ipv6(443, 50000)));
    }

    #[test]
    fn rango_de_puertos_incluye_los_extremos() {
        let programa = compile("portrange 1000-2000").expect("compila el rango");
        assert!(programa.matches(&trama_tcp(1000, 5000)));
        assert!(programa.matches(&trama_tcp(1500, 5000)));
        assert!(programa.matches(&trama_tcp(5000, 2000)));
        assert!(!programa.matches(&trama_tcp(999, 5000)));
        assert!(!programa.matches(&trama_tcp(5000, 2001)));

        let con_espacios = compile("src portrange 1000 - 2000").expect("compila con espacios");
        assert!(con_espacios.matches(&trama_tcp(1500, 5000)));
        assert!(!con_espacios.matches(&trama_tcp(5000, 1500)));

        let unico = compile("portrange 1500-1500").expect("rango de un solo puerto");
        assert!(unico.matches(&trama_tcp(1500, 5000)));
        assert!(!unico.matches(&trama_tcp(1501, 5000)));
    }

    #[test]
    fn host_y_red_comprueban_origen_y_destino() {
        let host = compile("host 10.0.0.2").expect("compila host");
        assert!(host.matches(&trama_tcp(1, 2)));
        assert!(!host.matches(&trama_ipv4(
            PROTOCOLO_TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            &transporte_tcp(1, 2)
        )));

        let origen = compile("src host 10.0.0.1").expect("compila src host");
        assert!(origen.matches(&trama_tcp(1, 2)));
        assert!(!origen.matches(&trama_ipv4(
            PROTOCOLO_TCP,
            [192, 168, 1, 1],
            [10, 0, 0, 1],
            &transporte_tcp(1, 2)
        )));

        let destino = compile("dst net 192.168.1.0/24").expect("compila dst net");
        assert!(destino.matches(&trama_ipv4(
            PROTOCOLO_TCP,
            [10, 0, 0, 1],
            [192, 168, 1, 20],
            &transporte_tcp(1, 2)
        )));
        assert!(!destino.matches(&trama_ipv4(
            PROTOCOLO_TCP,
            [192, 168, 1, 20],
            [10, 0, 0, 1],
            &transporte_tcp(1, 2)
        )));

        let red = compile("net 10.0.0.0/8").expect("compila net");
        assert!(red.matches(&trama_tcp(1, 2)));
        assert!(!red.matches(&trama_ipv4(
            PROTOCOLO_TCP,
            [172, 16, 0, 1],
            [192, 168, 1, 20],
            &transporte_tcp(1, 2)
        )));

        let todas = compile("net 0.0.0.0/0").expect("compila net /0");
        assert!(todas.matches(&trama_tcp(1, 2)));
        assert!(!todas.matches(&trama_arp()));

        let una_sola = compile("net 10.0.0.1/32").expect("compila net /32");
        assert!(una_sola.matches(&trama_tcp(1, 2)));
        assert!(!una_sola.matches(&trama_ipv4(
            PROTOCOLO_TCP,
            [10, 0, 0, 2],
            [10, 0, 0, 3],
            &transporte_tcp(1, 2)
        )));
    }

    #[test]
    fn combina_con_and_or_y_parentesis() {
        let puertos = compile("port 80 or port 443").expect("compila el or");
        assert!(puertos.matches(&trama_tcp(1234, 80)));
        assert!(puertos.matches(&trama_tcp(1234, 443)));
        assert!(!puertos.matches(&trama_tcp(1234, 22)));

        // "and" tiene más prioridad que "or": puerto 80 O (443 Y tcp).
        let precedencia = compile("port 80 or port 443 and tcp").expect("compila la precedencia");
        assert!(precedencia.matches(&trama_udp(1234, 80)));
        assert!(precedencia.matches(&trama_tcp(1234, 443)));
        assert!(!precedencia.matches(&trama_udp(1234, 443)));

        let parentesis =
            compile("(port 80 or port 443) and host 10.0.0.2").expect("compila paréntesis");
        assert!(parentesis.matches(&trama_tcp(1234, 80)));
        assert!(!parentesis.matches(&trama_ipv4(
            PROTOCOLO_TCP,
            [10, 0, 0, 1],
            [192, 168, 1, 5],
            &transporte_tcp(1234, 80)
        )));

        let no_aplica = compile("tcp and not port 22").expect("compila and not");
        assert!(no_aplica.matches(&trama_tcp(1234, 80)));
        assert!(!no_aplica.matches(&trama_tcp(1234, 22)));
    }

    #[test]
    fn negacion_ac_del_contrato() {
        let programa = compile("not port 22").expect("«not port 22» debe compilar");
        assert!(!programa.matches(&trama_tcp(1234, 22)));
        assert!(!programa.matches(&trama_tcp(22, 5000)));
        assert!(programa.matches(&trama_tcp(1234, 80)));

        let simbolica = compile("! port 22").expect("«! port 22» debe compilar");
        assert!(!simbolica.matches(&trama_tcp(1234, 22)));
        assert!(simbolica.matches(&trama_tcp(1234, 80)));
    }

    #[test]
    fn acepta_mayusculas_y_operadores_alternativos() {
        let programa = compile("TCP AND (PORT 80 || PORT 443)").expect("compila mayúsculas");
        assert!(programa.matches(&trama_tcp(1234, 80)));
        assert!(programa.matches(&trama_tcp(1234, 443)));
        assert!(!programa.matches(&trama_udp(1234, 80)));

        let simbolico = compile("tcp && (port 80 || port 443)").expect("compila && y ||");
        assert!(simbolico.matches(&trama_tcp(1234, 443)));
    }

    #[test]
    fn un_calificador_sobre_un_protocolo_no_cambia_el_resultado() {
        let programa = compile("src tcp").expect("«src tcp» se acepta por gramática");
        assert!(programa.matches(&trama_tcp(1234, 80)));
        assert!(!programa.matches(&trama_udp(1234, 80)));
    }

    #[test]
    fn tramas_truncadas_no_casan_ni_hacen_panic() {
        let programa = compile("tcp and port 80").expect("compila");
        let trama = trama_tcp(1234, 80);
        // Necesita al menos la cabecera Ethernet, la IPv4 y los dos puertos.
        for longitud in 0..38 {
            assert!(
                !programa.matches(&trama[..longitud]),
                "una trama truncada a {longitud} bytes no debe casar"
            );
        }
        assert!(programa.matches(&trama));

        let sin_filtro = compile("ip").expect("compila ip");
        assert!(!sin_filtro.matches(&[]));
        assert!(!sin_filtro.matches(&[0u8; 13]));
    }

    // --- Errores de compilación -------------------------------------------

    #[test]
    fn errores_de_compilacion_en_castellano() {
        let casos = [
            ("", "vacío"),
            ("   ", "vacío"),
            ("port 70000", "fuera de rango"),
            ("port -1", "número de puerto"),
            ("host 999.1.1.1", "IPv4"),
            ("host 1.2.3", "IPv4"),
            ("foo", "no reconocido"),
            ("port", "número de puerto"),
            ("(tcp", "paréntesis"),
            ("tcp)", "sobra"),
            (")", "paréntesis"),
            ("tcp and", "expresión"),
            ("or tcp", "expresión"),
            ("portrange 2000-1000", "invertido"),
            ("portrange 1000", "se esperaba"),
            ("net 10.0.0.0/33", "prefijo"),
            ("net 10.0.0.0/abc", "prefijo"),
            ("net 10.0.0.0/-1", "prefijo"),
            ("tcp udp", "sobra"),
        ];
        for (expresion, fragmento) in casos {
            let error =
                compile(expresion).expect_err(&format!("«{expresion}» debería fallar al compilar"));
            assert!(
                error.to_string().contains(fragmento),
                "mensaje inesperado para «{expresion}»: {error}"
            );
        }
    }

    #[test]
    fn el_error_vacio_se_muestra_tal_cual() {
        let error = compile("").expect_err("la cadena vacía no es un filtro");
        assert_eq!(error.to_string(), "el filtro BPF está vacío");
        assert!(std::error::Error::source(&error).is_none());
    }

    // --- Adjuntar al socket -----------------------------------------------

    #[test]
    fn adjunta_el_filtro_a_un_socket_real() {
        let programa = compile("tcp or udp").expect("compila el filtro");
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd >= 0, "no se pudo crear el socket de prueba");
        let resultado = programa.attach(fd);
        unsafe {
            libc::close(fd);
        }
        resultado.expect("el filtro compilado debe adjuntarse sin privilegios");
    }

    #[test]
    fn adjuntar_a_un_descriptor_invalido_devuelve_error() {
        let programa = compile("tcp").expect("compila el filtro");
        assert!(programa.attach(-1).is_err());
    }

    #[test]
    fn adjuntar_un_programa_vacio_no_hace_nada() {
        let programa = BpfProgram {
            instrucciones: Vec::new(),
        };
        assert!(programa.is_empty());
        programa
            .attach(-1)
            .expect("un programa vacío no se adjunta y no falla");
    }

    // --- Intérprete -------------------------------------------------------

    #[test]
    fn interprete_ejecuta_instrucciones_manuales() {
        let acepta = BpfProgram {
            instrucciones: vec![retorno(BPF_K, 1)],
        };
        assert!(acepta.matches(&[]));

        let rechaza = BpfProgram {
            instrucciones: vec![retorno(BPF_K, 0)],
        };
        assert!(!rechaza.matches(&[]));

        // Carga el primer byte y lo compara con 0x45.
        let comprueba = BpfProgram {
            instrucciones: vec![
                cargar_abs(BPF_B, 0),
                condicional(BPF_JEQ, 0x45),
                BpfInsn {
                    code: BPF_JMP | BPF_JA | BPF_K,
                    jt: 0,
                    jf: 0,
                    k: 1,
                },
                BpfInsn {
                    code: BPF_JMP | BPF_JA | BPF_K,
                    jt: 0,
                    jf: 0,
                    k: 1,
                },
                retorno(BPF_K, 1),
                retorno(BPF_K, 0),
            ],
        };
        assert!(comprueba.matches(&[0x45, 0x00]));
        assert!(!comprueba.matches(&[0x60, 0x00]));
        assert!(!comprueba.matches(&[]));

        let division = BpfProgram {
            instrucciones: vec![
                BpfInsn {
                    code: BPF_ALU | BPF_DIV | BPF_K,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                retorno(BPF_K, 1),
            ],
        };
        assert!(!division.matches(&[]));

        let desconocida = BpfProgram {
            instrucciones: vec![BpfInsn {
                code: 0xffff,
                jt: 0,
                jf: 0,
                k: 0,
            }],
        };
        assert!(!desconocida.matches(&[0u8; 64]));
    }

    #[test]
    fn interprete_soporta_memoria_y_registros() {
        // A = 0x2a; M[0] = A; A = 0; A = M[0]; ret A
        let programa = BpfProgram {
            instrucciones: vec![
                BpfInsn {
                    code: BPF_LD | BPF_IMM,
                    jt: 0,
                    jf: 0,
                    k: 0x2a,
                },
                BpfInsn {
                    code: BPF_ST,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                BpfInsn {
                    code: BPF_LD | BPF_IMM,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                BpfInsn {
                    code: BPF_LD | BPF_MEM,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                retorno(BPF_A, 0),
            ],
        };
        assert!(programa.matches(&[]));

        // X = A mediante TAX y retorno con A = X mediante TXA.
        let registros = BpfProgram {
            instrucciones: vec![
                BpfInsn {
                    code: BPF_LD | BPF_IMM,
                    jt: 0,
                    jf: 0,
                    k: 1,
                },
                BpfInsn {
                    code: BPF_MISC | BPF_TAX,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                BpfInsn {
                    code: BPF_LD | BPF_IMM,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                BpfInsn {
                    code: BPF_MISC | BPF_TXA,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                retorno(BPF_A, 0),
            ],
        };
        assert!(registros.matches(&[]));
    }

    #[test]
    fn interprete_evalua_las_instrucciones_que_genera_el_compilador() {
        let programa = compile("(tcp and (port 80 or port 443)) or (udp and portrange 50-60)")
            .expect("compila el filtro complejo");
        for instruccion in programa.instructions() {
            let clase = instruccion.code & BPF_CLASE_MASCARA;
            assert!(
                matches!(clase, BPF_LD | BPF_LDX | BPF_ALU | BPF_JMP | BPF_RET),
                "clase inesperada en {instruccion:?}"
            );
        }
        assert!(programa.matches(&trama_tcp(1234, 443)));
        assert!(programa.matches(&trama_udp(1234, 55)));
        assert!(!programa.matches(&trama_udp(1234, 443)));
    }

    #[test]
    fn los_saltos_generados_son_hacia_delante_y_dentro_del_programa() {
        let programa = compile("not (tcp or udp) and port 53").expect("compila el filtro");
        let instrucciones = programa.instructions();
        for (indice, instruccion) in instrucciones.iter().enumerate() {
            if (instruccion.code & BPF_CLASE_MASCARA) != BPF_JMP {
                continue;
            }
            let operacion = instruccion.code & BPF_OPERACION_MASCARA;
            if operacion == BPF_JA {
                let destino = indice + 1 + instruccion.k as usize;
                assert!(destino < instrucciones.len());
            } else {
                let verdadero = indice + 1 + usize::from(instruccion.jt);
                let falso = indice + 1 + usize::from(instruccion.jf);
                assert!(verdadero < instrucciones.len());
                assert!(falso < instrucciones.len());
            }
        }
    }
}
