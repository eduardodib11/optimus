//! Paleta do HUD (ADR 0040, item 5). Cores `0xFFRRGGBB`, opacas; a opacidade
//! de cada uso sai de [`cor`](crate::cor). O tema pode ser trocado por outro
//! conjunto de constantes (ex.: azul e vermelho) sem mudar o desenho.

use crate::Cor;

/// Ciano principal: núcleo, dados e vidro.
pub const CIANO: Cor = 0xFF2F_E6FF;
/// Ciano claro: marcações e traços finos.
pub const CIANO_CLARO: Cor = 0xFF8F_F3FF;
/// Ciano escuro: circunferências de apoio.
pub const CIANO_ESCURO: Cor = 0xFF1A_A9C0;
/// Cobre: molduras, títulos e destaques.
pub const COBRE: Cor = 0xFFD9_8A4E;
/// Cobre claro: marcas maiores e rótulos.
pub const COBRE_CLARO: Cor = 0xFFF2_C08F;
/// Vermelho: alertas e ação em risco.
pub const VERMELHO: Cor = 0xFFC8_102E;
/// Verde: estado saudável e fala da IA.
pub const VERDE: Cor = 0xFF3D_FFA8;
/// Texto principal.
pub const TEXTO: Cor = 0xFFD9_F7FF;
/// Texto secundário.
pub const TEXTO_SECUNDARIO: Cor = 0xFF7F_A6B5;
/// Fundo da tela.
pub const FUNDO: Cor = 0xFF04_070B;
/// Aço escovado.
pub const ACO: Cor = 0xFF8B_99A6;
/// Aço claro (traço externo, reflexo).
pub const ACO_CLARO: Cor = 0xFFE4_EDF2;
/// Aço escuro (sombra de degraus).
pub const ACO_ESCURO: Cor = 0xFF55_646F;
/// Branco puro: marcas do núcleo e centro do reator.
pub const BRANCO: Cor = 0xFFFF_FFFF;
/// Branco azulado: anel tracejado interno.
pub const BRANCO_AZULADO: Cor = 0xFFD6_FAFF;
/// Azul claro do reator.
pub const REATOR: Cor = 0xFFBF_F6FF;
/// Casco escuro do núcleo.
pub const NUCLEO_ESCURO: Cor = 0xFF06_141E;
/// Fundo interno do núcleo.
pub const NUCLEO_FUNDO: Cor = 0xFF02_101B;
/// Painel central do núcleo.
pub const PAINEL: Cor = 0xFF03_1A28;
/// Borda clara do vidro.
pub const VIDRO_BORDA: Cor = 0xFF9F_D8E6;
