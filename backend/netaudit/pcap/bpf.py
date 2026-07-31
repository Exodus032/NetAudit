"""A BPF-syntax subset: real tokeniser, recursive-descent parser producing
an AST, and a structural evaluator over packet fields (E4).

This is deliberately NOT a BPF compiler/VM and NEVER touches a shell, never
calls `eval`/`exec`/`compile` on anything, and never builds a regular
expression out of concatenated user input. The grammar:

    expr       := or_expr
    or_expr    := and_expr ( "or" and_expr )*
    and_expr   := unary ( "and" unary )*
    unary      := "not" unary | primary
    primary    := "(" expr ")"
                | "tcp" | "udp" | "icmp"
                | [ "src" | "dst" ] "port" NUMBER
                | [ "src" | "dst" ] "host" ADDR
                | [ "src" | "dst" ] "net" ADDR "/" PREFIXLEN

Every token knows its character offset in the original string, so a parse
error can report exactly where it went wrong (`BpfParseError.position`).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

# --- Errors --------------------------------------------------------------


class BpfParseError(ValueError):
    def __init__(self, message: str, position: int):
        super().__init__(message)
        self.message = message
        self.position = position

    def __str__(self) -> str:
        return f"{self.message} (at character {self.position})"


# --- Tokeniser -------------------------------------------------------------

_TOKEN_RE = re.compile(r"\(|\)|/|[^\s()/]+")

_KEYWORDS = {"tcp", "udp", "icmp", "and", "or", "not", "src", "dst", "port", "host", "net"}


@dataclass
class Token:
    kind: str  # "lparen" | "rparen" | "slash" | "word"
    value: str
    pos: int


def tokenize(expr: str) -> list[Token]:
    tokens: list[Token] = []
    for m in _TOKEN_RE.finditer(expr):
        text = m.group(0)
        if text == "(":
            tokens.append(Token("lparen", text, m.start()))
        elif text == ")":
            tokens.append(Token("rparen", text, m.start()))
        elif text == "/":
            tokens.append(Token("slash", text, m.start()))
        else:
            tokens.append(Token("word", text, m.start()))
    return tokens


# --- AST --------------------------------------------------------------------


class Node:
    pass


@dataclass
class BoolOp(Node):
    op: str  # "and" | "or"
    left: Node
    right: Node


@dataclass
class Not(Node):
    operand: Node


@dataclass
class Proto(Node):
    name: str  # "tcp" | "udp" | "icmp"


@dataclass
class PortExpr(Node):
    qualifier: Optional[str]  # None | "src" | "dst"
    port: int


@dataclass
class HostExpr(Node):
    qualifier: Optional[str]
    host: str


@dataclass
class NetExpr(Node):
    qualifier: Optional[str]
    network: str  # e.g. "192.168.1.0/24", already validated


# --- Parser -----------------------------------------------------------------


class _Parser:
    def __init__(self, tokens: list[Token], source_len: int):
        self.tokens = tokens
        self.i = 0
        self.source_len = source_len

    def _peek(self) -> Optional[Token]:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _end_pos(self) -> int:
        return self.tokens[-1].pos + len(self.tokens[-1].value) if self.tokens else self.source_len

    def _advance(self) -> Token:
        tok = self._peek()
        if tok is None:
            raise BpfParseError("unexpected end of expression", self._end_pos())
        self.i += 1
        return tok

    def _expect_word(self, expected: str) -> Token:
        tok = self._peek()
        if tok is None or tok.kind != "word" or tok.value.lower() != expected:
            got = f"'{tok.value}'" if tok else "end of expression"
            pos = tok.pos if tok else self._end_pos()
            raise BpfParseError(f"expected '{expected}', got {got}", pos)
        return self._advance()

    def parse(self) -> Node:
        node = self._or_expr()
        trailing = self._peek()
        if trailing is not None:
            raise BpfParseError(f"unexpected trailing token '{trailing.value}'", trailing.pos)
        return node

    def _or_expr(self) -> Node:
        node = self._and_expr()
        while True:
            tok = self._peek()
            if tok is not None and tok.kind == "word" and tok.value.lower() == "or":
                self._advance()
                right = self._and_expr()
                node = BoolOp("or", node, right)
            else:
                break
        return node

    def _and_expr(self) -> Node:
        node = self._unary()
        while True:
            tok = self._peek()
            if tok is not None and tok.kind == "word" and tok.value.lower() == "and":
                self._advance()
                right = self._unary()
                node = BoolOp("and", node, right)
            else:
                break
        return node

    def _unary(self) -> Node:
        tok = self._peek()
        if tok is not None and tok.kind == "word" and tok.value.lower() == "not":
            self._advance()
            return Not(self._unary())
        return self._primary()

    def _primary(self) -> Node:
        tok = self._peek()
        if tok is None:
            raise BpfParseError("unexpected end of expression", self._end_pos())

        if tok.kind == "lparen":
            self._advance()
            node = self._or_expr()
            closing = self._peek()
            if closing is None or closing.kind != "rparen":
                pos = closing.pos if closing else self._end_pos()
                raise BpfParseError("expected ')'", pos)
            self._advance()
            return node

        if tok.kind != "word":
            raise BpfParseError(f"unexpected token '{tok.value}'", tok.pos)

        lower = tok.value.lower()

        if lower in ("tcp", "udp", "icmp"):
            self._advance()
            return Proto(lower)

        qualifier: Optional[str] = None
        if lower in ("src", "dst"):
            self._advance()
            qualifier = lower
            tok = self._peek()
            if tok is None or tok.kind != "word":
                raise BpfParseError("expected 'port', 'host' or 'net' after qualifier", self._end_pos() if tok is None else tok.pos)
            lower = tok.value.lower()

        if lower == "port":
            self._advance()
            num_tok = self._peek()
            if num_tok is None or num_tok.kind != "word" or not num_tok.value.isdigit():
                pos = num_tok.pos if num_tok else self._end_pos()
                raise BpfParseError("expected a port number after 'port'", pos)
            self._advance()
            port = int(num_tok.value)
            if not (0 <= port <= 65535):
                raise BpfParseError(f"port {port} out of range (0-65535)", num_tok.pos)
            return PortExpr(qualifier, port)

        if lower == "host":
            self._advance()
            host_tok = self._peek()
            if host_tok is None or host_tok.kind != "word":
                pos = host_tok.pos if host_tok else self._end_pos()
                raise BpfParseError("expected an address after 'host'", pos)
            self._advance()
            try:
                ipaddress.ip_address(host_tok.value)
            except ValueError:
                raise BpfParseError(f"'{host_tok.value}' is not a valid IP address", host_tok.pos)
            return HostExpr(qualifier, host_tok.value)

        if lower == "net":
            self._advance()
            addr_tok = self._peek()
            if addr_tok is None or addr_tok.kind != "word":
                pos = addr_tok.pos if addr_tok else self._end_pos()
                raise BpfParseError("expected an address after 'net'", pos)
            self._advance()
            slash_tok = self._peek()
            if slash_tok is None or slash_tok.kind != "slash":
                pos = slash_tok.pos if slash_tok else self._end_pos()
                raise BpfParseError("expected '/' after net address (e.g. 'net 10.0.0.0/8')", pos)
            self._advance()
            prefix_tok = self._peek()
            if prefix_tok is None or prefix_tok.kind != "word" or not prefix_tok.value.isdigit():
                pos = prefix_tok.pos if prefix_tok else self._end_pos()
                raise BpfParseError("expected a prefix length after '/'", pos)
            self._advance()
            candidate = f"{addr_tok.value}/{prefix_tok.value}"
            try:
                network = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                raise BpfParseError(f"'{candidate}' is not a valid network (address/prefix)", addr_tok.pos)
            return NetExpr(qualifier, str(network))

        raise BpfParseError(
            f"unexpected keyword '{tok.value}' (expected tcp/udp/icmp/port/host/net/and/or/not/'(')",
            tok.pos,
        )


def parse_bpf(expr: str) -> Node:
    """Tokenises and parses `expr`. Raises BpfParseError with a message and
    a character position on anything invalid. Never touches a shell, never
    calls eval/exec/compile."""
    if not expr or not expr.strip():
        raise BpfParseError("expression is empty", 0)
    tokens = tokenize(expr)
    if not tokens:
        raise BpfParseError("expression is empty", 0)
    parser = _Parser(tokens, len(expr))
    return parser.parse()


# --- Structural evaluation ---------------------------------------------------


def evaluate(node: Node, packet: dict) -> bool:
    """Evaluates the AST against a packet dict with at least: protocol,
    src_addr, src_port, dst_addr, dst_port. Purely structural -- no eval,
    no exec, no code generation of any kind."""
    if isinstance(node, BoolOp):
        if node.op == "and":
            return evaluate(node.left, packet) and evaluate(node.right, packet)
        return evaluate(node.left, packet) or evaluate(node.right, packet)

    if isinstance(node, Not):
        return not evaluate(node.operand, packet)

    if isinstance(node, Proto):
        return (packet.get("protocol") or "").lower() == node.name

    if isinstance(node, PortExpr):
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")
        if node.qualifier == "src":
            return src_port == node.port
        if node.qualifier == "dst":
            return dst_port == node.port
        return src_port == node.port or dst_port == node.port

    if isinstance(node, HostExpr):
        src_addr = packet.get("src_addr")
        dst_addr = packet.get("dst_addr")
        if node.qualifier == "src":
            return src_addr == node.host
        if node.qualifier == "dst":
            return dst_addr == node.host
        return src_addr == node.host or dst_addr == node.host

    if isinstance(node, NetExpr):
        network = ipaddress.ip_network(node.network, strict=False)
        src_addr = packet.get("src_addr")
        dst_addr = packet.get("dst_addr")

        def _in_net(addr: Optional[str]) -> bool:
            if not addr:
                return False
            try:
                return ipaddress.ip_address(addr) in network
            except ValueError:
                return False

        if node.qualifier == "src":
            return _in_net(src_addr)
        if node.qualifier == "dst":
            return _in_net(dst_addr)
        return _in_net(src_addr) or _in_net(dst_addr)

    raise TypeError(f"unknown AST node type: {type(node)!r}")  # pragma: no cover


def describe(node: Node) -> str:
    """Human-readable summary for `compiled_summary` in the E4 response."""
    if isinstance(node, BoolOp):
        return f"({describe(node.left)} {node.op.upper()} {describe(node.right)})"
    if isinstance(node, Not):
        return f"NOT {describe(node.operand)}"
    if isinstance(node, Proto):
        return node.name.upper()
    if isinstance(node, PortExpr):
        if node.qualifier:
            return f"{node.qualifier} port {node.port}"
        return f"dst/src port {node.port}"
    if isinstance(node, HostExpr):
        q = node.qualifier or "src/dst"
        return f"{q} host {node.host}"
    if isinstance(node, NetExpr):
        q = node.qualifier or "src/dst"
        return f"{q} net {node.network}"
    return "?"  # pragma: no cover
