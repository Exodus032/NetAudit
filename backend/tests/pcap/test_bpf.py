from __future__ import annotations

import ast as pyast
import inspect

import pytest

from netaudit.pcap import bpf


# --- Table: expression -> expected AST shape --------------------------------


def _pkt(protocol="tcp", src="10.0.0.1", sport=1234, dst="1.1.1.1", dport=443):
    return {"protocol": protocol, "src_addr": src, "src_port": sport, "dst_addr": dst, "dst_port": dport}


class TestValidExpressions:
    def test_simple_proto(self):
        node = bpf.parse_bpf("tcp")
        assert node == bpf.Proto("tcp")

    def test_port(self):
        node = bpf.parse_bpf("port 443")
        assert node == bpf.PortExpr(None, 443)

    def test_src_port(self):
        node = bpf.parse_bpf("src port 80")
        assert node == bpf.PortExpr("src", 80)

    def test_dst_host(self):
        node = bpf.parse_bpf("dst host 1.2.3.4")
        assert node == bpf.HostExpr("dst", "1.2.3.4")

    def test_net(self):
        node = bpf.parse_bpf("net 192.168.1.0/24")
        assert node == bpf.NetExpr(None, "192.168.1.0/24")

    def test_and(self):
        node = bpf.parse_bpf("tcp and port 443")
        assert node == bpf.BoolOp("and", bpf.Proto("tcp"), bpf.PortExpr(None, 443))

    def test_or(self):
        node = bpf.parse_bpf("tcp port 443 or udp port 53")
        expected = bpf.BoolOp(
            "or",
            bpf.BoolOp("and", bpf.Proto("tcp"), bpf.PortExpr(None, 443)),
            bpf.BoolOp("and", bpf.Proto("udp"), bpf.PortExpr(None, 53)),
        )
        assert node == expected

    def test_not(self):
        node = bpf.parse_bpf("not tcp")
        assert node == bpf.Not(bpf.Proto("tcp"))

    def test_parens_override_precedence(self):
        node = bpf.parse_bpf("(tcp or udp) and port 53")
        expected = bpf.BoolOp(
            "and",
            bpf.BoolOp("or", bpf.Proto("tcp"), bpf.Proto("udp")),
            bpf.PortExpr(None, 53),
        )
        assert node == expected

    def test_case_insensitive_keywords(self):
        node = bpf.parse_bpf("TCP AND PORT 443")
        assert node == bpf.BoolOp("and", bpf.Proto("tcp"), bpf.PortExpr(None, 443))

    def test_no_spaces_around_parens(self):
        node = bpf.parse_bpf("(tcp)or(udp)")
        assert node == bpf.BoolOp("or", bpf.Proto("tcp"), bpf.Proto("udp"))


# --- Table: invalid expression -> expected error position -------------------


class TestInvalidExpressions:
    @pytest.mark.parametrize(
        "expr,expected_pos",
        [
            ("", 0),
            ("   ", 0),
            ("tcp and", 7),               # dangling 'and' -- position is end-of-string
            ("port", 4),                  # missing number
            ("port abc", 5),              # non-numeric port
            ("port 99999", 5),            # out of range, position at the number
            ("host not-an-ip", 5),        # bad address
            ("net 10.0.0.0", 12),         # missing '/prefix' -- position is end-of-string
            ("net 10.0.0.0/abc", 13),     # non-numeric prefix (position of '/')
            ("tcp 123", 4),               # "123" isn't a valid primary -- trailing garbage
            ("(tcp", 4),                  # unclosed paren
            ("tcp)", 3),                  # stray close paren
            ("banana", 0),                # unknown keyword
        ],
    )
    def test_error_position(self, expr, expected_pos):
        with pytest.raises(bpf.BpfParseError) as exc_info:
            bpf.parse_bpf(expr)
        assert exc_info.value.position == expected_pos, (
            f"expr={expr!r} message={exc_info.value.message!r} "
            f"got pos={exc_info.value.position}, want {expected_pos}"
        )

    def test_previous_filter_untouched_is_a_router_contract(self):
        # bpf.py itself is stateless (see router.py's _FilterState.try_set,
        # which never mutates state before a successful parse) -- this test
        # just documents that parse_bpf raises before returning anything,
        # so a caller can never observe a partially-applied AST.
        with pytest.raises(bpf.BpfParseError):
            bpf.parse_bpf("tcp and")


# --- Evaluation: match / no-match -------------------------------------------


class TestEvaluate:
    def test_proto_match(self):
        node = bpf.parse_bpf("tcp")
        assert bpf.evaluate(node, _pkt(protocol="tcp")) is True
        assert bpf.evaluate(node, _pkt(protocol="udp")) is False

    def test_port_either_side(self):
        node = bpf.parse_bpf("port 443")
        assert bpf.evaluate(node, _pkt(sport=443, dport=9999)) is True
        assert bpf.evaluate(node, _pkt(sport=9999, dport=443)) is True
        assert bpf.evaluate(node, _pkt(sport=1, dport=2)) is False

    def test_src_port_only(self):
        node = bpf.parse_bpf("src port 443")
        assert bpf.evaluate(node, _pkt(sport=443, dport=1)) is True
        assert bpf.evaluate(node, _pkt(sport=1, dport=443)) is False

    def test_host_either_side(self):
        node = bpf.parse_bpf("host 1.2.3.4")
        assert bpf.evaluate(node, _pkt(src="1.2.3.4")) is True
        assert bpf.evaluate(node, _pkt(dst="1.2.3.4")) is True
        assert bpf.evaluate(node, _pkt(src="9.9.9.9", dst="8.8.8.8")) is False

    def test_net_containment(self):
        node = bpf.parse_bpf("net 192.168.1.0/24")
        assert bpf.evaluate(node, _pkt(src="192.168.1.55")) is True
        assert bpf.evaluate(node, _pkt(src="192.168.2.55", dst="10.0.0.1")) is False

    def test_and_or_not_combination(self):
        node = bpf.parse_bpf("tcp port 443 or udp port 53")
        assert bpf.evaluate(node, _pkt(protocol="tcp", sport=1, dport=443)) is True
        assert bpf.evaluate(node, _pkt(protocol="udp", sport=53, dport=1)) is True
        assert bpf.evaluate(node, _pkt(protocol="udp", sport=1, dport=443)) is False

    def test_not(self):
        node = bpf.parse_bpf("not tcp")
        assert bpf.evaluate(node, _pkt(protocol="tcp")) is False
        assert bpf.evaluate(node, _pkt(protocol="udp")) is True

    def test_parens(self):
        node = bpf.parse_bpf("(tcp or udp) and port 53")
        assert bpf.evaluate(node, _pkt(protocol="tcp", sport=53, dport=1)) is True
        assert bpf.evaluate(node, _pkt(protocol="icmp", sport=53, dport=1)) is False


# --- Security: never a shell, eval, exec, or a regex built from user input --


class TestNoUnsafeConstructs:
    """AST-scans this package's own source, per the task's explicit
    requirement, rather than trusting a code-review pass."""

    # Builtins that would mean "run this string as code" if called bare
    # (a `Name` call, e.g. `eval(x)`) -- NOT flagged as an `Attribute` call,
    # since that shape covers legitimate, unrelated methods like
    # `re.compile(...)` (a fixed literal pattern, checked separately below)
    # or a hypothetical `something.exec(...)` that isn't the builtin at all.
    _FORBIDDEN_BUILTIN_CALLS = {"eval", "exec", "compile"}
    # Attribute calls that would mean "run a subprocess/shell command".
    _FORBIDDEN_ATTR_CALLS = {"system", "popen", "run", "call", "check_call", "check_output", "Popen"}

    def _scan_module(self, module) -> list[str]:
        source = inspect.getsource(module)
        tree = pyast.parse(source)
        violations: list[str] = []
        for node in pyast.walk(tree):
            if isinstance(node, pyast.Call):
                func = node.func
                if isinstance(func, pyast.Name) and func.id in self._FORBIDDEN_BUILTIN_CALLS:
                    violations.append(f"line {node.lineno}: call to builtin {func.id!r}")
                elif isinstance(func, pyast.Attribute) and func.attr in self._FORBIDDEN_ATTR_CALLS:
                    violations.append(f"line {node.lineno}: call to {func.attr!r}")
            if isinstance(node, pyast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        violations.append(f"line {node.lineno}: import of 'subprocess' in bpf.py")
        return violations

    def test_bpf_module_has_no_unsafe_constructs(self):
        violations = self._scan_module(bpf)
        assert violations == [], f"unsafe constructs found in bpf.py: {violations}"

    def test_bpf_module_never_calls_shell_true(self):
        source = inspect.getsource(bpf)
        assert "shell=True" not in source
        assert "shell =True".replace(" ", "") not in source.replace(" ", "")

    def test_bpf_module_does_not_build_regex_from_user_input(self):
        """The tokeniser's regex pattern is a fixed literal (`_TOKEN_RE =
        re.compile(...)`, checked once at import time); the only thing
        that varies at runtime is the *string being searched*
        (`_TOKEN_RE.finditer(expr)`), never the pattern. This checks every
        direct `re.<method>(...)` call (receiver literally named `re`,
        which is the only shape that takes a *pattern* as its first
        argument) uses a literal constant pattern -- never a value built
        from `expr`/user input. Method calls on an already-compiled
        pattern object (`_TOKEN_RE.finditer(...)`) are a different shape
        (their first argument is the search subject, not a pattern) and
        are correctly not in scope for this check."""
        source = inspect.getsource(bpf)
        tree = pyast.parse(source)
        checked_any = False
        for node in pyast.walk(tree):
            if (
                isinstance(node, pyast.Call)
                and isinstance(node.func, pyast.Attribute)
                and isinstance(node.func.value, pyast.Name)
                and node.func.value.id == "re"
                and node.func.attr in ("compile", "match", "search", "findall", "sub", "finditer")
            ):
                checked_any = True
                assert node.args, f"line {node.lineno}: re.{node.func.attr}() called with no pattern argument"
                pattern_arg = node.args[0]
                assert isinstance(pattern_arg, pyast.Constant), (
                    f"line {node.lineno}: regex pattern is not a literal constant "
                    f"({pyast.dump(pattern_arg)})"
                )
        assert checked_any, "expected at least one re.compile(...) call in bpf.py to check"

    def test_evaluate_is_purely_structural_no_ast_node_reaches_eval(self):
        # NOTE: these are plain substring checks against bpf.py's own source
        # text (asserting the strings "eval(" / "exec(" are ABSENT from it).
        # No eval/exec is called here or anywhere in this test file.
        source = inspect.getsource(bpf)
        assert "eval(" not in source
        assert "exec(" not in source
