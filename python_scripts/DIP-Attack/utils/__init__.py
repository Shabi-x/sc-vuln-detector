"""Solidity source-code utilities for DIP Attack."""

from utils.solidity_utils import (
    tokenize_sol,
    count_tokens,
    basic_syntax_check,
    insert_at_line,
    get_function_bodies,
    get_function_lines,
    get_insertable_positions,
    find_user_defined_vars,
    find_var_scope,
    get_scope_nesting_depth,
)
