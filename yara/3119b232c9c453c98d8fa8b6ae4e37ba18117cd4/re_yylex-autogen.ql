/**
 * @name yara-3119b232c9c453c98d8fa8b6ae4e37ba18117cd4-re_yylex
 * @id cpp/yara/3119b232c9c453c98d8fa8b6ae4e37ba18117cd4/re-yylex
 * @description yara-3119b232c9c453c98d8fa8b6ae4e37ba18117cd4-libyara/re_lexer.c-re_yylex CVE-2016-10210
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="unexpected end of buffer"
		and not target_0.getValue()="illegal escape sequence"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="unexpected end of buffer"
		and not target_1.getValue()="illegal escape sequence"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="unexpected end of buffer"
		and not target_2.getValue()="illegal escape sequence"
		and target_2.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0, StringLiteral target_1, StringLiteral target_2
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
