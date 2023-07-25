/**
 * @name libgit2-2fdef641fd0dd2828bd948234ae86de75221a11a-git_pkt_parse_line
 * @id cpp/libgit2/2fdef641fd0dd2828bd948234ae86de75221a11a/git-pkt-parse-line
 * @description libgit2-2fdef641fd0dd2828bd948234ae86de75221a11a-src/transports/smart_pkt.c-git_pkt_parse_line CVE-2016-10129
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("giterr_set_str")
		and target_0.getArgument(1).(StringLiteral).getValue()="Invalid empty packet"
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Parameter vline_399, Parameter vout_399, EqualityOperation target_5, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vout_399
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vline_399
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_3(Parameter vhead_399, AssignExpr target_3) {
		target_3.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vhead_399
		and target_3.getRValue().(Literal).getValue()="0"
}

predicate func_5(EqualityOperation target_5) {
		target_5.getAnOperand().(Literal).getValue()="4"
}

from Function func, Parameter vhead_399, Parameter vline_399, Parameter vout_399, ExprStmt target_2, AssignExpr target_3, EqualityOperation target_5
where
not func_0(func)
and func_2(vline_399, vout_399, target_5, target_2)
and func_3(vhead_399, target_3)
and func_5(target_5)
and vhead_399.getType().hasName("git_pkt **")
and vline_399.getType().hasName("const char *")
and vout_399.getType().hasName("const char **")
and vhead_399.getParentScope+() = func
and vline_399.getParentScope+() = func
and vout_399.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
