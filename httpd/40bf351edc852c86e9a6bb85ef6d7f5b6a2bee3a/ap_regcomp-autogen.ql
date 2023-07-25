/**
 * @name httpd-40bf351edc852c86e9a6bb85ef6d7f5b6a2bee3a-ap_regcomp
 * @id cpp/httpd/40bf351edc852c86e9a6bb85ef6d7f5b6a2bee3a/ap-regcomp
 * @description httpd-40bf351edc852c86e9a6bb85ef6d7f5b6a2bee3a-server/util_pcre.c-ap_regcomp CVE-2020-1927
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcflags_164, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vcflags_164
		and target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1024"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcflags_164, Variable vdefault_cflags, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vcflags_164
		and target_1.getExpr().(AssignOrExpr).getRValue().(VariableAccess).getTarget()=vdefault_cflags
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

from Function func, Parameter vcflags_164, Variable vdefault_cflags, ExprStmt target_1
where
not func_0(vcflags_164, target_1, func)
and func_1(vcflags_164, vdefault_cflags, func, target_1)
and vcflags_164.getType().hasName("int")
and vdefault_cflags.getType().hasName("int")
and vcflags_164.getFunction() = func
and not vdefault_cflags.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
