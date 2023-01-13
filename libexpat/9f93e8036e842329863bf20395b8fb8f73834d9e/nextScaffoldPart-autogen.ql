/**
 * @name libexpat-9f93e8036e842329863bf20395b8fb8f73834d9e-nextScaffoldPart
 * @id cpp/libexpat/9f93e8036e842329863bf20395b8fb8f73834d9e/nextScaffoldPart
 * @description libexpat-9f93e8036e842329863bf20395b8fb8f73834d9e-nextScaffoldPart CVE-2022-22826
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdtd_7132) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="scaffSize"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_7132
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="2147483647"
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="scaffold"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdtd_7132)
}

predicate func_2(Variable vdtd_7132) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="scaffold"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdtd_7132)
}

from Function func, Variable vdtd_7132
where
not func_0(vdtd_7132)
and vdtd_7132.getType().hasName("DTD *const")
and func_2(vdtd_7132)
and vdtd_7132.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
