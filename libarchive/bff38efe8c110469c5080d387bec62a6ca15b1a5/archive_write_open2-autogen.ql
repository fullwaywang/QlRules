/**
 * @name libarchive-bff38efe8c110469c5080d387bec62a6ca15b1a5-archive_write_open2
 * @id cpp/libarchive/bff38efe8c110469c5080d387bec62a6ca15b1a5/archive-write-open2
 * @description libarchive-bff38efe8c110469c5080d387bec62a6ca15b1a5-libarchive/archive_write.c-archive_write_open2 CVE-2022-36227
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vclient_filter_537, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vclient_filter_537
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-30"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vclient_filter_537, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vclient_filter_537
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__archive_write_allocate_filter")
}

predicate func_2(Variable vclient_filter_537, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="open"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vclient_filter_537
}

from Function func, Variable vclient_filter_537, ExprStmt target_1, ExprStmt target_2
where
not func_0(vclient_filter_537, target_1, target_2, func)
and func_1(vclient_filter_537, target_1)
and func_2(vclient_filter_537, target_2)
and vclient_filter_537.getType().hasName("archive_write_filter *")
and vclient_filter_537.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
