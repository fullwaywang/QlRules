/**
 * @name libarchive-22531545514043e04633e1c015c7540b9de9dbe4-_archive_write_data
 * @id cpp/libarchive/22531545514043e04633e1c015c7540b9de9dbe4/-archive-write-data
 * @description libarchive-22531545514043e04633e1c015c7540b9de9dbe4-libarchive/archive_write.c-_archive_write_data CVE-2013-0211
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_673, VariableCall target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vs_673
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_673
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("size_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_673, VariableCall target_1) {
		target_1.getExpr().(PointerFieldAccess).getTarget().getName()="format_write_data"
		and target_1.getArgument(2).(VariableAccess).getTarget()=vs_673
}

from Function func, Parameter vs_673, VariableCall target_1
where
not func_0(vs_673, target_1, func)
and func_1(vs_673, target_1)
and vs_673.getType().hasName("size_t")
and vs_673.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
