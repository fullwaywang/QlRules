/**
 * @name libarchive-ede459d2ebb879f5eedb6f7abea203be0b334230-new_fixup
 * @id cpp/libarchive/ede459d2ebb879f5eedb6f7abea203be0b334230/new-fixup
 * @description libarchive-ede459d2ebb879f5eedb6f7abea203be0b334230-libarchive/archive_write_disk_posix.c-new_fixup CVE-2021-31566
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfe_2681, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="filetype"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_2681
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vfe_2681, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fixup"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_2681
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_2(Variable vfe_2681, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_2681
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strdup")
}

from Function func, Variable vfe_2681, ExprStmt target_1, ExprStmt target_2
where
not func_0(vfe_2681, target_1, target_2, func)
and func_1(vfe_2681, target_1)
and func_2(vfe_2681, target_2)
and vfe_2681.getType().hasName("fixup_entry *")
and vfe_2681.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
