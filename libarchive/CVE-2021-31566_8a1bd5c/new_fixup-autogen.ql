/**
 * @name libarchive-8a1bd5c18e896f0411a991240ce0d772bb02c840-new_fixup
 * @id cpp/libarchive/8a1bd5c18e896f0411a991240ce0d772bb02c840/new-fixup
 * @description libarchive-8a1bd5c18e896f0411a991240ce0d772bb02c840-libarchive/archive_write_disk_posix.c-new_fixup CVE-2021-31566
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfe_2656, Function func, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mode"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfe_2656
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Variable vfe_2656, ExprStmt target_0
where
func_0(vfe_2656, func, target_0)
and vfe_2656.getType().hasName("fixup_entry *")
and vfe_2656.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
