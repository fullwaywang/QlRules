/**
 * @name libarchive-bff38efe8c110469c5080d387bec62a6ca15b1a5-__archive_write_allocate_filter
 * @id cpp/libarchive/bff38efe8c110469c5080d387bec62a6ca15b1a5/--archive-write-allocate-filter
 * @description libarchive-bff38efe8c110469c5080d387bec62a6ca15b1a5-libarchive/archive_write.c-__archive_write_allocate_filter CVE-2022-36227
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vf_201, PointerDereferenceExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vf_201
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vf_201, PointerDereferenceExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vf_201
}

predicate func_2(Variable vf_201, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="archive"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_201
}

from Function func, Variable vf_201, PointerDereferenceExpr target_1, ExprStmt target_2
where
not func_0(vf_201, target_1, target_2, func)
and func_1(vf_201, target_1)
and func_2(vf_201, target_2)
and vf_201.getType().hasName("archive_write_filter *")
and vf_201.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
