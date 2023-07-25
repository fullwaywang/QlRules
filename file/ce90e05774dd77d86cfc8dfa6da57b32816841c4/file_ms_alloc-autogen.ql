/**
 * @name file-ce90e05774dd77d86cfc8dfa6da57b32816841c4-file_ms_alloc
 * @id cpp/file/ce90e05774dd77d86cfc8dfa6da57b32816841c4/file-ms-alloc
 * @description file-ce90e05774dd77d86cfc8dfa6da57b32816841c4-src/apprentice.c-file_ms_alloc CVE-2014-9620
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="184"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vms_503, ExprStmt target_2, ReturnStmt target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="elf_notes_max"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_503
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="256"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_1)
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(VariableAccess).getLocation()))
}

predicate func_2(Variable vms_503, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="elf_phnum_max"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_503
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="128"
}

predicate func_3(Variable vms_503, ReturnStmt target_3) {
		target_3.getExpr().(VariableAccess).getTarget()=vms_503
}

from Function func, Variable vms_503, SizeofTypeOperator target_0, ExprStmt target_2, ReturnStmt target_3
where
func_0(func, target_0)
and not func_1(vms_503, target_2, target_3, func)
and func_2(vms_503, target_2)
and func_3(vms_503, target_3)
and vms_503.getType().hasName("magic_set *")
and vms_503.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
