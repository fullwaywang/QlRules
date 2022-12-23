/**
 * @name linux-4e78921ba4dd0aca1cc89168f45039add4183f8e-efi_call_phys_prolog
 * @id cpp/linux/4e78921ba4dd0aca1cc89168f45039add4183f8e/efi_call_phys_prolog
 * @description linux-4e78921ba4dd0aca1cc89168f45039add4183f8e-efi_call_phys_prolog 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vefi_mm) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(ValueFieldAccess).getTarget().getName()="pgd"
		and target_0.getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_0.getExpr().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vefi_mm
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("efi_enabled")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="7")
}

predicate func_1(Variable vsave_pgd_78, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vsave_pgd_78
		and target_1.getThen() instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

predicate func_2(Variable vsave_pgd_78, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("efi_call_phys_epilog")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsave_pgd_78
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_2))
}

predicate func_3(Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_3))
}

predicate func_5(Variable vsave_pgd_78) {
	exists(PointerDereferenceExpr target_5 |
		target_5.getOperand().(VariableAccess).getTarget()=vsave_pgd_78)
}

predicate func_6(Variable vsave_pgd_78, Function func) {
	exists(ReturnStmt target_6 |
		target_6.getExpr().(VariableAccess).getTarget()=vsave_pgd_78
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

from Function func, Variable vsave_pgd_78, Variable vefi_mm
where
not func_0(vefi_mm)
and not func_1(vsave_pgd_78, func)
and not func_2(vsave_pgd_78, func)
and not func_3(func)
and vsave_pgd_78.getType().hasName("pgd_t *")
and func_5(vsave_pgd_78)
and func_6(vsave_pgd_78, func)
and vefi_mm.getType().hasName("mm_struct")
and vsave_pgd_78.getParentScope+() = func
and not vefi_mm.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
