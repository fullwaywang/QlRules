/**
 * @name linux-4e78921ba4dd0aca1cc89168f45039add4183f8e-phys_efi_set_virtual_address_map
 * @id cpp/linux/4e78921ba4dd0aca1cc89168f45039add4183f8e/phys_efi_set_virtual_address_map
 * @description linux-4e78921ba4dd0aca1cc89168f45039add4183f8e-phys_efi_set_virtual_address_map 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vsave_pgd_85, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vsave_pgd_85
		and target_0.getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getValue()="9223372036854775829"
		and target_0.getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="21"
		and target_0.getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="9223372036854775808"
		and target_0.getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="64"
		and target_0.getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Variable vsave_pgd_85) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vsave_pgd_85
		and target_1.getRValue().(FunctionCall).getTarget().hasName("efi_call_phys_prolog"))
}

from Function func, Variable vsave_pgd_85
where
not func_0(vsave_pgd_85, func)
and vsave_pgd_85.getType().hasName("pgd_t *")
and func_1(vsave_pgd_85)
and vsave_pgd_85.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
