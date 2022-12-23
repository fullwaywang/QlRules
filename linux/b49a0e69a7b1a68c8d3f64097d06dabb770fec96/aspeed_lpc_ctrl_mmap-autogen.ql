/**
 * @name linux-b49a0e69a7b1a68c8d3f64097d06dabb770fec96-aspeed_lpc_ctrl_mmap
 * @id cpp/linux/b49a0e69a7b1a68c8d3f64097d06dabb770fec96/aspeed_lpc_ctrl_mmap
 * @description linux-b49a0e69a7b1a68c8d3f64097d06dabb770fec96-aspeed_lpc_ctrl_mmap 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Parameter vvma_48) {
	exists(BinaryBitwiseOperation target_1 |
		target_1.getLeftOperand() instanceof PointerFieldAccess
		and target_1.getRightOperand().(Literal).getValue()="12"
		and target_1.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="vm_pgoff"
		and target_1.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_48
		and target_1.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("vma_pages")
		and target_1.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvma_48
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_2(Variable vlpc_ctrl_50) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="mem_base"
		and target_2.getQualifier().(VariableAccess).getTarget()=vlpc_ctrl_50)
}

predicate func_3(Variable vlpc_ctrl_50) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="mem_size"
		and target_3.getQualifier().(VariableAccess).getTarget()=vlpc_ctrl_50)
}

predicate func_5(Parameter vvma_48, Variable vvsize_51) {
	exists(AddExpr target_5 |
		target_5.getAnOperand() instanceof PointerFieldAccess
		and target_5.getAnOperand() instanceof PointerFieldAccess
		and target_5.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="vm_pgoff"
		and target_5.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvma_48
		and target_5.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vvsize_51
		and target_5.getParent().(GTExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_6(Parameter vvma_48) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="vm_pgoff"
		and target_6.getQualifier().(VariableAccess).getTarget()=vvma_48)
}

from Function func, Parameter vvma_48, Variable vlpc_ctrl_50, Variable vvsize_51
where
not func_1(vvma_48)
and func_2(vlpc_ctrl_50)
and func_3(vlpc_ctrl_50)
and func_5(vvma_48, vvsize_51)
and vvma_48.getType().hasName("vm_area_struct *")
and func_6(vvma_48)
and vlpc_ctrl_50.getType().hasName("aspeed_lpc_ctrl *")
and vvsize_51.getType().hasName("unsigned long")
and vvma_48.getParentScope+() = func
and vlpc_ctrl_50.getParentScope+() = func
and vvsize_51.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
