/**
 * @name linux-574823bfab82d9d8fa47f422778043fbb4b4f50e-mincore_pte_range
 * @id cpp/linux/574823bfab82d9d8fa47f422778043fbb4b4f50e/mincore_pte_range
 * @description linux-574823bfab82d9d8fa47f422778043fbb4b4f50e-mincore_pte_range 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vvec_120) {
	exists(Literal target_0 |
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvec_120)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="12"
		and not target_1.getValue()="1"
		and target_1.getParent().(LShiftExpr).getParent().(AddExpr).getAnOperand() instanceof BinaryBitwiseOperation
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Variable vvec_120) {
	exists(NotExpr target_3 |
		target_3.getOperand().(NotExpr).getOperand() instanceof FunctionCall
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvec_120)
}

predicate func_4(Variable ventry_145) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("non_swap_entry")
		and target_4.getArgument(0).(VariableAccess).getTarget()=ventry_145)
}

predicate func_6(Parameter vend_114, Variable vvma_118, Variable vvec_120, Parameter vaddr_114) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("__mincore_unmapped_range")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vaddr_114
		and target_6.getArgument(1).(VariableAccess).getTarget()=vend_114
		and target_6.getArgument(2).(VariableAccess).getTarget()=vvma_118
		and target_6.getArgument(3).(VariableAccess).getTarget()=vvec_120)
}

predicate func_7(Variable vvma_118, Variable vvec_120, Variable vpte_137, Parameter vaddr_114) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("__mincore_unmapped_range")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vaddr_114
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vaddr_114
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getValue()="4096"
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand() instanceof Literal
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvma_118
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vvec_120
		and target_7.getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("pte_none")
		and target_7.getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpte_137)
}

predicate func_8(Variable ventry_145, Variable vswapper_spaces, Variable vvec_120, Variable vpte_137) {
	exists(IfStmt target_8 |
		target_8.getCondition() instanceof FunctionCall
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvec_120
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvec_120
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mincore_page")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vswapper_spaces
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(FunctionCall).getTarget().hasName("swp_type")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ventry_145
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getTarget().hasName("swp_offset")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ventry_145
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="14"
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("swp_offset")
		and target_8.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=ventry_145
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("pte_present")
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpte_137)
}

predicate func_10(Variable vvec_120, Variable vnr_121) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("__memset")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vvec_120
		and target_10.getArgument(1).(Literal).getValue()="1"
		and target_10.getArgument(2).(VariableAccess).getTarget()=vnr_121)
}

from Function func, Variable ventry_145, Variable vswapper_spaces, Parameter vend_114, Variable vvma_118, Variable vvec_120, Variable vnr_121, Variable vpte_137, Parameter vaddr_114
where
func_0(vvec_120)
and func_1(func)
and not func_3(vvec_120)
and func_4(ventry_145)
and func_6(vend_114, vvma_118, vvec_120, vaddr_114)
and func_7(vvma_118, vvec_120, vpte_137, vaddr_114)
and func_8(ventry_145, vswapper_spaces, vvec_120, vpte_137)
and ventry_145.getType().hasName("swp_entry_t")
and vswapper_spaces.getType().hasName("address_space *[]")
and vend_114.getType().hasName("unsigned long")
and vvma_118.getType().hasName("vm_area_struct *")
and vvec_120.getType().hasName("unsigned char *")
and vnr_121.getType().hasName("int")
and func_10(vvec_120, vnr_121)
and vpte_137.getType().hasName("pte_t")
and vaddr_114.getType().hasName("unsigned long")
and ventry_145.getParentScope+() = func
and not vswapper_spaces.getParentScope+() = func
and vend_114.getParentScope+() = func
and vvma_118.getParentScope+() = func
and vvec_120.getParentScope+() = func
and vnr_121.getParentScope+() = func
and vpte_137.getParentScope+() = func
and vaddr_114.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
