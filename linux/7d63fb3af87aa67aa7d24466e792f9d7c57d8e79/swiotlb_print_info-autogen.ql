/**
 * @name linux-7d63fb3af87aa67aa7d24466e792f9d7c57d8e79-swiotlb_print_info
 * @id cpp/linux/7d63fb3af87aa67aa7d24466e792f9d7c57d8e79/swiotlb-print-info
 * @description linux-7d63fb3af87aa67aa7d24466e792f9d7c57d8e79-swiotlb_print_info 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="6software IO TLB [mem %#010llx-%#010llx] (%luMB) mapped at [%p-%p]\n"
		and not target_0.getValue()="6software IO TLB: mapped [mem %#010llx-%#010llx] (%luMB)\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and target_1.getDeclarationEntry(1).(VariableDeclarationEntry).getType() instanceof CharPointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vvstart_165, Variable vio_tlb_start) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vvstart_165
		and target_2.getRValue().(FunctionCall).getTarget().hasName("phys_to_virt")
		and target_2.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vio_tlb_start)
}

predicate func_3(Variable vvend_165, Variable vio_tlb_end, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvend_165
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("phys_to_virt")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vio_tlb_end
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Variable vvstart_165, Variable vvend_165, Variable vio_tlb_start, Variable vio_tlb_end, Variable vbytes_164, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_4.getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vio_tlb_start
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vio_tlb_end
		and target_4.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vbytes_164
		and target_4.getExpr().(FunctionCall).getArgument(3).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="20"
		and target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvstart_165
		and target_4.getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vvend_165
		and target_4.getExpr().(FunctionCall).getArgument(5).(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Variable vvstart_165, Variable vvend_165, Variable vio_tlb_start, Variable vio_tlb_end, Variable vbytes_164
where
func_0(func)
and func_1(func)
and func_2(vvstart_165, vio_tlb_start)
and func_3(vvend_165, vio_tlb_end, func)
and func_4(vvstart_165, vvend_165, vio_tlb_start, vio_tlb_end, vbytes_164, func)
and vvstart_165.getType().hasName("unsigned char *")
and vvend_165.getType().hasName("unsigned char *")
and vio_tlb_start.getType().hasName("phys_addr_t")
and vio_tlb_end.getType().hasName("phys_addr_t")
and vbytes_164.getType().hasName("unsigned long")
and vvstart_165.getParentScope+() = func
and vvend_165.getParentScope+() = func
and not vio_tlb_start.getParentScope+() = func
and not vio_tlb_end.getParentScope+() = func
and vbytes_164.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
