/**
 * @name linux-574823bfab82d9d8fa47f422778043fbb4b4f50e-mincore_unmapped_range
 * @id cpp/linux/574823bfab82d9d8fa47f422778043fbb4b4f50e/mincore_unmapped_range
 * @description linux-574823bfab82d9d8fa47f422778043fbb4b4f50e-mincore_unmapped_range 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof PointerFieldAccess
		and func.getEntryPoint().(BlockStmt).getStmt(0)=target_0)
}

predicate func_1(Parameter vaddr_106, Parameter vend_106, Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vend_106
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vaddr_106
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_1)
}

predicate func_2(Function func) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("__memset")
		and target_2.getArgument(0).(VariableAccess).getType().hasName("unsigned char *")
		and target_2.getArgument(1).(Literal).getValue()="0"
		and target_2.getArgument(2).(VariableAccess).getType().hasName("unsigned long")
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vwalk_107, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="private"
		and target_3.getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwalk_107
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getType().hasName("unsigned long")
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_3))
}

predicate func_5(Parameter vwalk_107) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="private"
		and target_5.getQualifier().(VariableAccess).getTarget()=vwalk_107
		and target_5.getParent().(FunctionCall).getParent().(AssignPointerAddExpr).getRValue() instanceof FunctionCall)
}

predicate func_8(Parameter vwalk_107, Parameter vaddr_106, Parameter vend_106) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("__mincore_unmapped_range")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vaddr_106
		and target_8.getArgument(1).(VariableAccess).getTarget()=vend_106
		and target_8.getArgument(2).(PointerFieldAccess).getTarget().getName()="vma"
		and target_8.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwalk_107
		and target_8.getArgument(3) instanceof PointerFieldAccess)
}

from Function func, Parameter vwalk_107, Parameter vaddr_106, Parameter vend_106
where
not func_0(func)
and not func_1(vaddr_106, vend_106, func)
and not func_2(func)
and not func_3(vwalk_107, func)
and func_5(vwalk_107)
and func_8(vwalk_107, vaddr_106, vend_106)
and vwalk_107.getType().hasName("mm_walk *")
and vaddr_106.getType().hasName("unsigned long")
and vend_106.getType().hasName("unsigned long")
and vwalk_107.getParentScope+() = func
and vaddr_106.getParentScope+() = func
and vend_106.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
