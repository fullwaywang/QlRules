/**
 * @name linux-46f8a29272e51b6df7393d58fc5cb8967397ef2b-vduse_vdpa_get_config
 * @id cpp/linux/46f8a29272e51b6df7393d58fc5cb8967397ef2b/vduse-vdpa-get-config
 * @description linux-46f8a29272e51b6df7393d58fc5cb8967397ef2b-vduse_vdpa_get_config CVE-2022-2308
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbuf_672, Parameter vlen_672, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_672
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_672
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Parameter voffset_671, Parameter vlen_672, Variable vdev_674, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof RelationalOperation
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlen_672
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="config_size"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_674
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=voffset_671
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1))
}

predicate func_4(Function func) {
	exists(LogicalOrExpr target_4 |
		target_4.getAnOperand() instanceof RelationalOperation
		and target_4.getAnOperand() instanceof RelationalOperation
		and target_4.getParent().(IfStmt).getThen().(ReturnStmt).toString() = "return ..."
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter voffset_671, Variable vdev_674) {
	exists(SubExpr target_5 |
		target_5.getLeftOperand().(PointerFieldAccess).getTarget().getName()="config_size"
		and target_5.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_674
		and target_5.getRightOperand().(VariableAccess).getTarget()=voffset_671)
}

predicate func_6(Parameter voffset_671, Parameter vbuf_672, Parameter vlen_672, Variable vdev_674) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("__memcpy")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vbuf_672
		and target_6.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="config"
		and target_6.getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_674
		and target_6.getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=voffset_671
		and target_6.getArgument(2).(VariableAccess).getTarget()=vlen_672)
}

predicate func_7(Variable vdev_674) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="config_size"
		and target_7.getQualifier().(VariableAccess).getTarget()=vdev_674)
}

from Function func, Parameter voffset_671, Parameter vbuf_672, Parameter vlen_672, Variable vdev_674
where
not func_0(vbuf_672, vlen_672, func)
and not func_1(voffset_671, vlen_672, vdev_674, func)
and func_4(func)
and voffset_671.getType().hasName("unsigned int")
and func_5(voffset_671, vdev_674)
and vbuf_672.getType().hasName("void *")
and vlen_672.getType().hasName("unsigned int")
and func_6(voffset_671, vbuf_672, vlen_672, vdev_674)
and vdev_674.getType().hasName("vduse_dev *")
and func_7(vdev_674)
and voffset_671.getParentScope+() = func
and vbuf_672.getParentScope+() = func
and vlen_672.getParentScope+() = func
and vdev_674.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
