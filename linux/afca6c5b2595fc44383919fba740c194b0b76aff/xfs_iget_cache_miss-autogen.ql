/**
 * @name linux-afca6c5b2595fc44383919fba740c194b0b76aff-xfs_iget_cache_miss
 * @id cpp/linux/afca6c5b2595fc44383919fba740c194b0b76aff/xfs-iget-cache-miss
 * @description linux-afca6c5b2595fc44383919fba740c194b0b76aff-xfs_iget_cache_miss 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vflags_463, Variable vip_466) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xfs_iget_check_free_state")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vip_466
		and target_0.getArgument(1).(VariableAccess).getTarget()=vflags_463)
}

predicate func_2(Variable vip_466) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("VFS_I")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vip_466)
}

predicate func_5(Function func) {
	exists(GotoStmt target_5 |
		target_5.toString() = "goto ..."
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation
		and target_5.getEnclosingFunction() = func)
}

predicate func_10(Parameter vino_461, Parameter vflags_463, Variable vip_466, Variable verror_467, Parameter vmp_458) {
	exists(IfStmt target_10 |
		target_10.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="di_nblocks"
		and target_10.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="i_d"
		and target_10.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vip_466
		and target_10.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xfs_warn")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmp_458
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Corruption detected! Free inode 0x%llx has blocks allocated!"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vino_461
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_467
		and target_10.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="117"
		and target_10.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_463
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_14(Parameter vflags_463, Variable vip_466, Variable verror_467) {
	exists(IfStmt target_14 |
		target_14.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_14.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("VFS_I")
		and target_14.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vip_466
		and target_14.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_467
		and target_14.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="2"
		and target_14.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_14.getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_463
		and target_14.getParent().(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1")
}

predicate func_17(Variable verror_467) {
	exists(AssignExpr target_17 |
		target_17.getLValue().(VariableAccess).getTarget()=verror_467
		and target_17.getRValue().(UnaryMinusExpr).getValue()="-117"
		and target_17.getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="117")
}

from Function func, Parameter vino_461, Parameter vflags_463, Variable vip_466, Variable verror_467, Parameter vmp_458
where
not func_0(vflags_463, vip_466)
and func_2(vip_466)
and func_5(func)
and func_10(vino_461, vflags_463, vip_466, verror_467, vmp_458)
and func_14(vflags_463, vip_466, verror_467)
and vino_461.getType().hasName("xfs_ino_t")
and vflags_463.getType().hasName("int")
and vip_466.getType().hasName("xfs_inode *")
and verror_467.getType().hasName("int")
and func_17(verror_467)
and vmp_458.getType().hasName("xfs_mount *")
and vino_461.getParentScope+() = func
and vflags_463.getParentScope+() = func
and vip_466.getParentScope+() = func
and verror_467.getParentScope+() = func
and vmp_458.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
