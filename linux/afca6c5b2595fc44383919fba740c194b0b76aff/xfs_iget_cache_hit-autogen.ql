/**
 * @name linux-afca6c5b2595fc44383919fba740c194b0b76aff-xfs_iget_cache_hit
 * @id cpp/linux/afca6c5b2595fc44383919fba740c194b0b76aff/xfs-iget-cache-hit
 * @description linux-afca6c5b2595fc44383919fba740c194b0b76aff-xfs_iget_cache_hit 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vip_317, Parameter vflags_319) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xfs_iget_check_free_state")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vip_317
		and target_0.getArgument(1).(VariableAccess).getTarget()=vflags_319)
}

predicate func_4(Function func) {
	exists(GotoStmt target_4 |
		target_4.toString() = "goto ..."
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof LogicalAndExpr
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vip_317, Parameter vflags_319, Variable verror_324) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("VFS_I")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vip_317
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_319
		and target_5.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verror_324
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="2"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof GotoStmt)
}

predicate func_7(Variable verror_324) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(VariableAccess).getTarget()=verror_324
		and target_7.getRValue().(UnaryMinusExpr).getValue()="-11"
		and target_7.getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="11")
}

from Function func, Parameter vip_317, Parameter vflags_319, Variable verror_324
where
not func_0(vip_317, vflags_319)
and func_4(func)
and func_5(vip_317, vflags_319, verror_324)
and vip_317.getType().hasName("xfs_inode *")
and vflags_319.getType().hasName("int")
and verror_324.getType().hasName("int")
and func_7(verror_324)
and vip_317.getParentScope+() = func
and vflags_319.getParentScope+() = func
and verror_324.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
