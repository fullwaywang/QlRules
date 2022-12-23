/**
 * @name linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_stat2inode_dotl
 * @id cpp/linux/5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f/v9fs_stat2inode_dotl
 * @description linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_stat2inode_dotl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vstat_614, Parameter vinode_614) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("i_size_write")
		and not target_0.getTarget().hasName("v9fs_i_size_write")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_614
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="st_size"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstat_614)
}

predicate func_2(Parameter vstat_614, Parameter vinode_614) {
	exists(NotExpr target_2 |
		target_2.getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_2.getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("v9fs_i_size_write")
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_614
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="st_size"
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstat_614)
}

predicate func_3(Parameter vstat_614, Parameter vinode_614) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand() instanceof BitwiseAndExpr
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("v9fs_i_size_write")
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_614
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="st_size"
		and target_3.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstat_614
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="st_result_mask"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstat_614
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2047"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="2047")
}

predicate func_4(Parameter vstat_614) {
	exists(BitwiseAndExpr target_4 |
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="st_result_mask"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstat_614
		and target_4.getRightOperand().(Literal).getValue()="512"
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall)
}

from Function func, Parameter vstat_614, Parameter vinode_614
where
func_0(vstat_614, vinode_614)
and not func_2(vstat_614, vinode_614)
and not func_3(vstat_614, vinode_614)
and func_4(vstat_614)
and vstat_614.getType().hasName("p9_stat_dotl *")
and vinode_614.getType().hasName("inode *")
and vstat_614.getParentScope+() = func
and vinode_614.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
