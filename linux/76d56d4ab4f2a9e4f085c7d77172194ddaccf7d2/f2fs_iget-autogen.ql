/**
 * @name linux-76d56d4ab4f2a9e4f085c7d77172194ddaccf7d2-f2fs_iget
 * @id cpp/linux/76d56d4ab4f2a9e4f085c7d77172194ddaccf7d2/f2fs_iget
 * @description linux-76d56d4ab4f2a9e4f085c7d77172194ddaccf7d2-f2fs_iget 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_324, Variable vret_325, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sanity_check_inode")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_324
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_325
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Variable vinode_324, Variable vret_325
where
func_0(vinode_324, vret_325, func)
and vinode_324.getType().hasName("inode *")
and vret_325.getType().hasName("int")
and vinode_324.getParentScope+() = func
and vret_325.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
