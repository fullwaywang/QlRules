/**
 * @name linux-688e8128b7a92df982709a4137ea4588d16f24aa-show_transport_handle
 * @id cpp/linux/688e8128b7a92df982709a4137ea4588d16f24aa/show_transport_handle
 * @description linux-688e8128b7a92df982709a4137ea4588d16f24aa-show_transport_handle 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("capable")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="21"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-13"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
