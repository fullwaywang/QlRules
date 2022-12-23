/**
 * @name linux-b91ee4aa2a2199ba4d4650706c272985a5a32d80-base_sock_create
 * @id cpp/linux/b91ee4aa2a2199ba4d4650706c272985a5a32d80/base_sock_create
 * @description linux-b91ee4aa2a2199ba4d4650706c272985a5a32d80-base_sock_create 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("capable")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
