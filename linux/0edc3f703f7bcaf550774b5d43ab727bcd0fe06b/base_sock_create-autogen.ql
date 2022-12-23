/**
 * @name linux-0edc3f703f7bcaf550774b5d43ab727bcd0fe06b-base_sock_create
 * @id cpp/linux/0edc3f703f7bcaf550774b5d43ab727bcd0fe06b/base-sock-create
 * @description linux-0edc3f703f7bcaf550774b5d43ab727bcd0fe06b-base_sock_create 
 * @kind problem
 * @problem.severity error
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
