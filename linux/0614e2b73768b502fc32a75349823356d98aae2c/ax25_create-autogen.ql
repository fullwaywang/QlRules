/**
 * @name linux-0614e2b73768b502fc32a75349823356d98aae2c-ax25_create
 * @id cpp/linux/0614e2b73768b502fc32a75349823356d98aae2c/ax25_create
 * @description linux-0614e2b73768b502fc32a75349823356d98aae2c-ax25_create 
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
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
