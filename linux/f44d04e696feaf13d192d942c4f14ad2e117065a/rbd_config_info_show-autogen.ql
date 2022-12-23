/**
 * @name linux-f44d04e696feaf13d192d942c4f14ad2e117065a-rbd_config_info_show
 * @id cpp/linux/f44d04e696feaf13d192d942c4f14ad2e117065a/rbd_config_info_show
 * @description linux-f44d04e696feaf13d192d942c4f14ad2e117065a-rbd_config_info_show 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("capable")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="21"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
