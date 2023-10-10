/**
 * @name linux-ba953a9d89a00c078b85f4b190bc1dde66fe16b5-pfkey_register
 * @id cpp/linux/ba953a9d89a00c078b85f4b190bc1dde66fe16b5/pfkey-register
 * @description linux-ba953a9d89a00c078b85f4b190bc1dde66fe16b5-pfkey_register 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mutex_lock_nested")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mutex")
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_0)
}

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("mutex_unlock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("mutex")
		and func.getEntryPoint().(BlockStmt).getStmt(7)=target_1)
}

from Function func
where
not func_0(func)
and not func_1(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
