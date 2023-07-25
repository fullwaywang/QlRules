/**
 * @name bluez-00da0fb4972cf59e1c075f313da81ea549cb8738-handle_read_req
 * @id cpp/bluez/00da0fb4972cf59e1c075f313da81ea549cb8738/handle-read-req
 * @description bluez-00da0fb4972cf59e1c075f313da81ea549cb8738-src/shared/gatt-server.c-handle_read_req CVE-2020-26558
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BitwiseOrExpr target_0 |
		target_0.getValue()="277"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_permissions")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof BitwiseOrExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func, BitwiseOrExpr target_1) {
		target_1.getValue()="21"
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_permissions")
		and target_1.getEnclosingFunction() = func
}

from Function func, BitwiseOrExpr target_1
where
not func_0(func)
and func_1(func, target_1)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
