/**
 * @name bluez-f2778f5877d20696d68a452b26e4accb91bfb19e-hog_accept
 * @id cpp/bluez/f2778f5877d20696d68a452b26e4accb91bfb19e/hog-accept
 * @description bluez-f2778f5877d20696d68a452b26e4accb91bfb19e-profiles/input/hog.c-hog_accept CVE-2020-0556
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_4, Function func) {
	exists(NotExpr target_0 |
		target_0.getOperand().(VariableAccess).getType().hasName("bool")
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(NotExpr target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof NotExpr
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-111"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vclient_193, BlockStmt target_4, NotExpr target_2) {
		target_2.getOperand().(FunctionCall).getTarget().hasName("bt_gatt_client_set_security")
		and target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vclient_193
		and target_2.getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(NotExpr target_2, Function func, ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-111"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getEnclosingFunction() = func
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0) instanceof ReturnStmt
}

predicate func_5(NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("device_is_bonded")
		and target_5.getOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("btd_device_get_bdaddr_type")
}

from Function func, Variable vclient_193, NotExpr target_2, ReturnStmt target_3, BlockStmt target_4, NotExpr target_5
where
not func_0(target_4, func)
and not func_1(target_5, func)
and func_2(vclient_193, target_4, target_2)
and func_3(target_2, func, target_3)
and func_4(target_4)
and func_5(target_5)
and vclient_193.getType().hasName("bt_gatt_client *")
and vclient_193.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
