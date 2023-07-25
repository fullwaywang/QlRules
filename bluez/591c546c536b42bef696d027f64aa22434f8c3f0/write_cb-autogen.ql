/**
 * @name bluez-591c546c536b42bef696d027f64aa22434f8c3f0-write_cb
 * @id cpp/bluez/591c546c536b42bef696d027f64aa22434f8c3f0/write-cb
 * @description bluez-591c546c536b42bef696d027f64aa22434f8c3f0-src/shared/gatt-server.c-write_cb CVE-2022-0204
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlength_783, Variable vecode_789, RelationalOperation target_2, SubExpr target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vecode_789
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_length")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlength_783
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0)
		and target_2.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vecode_789, IfStmt target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vecode_789
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(GotoStmt).getName() ="error"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_1)
		and target_5.getCondition().(VariableAccess).getLocation().isBefore(target_1.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vlength_783, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vlength_783
		and target_2.getGreaterOperand().(Literal).getValue()="2"
}

predicate func_3(Parameter vlength_783, SubExpr target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vlength_783
		and target_3.getRightOperand().(Literal).getValue()="2"
}

predicate func_4(Variable vecode_789, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vecode_789
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_5(Variable vecode_789, IfStmt target_5) {
		target_5.getCondition().(VariableAccess).getTarget()=vecode_789
		and target_5.getThen().(GotoStmt).toString() = "goto ..."
		and target_5.getThen().(GotoStmt).getName() ="error"
}

from Function func, Parameter vlength_783, Variable vecode_789, RelationalOperation target_2, SubExpr target_3, ExprStmt target_4, IfStmt target_5
where
not func_0(vlength_783, vecode_789, target_2, target_3, target_4, func)
and not func_1(vecode_789, target_5, func)
and func_2(vlength_783, target_2)
and func_3(vlength_783, target_3)
and func_4(vecode_789, target_4)
and func_5(vecode_789, target_5)
and vlength_783.getType().hasName("uint16_t")
and vecode_789.getType().hasName("uint8_t")
and vlength_783.getParentScope+() = func
and vecode_789.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
