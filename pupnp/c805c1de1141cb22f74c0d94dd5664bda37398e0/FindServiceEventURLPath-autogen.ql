/**
 * @name pupnp-c805c1de1141cb22f74c0d94dd5664bda37398e0-FindServiceEventURLPath
 * @id cpp/pupnp/c805c1de1141cb22f74c0d94dd5664bda37398e0/FindServiceEventURLPath
 * @description pupnp-c805c1de1141cb22f74c0d94dd5664bda37398e0-upnp/src/genlib/service_table/service_table.c-FindServiceEventURLPath CVE-2020-13848
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtable_279, Parameter veventURLPath_279, BlockStmt target_7, ExprStmt target_8, LogicalAndExpr target_6) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vtable_279
		and target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=veventURLPath_279
		and target_0.getParent().(IfStmt).getThen()=target_7
		and target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtable_279, Variable vfinger_281, LogicalAndExpr target_6, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof EqualityOperation
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfinger_281
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="serviceList"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_279
		and target_1.getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(VariableAccess).getTarget()=vfinger_281
		and target_1.getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="eventURL"
		and target_1.getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfinger_281
		and target_1.getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfinger_281
		and target_1.getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_6.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vtable_279, Parameter veventURLPath_279, Variable vparsed_url_in_283, BlockStmt target_7, EqualityOperation target_3) {
		target_3.getAnOperand().(FunctionCall).getTarget().hasName("parse_uri")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veventURLPath_279
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("strlen")
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veventURLPath_279
		and target_3.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparsed_url_in_283
		and target_3.getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vtable_279
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_4(Function func, ReturnStmt target_4) {
		target_4.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

/*predicate func_5(Parameter vtable_279, Parameter veventURLPath_279, Variable vparsed_url_in_283, BlockStmt target_7, VariableAccess target_5) {
		target_5.getTarget()=vtable_279
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("parse_uri")
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veventURLPath_279
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("strlen")
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veventURLPath_279
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vparsed_url_in_283
		and target_5.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_7
}

*/
predicate func_6(Parameter vtable_279, BlockStmt target_7, LogicalAndExpr target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vtable_279
		and target_6.getAnOperand() instanceof EqualityOperation
		and target_6.getParent().(IfStmt).getThen()=target_7
}

predicate func_7(Parameter vtable_279, Variable vfinger_281, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfinger_281
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="serviceList"
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_279
		and target_7.getStmt(1).(WhileStmt).getCondition().(VariableAccess).getTarget()=vfinger_281
		and target_7.getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="eventURL"
		and target_7.getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfinger_281
		and target_7.getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfinger_281
		and target_7.getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_7.getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfinger_281
}

predicate func_8(Parameter vtable_279, Variable vfinger_281, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfinger_281
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="serviceList"
		and target_8.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtable_279
}

from Function func, Parameter vtable_279, Parameter veventURLPath_279, Variable vfinger_281, Variable vparsed_url_in_283, EqualityOperation target_3, ReturnStmt target_4, LogicalAndExpr target_6, BlockStmt target_7, ExprStmt target_8
where
not func_0(vtable_279, veventURLPath_279, target_7, target_8, target_6)
and not func_1(vtable_279, vfinger_281, target_6, func)
and func_3(vtable_279, veventURLPath_279, vparsed_url_in_283, target_7, target_3)
and func_4(func, target_4)
and func_6(vtable_279, target_7, target_6)
and func_7(vtable_279, vfinger_281, target_7)
and func_8(vtable_279, vfinger_281, target_8)
and vtable_279.getType().hasName("service_table *")
and veventURLPath_279.getType().hasName("const char *")
and vfinger_281.getType().hasName("service_info *")
and vparsed_url_in_283.getType().hasName("uri_type")
and vtable_279.getFunction() = func
and veventURLPath_279.getFunction() = func
and vfinger_281.(LocalVariable).getFunction() = func
and vparsed_url_in_283.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
