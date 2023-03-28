/**
 * @name redis-3f1f02034ce674cad8268f958cf8c39944b240c6-hrandfieldCommand
 * @id cpp/redis/3f1f02034ce674cad8268f958cf8c39944b240c6/hrandfieldCommand
 * @description redis-3f1f02034ce674cad8268f958cf8c39944b240c6-hrandfieldCommand CVE-2023-22458
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_1117, Parameter vc_1116, EqualityOperation target_5, AddressOfExpr target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vl_1117
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="-4611686018427387904"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_1117
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="4611686018427387903"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1116
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="value is out of range"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Variable vwithvalues_1118, LogicalOrExpr target_8, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwithvalues_1118
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_2.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_8
}

predicate func_3(RelationalOperation target_9, Function func, ReturnStmt target_3) {
		target_3.toString() = "return ..."
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Function func, ReturnStmt target_4) {
		target_4.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vc_1116, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1116
		and target_5.getAnOperand().(Literal).getValue()="4"
}

predicate func_6(Variable vl_1117, AddressOfExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vl_1117
}

predicate func_7(Variable vl_1117, Variable vwithvalues_1118, Parameter vc_1116, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("hrandfieldWithCountCommand")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_1116
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_1117
		and target_7.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vwithvalues_1118
}

predicate func_8(Parameter vc_1116, LogicalOrExpr target_8) {
		target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1116
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1116
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("strcasecmp")
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1116
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="withvalues"
}

predicate func_9(Parameter vc_1116, RelationalOperation target_9) {
		 (target_9 instanceof GEExpr or target_9 instanceof LEExpr)
		and target_9.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_9.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1116
		and target_9.getLesserOperand().(Literal).getValue()="3"
}

from Function func, Variable vl_1117, Variable vwithvalues_1118, Parameter vc_1116, ExprStmt target_2, ReturnStmt target_3, ReturnStmt target_4, EqualityOperation target_5, AddressOfExpr target_6, ExprStmt target_7, LogicalOrExpr target_8, RelationalOperation target_9
where
not func_0(vl_1117, vc_1116, target_5, target_6, target_7)
and func_2(vwithvalues_1118, target_8, target_2)
and func_3(target_9, func, target_3)
and func_4(func, target_4)
and func_5(vc_1116, target_5)
and func_6(vl_1117, target_6)
and func_7(vl_1117, vwithvalues_1118, vc_1116, target_7)
and func_8(vc_1116, target_8)
and func_9(vc_1116, target_9)
and vl_1117.getType().hasName("long")
and vwithvalues_1118.getType().hasName("int")
and vc_1116.getType().hasName("client *")
and vl_1117.getParentScope+() = func
and vwithvalues_1118.getParentScope+() = func
and vc_1116.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
