/**
 * @name redis-3f1f02034ce674cad8268f958cf8c39944b240c6-zrandmemberCommand
 * @id cpp/redis/3f1f02034ce674cad8268f958cf8c39944b240c6/zrandmemberCommand
 * @description redis-3f1f02034ce674cad8268f958cf8c39944b240c6-src/t_zset.c-zrandmemberCommand CVE-2023-22458
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_4286, Parameter vc_4285, EqualityOperation target_2, AddressOfExpr target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vl_4286
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="-4611686018427387904"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_4286
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="4611686018427387903"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_4285
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="value is out of range"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vwithscores_4287, LogicalOrExpr target_5, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwithscores_4287
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_2(Parameter vc_4285, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_4285
		and target_2.getAnOperand().(Literal).getValue()="4"
}

predicate func_3(Variable vl_4286, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vl_4286
}

predicate func_4(Variable vl_4286, Variable vwithscores_4287, Parameter vc_4285, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("zrandmemberWithCountCommand")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_4285
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_4286
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vwithscores_4287
}

predicate func_5(Parameter vc_4285, LogicalOrExpr target_5) {
		target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_4285
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_4285
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("strcasecmp")
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_4285
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="withscores"
}

from Function func, Variable vl_4286, Variable vwithscores_4287, Parameter vc_4285, ExprStmt target_1, EqualityOperation target_2, AddressOfExpr target_3, ExprStmt target_4, LogicalOrExpr target_5
where
not func_0(vl_4286, vc_4285, target_2, target_3, target_4)
and func_1(vwithscores_4287, target_5, target_1)
and func_2(vc_4285, target_2)
and func_3(vl_4286, target_3)
and func_4(vl_4286, vwithscores_4287, vc_4285, target_4)
and func_5(vc_4285, target_5)
and vl_4286.getType().hasName("long")
and vwithscores_4287.getType().hasName("int")
and vc_4285.getType().hasName("client *")
and vl_4286.(LocalVariable).getFunction() = func
and vwithscores_4287.(LocalVariable).getFunction() = func
and vc_4285.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
