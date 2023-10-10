/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-lsetCommand
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/lsetCommand
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-src/t_list.c-lsetCommand CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvalue_345, Parameter vc_341, FunctionCall target_1, ArrayExpr target_2, EqualityOperation target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_345
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294966272"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_341
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Element too large"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vvalue_345, FunctionCall target_1) {
		target_1.getTarget().hasName("quicklistReplaceAtIndex")
		and target_1.getArgument(0).(VariableAccess).getTarget().getType().hasName("quicklist *")
		and target_1.getArgument(1).(VariableAccess).getTarget().getType().hasName("long")
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_345
		and target_1.getArgument(3).(FunctionCall).getTarget().hasName("sdslen")
		and target_1.getArgument(3).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_1.getArgument(3).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvalue_345
}

predicate func_2(Parameter vc_341, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_341
		and target_2.getArrayOffset().(Literal).getValue()="3"
}

predicate func_3(Parameter vc_341, EqualityOperation target_3) {
		target_3.getAnOperand().(FunctionCall).getTarget().hasName("getLongFromObjectOrReply")
		and target_3.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_341
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_341
		and target_3.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_3.getAnOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("long")
		and target_3.getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_3.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vvalue_345, Parameter vc_341, FunctionCall target_1, ArrayExpr target_2, EqualityOperation target_3
where
not func_0(vvalue_345, vc_341, target_1, target_2, target_3, func)
and func_1(vvalue_345, target_1)
and func_2(vc_341, target_2)
and func_3(vc_341, target_3)
and vvalue_345.getType().hasName("robj *")
and vc_341.getType().hasName("client *")
and vvalue_345.(LocalVariable).getFunction() = func
and vc_341.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
