/**
 * @name redis-f6a40570fa63d5afdd596c78083d754081d80ae3-lposCommand
 * @id cpp/redis/f6a40570fa63d5afdd596c78083d754081d80ae3/lposCommand
 * @description redis-f6a40570fa63d5afdd596c78083d754081d80ae3-src/t_list.c-lposCommand CVE-2021-32627
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vele_508, Parameter vc_507, ExprStmt target_1, FunctionCall target_2, RelationalOperation target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ptr"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vele_508
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="4294966272"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_507
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Element too large"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(1).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vele_508, Parameter vc_507, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vele_508
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_507
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
}

predicate func_2(Variable vele_508, FunctionCall target_2) {
		target_2.getTarget().hasName("listTypeEqual")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("listTypeEntry")
		and target_2.getArgument(1).(VariableAccess).getTarget()=vele_508
}

predicate func_3(Parameter vc_507, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="argc"
		and target_3.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_507
}

from Function func, Variable vele_508, Parameter vc_507, ExprStmt target_1, FunctionCall target_2, RelationalOperation target_3
where
not func_0(vele_508, vc_507, target_1, target_2, target_3, func)
and func_1(vele_508, vc_507, target_1)
and func_2(vele_508, target_2)
and func_3(vc_507, target_3)
and vele_508.getType().hasName("robj *")
and vc_507.getType().hasName("client *")
and vele_508.(LocalVariable).getFunction() = func
and vc_507.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
