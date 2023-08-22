/**
 * @name redis-6ac3c0b7abd35f37201ed2d6298ecef4ea1ae1dd-ldbRepl
 * @id cpp/redis/6ac3c0b7abd35f37201ed2d6298ecef4ea1ae1dd/ldbRepl
 * @description redis-6ac3c0b7abd35f37201ed2d6298ecef4ea1ae1dd-src/scripting.c-ldbRepl CVE-2021-32672
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(VariableAccess).getType().hasName("char *")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ldbReplParseCommand")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vlua_2555) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getType().hasName("char *")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lua_pushstring")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_2555
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("char *")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lua_error")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_2555)
}

predicate func_2(Variable vldb, Parameter vlua_2555, ValueFieldAccess target_7, ExprStmt target_8) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("sdslen")
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="cbuf"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vldb
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getValue()="1048576"
		and target_2.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lua_pushstring")
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_2555
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="max client buffer reached"
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lua_error")
		and target_2.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_2555
		and target_7.getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable vldb, ValueFieldAccess target_9) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="cbuf"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vldb
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sdsempty")
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vldb, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("sdsfree")
		and target_5.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="cbuf"
		and target_5.getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vldb
}

predicate func_6(Variable vldb, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="cbuf"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vldb
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sdsempty")
}

predicate func_7(Variable vldb, ValueFieldAccess target_7) {
		target_7.getTarget().getName()="cbuf"
		and target_7.getQualifier().(VariableAccess).getTarget()=vldb
}

predicate func_8(Parameter vlua_2555, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("ldbTrace")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlua_2555
}

predicate func_9(Variable vldb, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="cbuf"
		and target_9.getQualifier().(VariableAccess).getTarget()=vldb
}

from Function func, Variable vldb, Parameter vlua_2555, ExprStmt target_5, ExprStmt target_6, ValueFieldAccess target_7, ExprStmt target_8, ValueFieldAccess target_9
where
not func_0(func)
and not func_1(vlua_2555)
and not func_2(vldb, vlua_2555, target_7, target_8)
and not func_4(vldb, target_9)
and func_5(vldb, target_5)
and func_6(vldb, target_6)
and func_7(vldb, target_7)
and func_8(vlua_2555, target_8)
and func_9(vldb, target_9)
and vldb.getType().hasName("ldbState")
and vlua_2555.getType().hasName("lua_State *")
and not vldb.getParentScope+() = func
and vlua_2555.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
