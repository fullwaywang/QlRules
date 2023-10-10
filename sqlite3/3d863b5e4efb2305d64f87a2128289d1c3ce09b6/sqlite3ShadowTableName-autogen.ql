/**
 * @name sqlite3-3d863b5e4efb2305d64f87a2128289d1c3ce09b6-sqlite3ShadowTableName
 * @id cpp/sqlite3/3d863b5e4efb2305d64f87a2128289d1c3ce09b6/sqlite3ShadowTableName
 * @description sqlite3-3d863b5e4efb2305d64f87a2128289d1c3ce09b6-src/build.c-sqlite3ShadowTableName CVE-2020-13631
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdb_2142, Parameter vzName_2142, Variable vpTab_2144, ExprStmt target_10, NotExpr target_11) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("sqlite3IsShadowTableOf")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vdb_2142
		and target_0.getArgument(1).(VariableAccess).getTarget()=vpTab_2144
		and target_0.getArgument(2).(VariableAccess).getTarget()=vzName_2142
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdb_2142, VariableAccess target_1) {
		target_1.getTarget()=vdb_2142
		and target_1.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_2(Variable vpTab_2144, VariableAccess target_2) {
		target_2.getTarget()=vpTab_2144
		and target_2.getParent().(PointerFieldAccess).getParent().(ArrayExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Function func, DeclStmt target_3) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Parameter vdb_2142, Variable vpTab_2144, Variable vpMod_2145, Function func, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpMod_2145
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3HashFind")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="aModule"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_2142
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="azModuleArg"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpTab_2144
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Variable vpMod_2145, Function func, IfStmt target_5) {
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpMod_2145
		and target_5.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_7(Variable vpMod_2145, Function func, IfStmt target_7) {
		target_7.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="iVersion"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pModule"
		and target_7.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpMod_2145
		and target_7.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="3"
		and target_7.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vpMod_2145, Function func, IfStmt target_8) {
		target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="xShadowName"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pModule"
		and target_8.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpMod_2145
		and target_8.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Variable vzTail_2143, Variable vpMod_2145, Function func, ReturnStmt target_9) {
		target_9.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="xShadowName"
		and target_9.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pModule"
		and target_9.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpMod_2145
		and target_9.getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vzTail_2143
		and target_9.getExpr().(VariableCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Parameter vdb_2142, Parameter vzName_2142, Variable vpTab_2144, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpTab_2144
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3FindTable")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_2142
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vzName_2142
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_11(Variable vpTab_2144, NotExpr target_11) {
		target_11.getOperand().(PointerFieldAccess).getTarget().getName()="nModuleArg"
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpTab_2144
}

from Function func, Parameter vdb_2142, Parameter vzName_2142, Variable vzTail_2143, Variable vpTab_2144, Variable vpMod_2145, VariableAccess target_1, VariableAccess target_2, DeclStmt target_3, ExprStmt target_4, IfStmt target_5, IfStmt target_7, IfStmt target_8, ReturnStmt target_9, ExprStmt target_10, NotExpr target_11
where
not func_0(vdb_2142, vzName_2142, vpTab_2144, target_10, target_11)
and func_1(vdb_2142, target_1)
and func_2(vpTab_2144, target_2)
and func_3(func, target_3)
and func_4(vdb_2142, vpTab_2144, vpMod_2145, func, target_4)
and func_5(vpMod_2145, func, target_5)
and func_7(vpMod_2145, func, target_7)
and func_8(vpMod_2145, func, target_8)
and func_9(vzTail_2143, vpMod_2145, func, target_9)
and func_10(vdb_2142, vzName_2142, vpTab_2144, target_10)
and func_11(vpTab_2144, target_11)
and vdb_2142.getType().hasName("sqlite3 *")
and vzName_2142.getType().hasName("const char *")
and vzTail_2143.getType().hasName("char *")
and vpTab_2144.getType().hasName("Table *")
and vpMod_2145.getType().hasName("Module *")
and vdb_2142.getFunction() = func
and vzName_2142.getFunction() = func
and vzTail_2143.(LocalVariable).getFunction() = func
and vpTab_2144.(LocalVariable).getFunction() = func
and vpMod_2145.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
