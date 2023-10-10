/**
 * @name sqlite3-7694e06461203a466865fc8ed3068e0990a7ca50-unixGetTempname
 * @id cpp/sqlite3/7694e06461203a466865fc8ed3068e0990a7ca50/unixGetTempname
 * @description sqlite3-7694e06461203a466865fc8ed3068e0990a7ca50-src/os_unix.c-unixGetTempname CVE-2016-6153
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vzBuf_5434, EqualityOperation target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vzBuf_5434
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_0.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vzDir_5435, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vzDir_5435
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(BitwiseOrExpr).getValue()="6410"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1)
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vzBuf_5434, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="pCurrent"
		and target_2.getAnOperand().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_2.getAnOperand().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_2.getAnOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vzBuf_5434
		and target_2.getAnOperand().(VariableCall).getArgument(1).(Literal).getValue()="0"
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vzDir_5435, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vzDir_5435
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("unixTempFileDir")
}

predicate func_4(Parameter vzBuf_5434, Variable vzDir_5435, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("sqlite3_snprintf")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vzBuf_5434
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s/etilqs_%llx%c"
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vzDir_5435
		and target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("u64")
		and target_4.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

from Function func, Parameter vzBuf_5434, Variable vzDir_5435, EqualityOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vzBuf_5434, target_2, func)
and not func_1(vzDir_5435, target_3, target_4, func)
and func_2(vzBuf_5434, target_2)
and func_3(vzDir_5435, target_3)
and func_4(vzBuf_5434, vzDir_5435, target_4)
and vzBuf_5434.getType().hasName("char *")
and vzDir_5435.getType().hasName("const char *")
and vzBuf_5434.getFunction() = func
and vzDir_5435.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
