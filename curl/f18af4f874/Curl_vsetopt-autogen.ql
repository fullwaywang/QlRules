/**
 * @name curl-f18af4f874-Curl_vsetopt
 * @id cpp/curl/f18af4f874/Curl-vsetopt
 * @description curl-f18af4f874-Curl_vsetopt CVE-2022-27782
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable varg_157) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_0.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_0.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_0.getRValue().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=varg_157
		and target_0.getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="255")
}

predicate func_1(Variable varg_157) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(ValueFieldAccess).getTarget().getName()="ssl_options"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_1.getRValue().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=varg_157
		and target_1.getRValue().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="255")
}

predicate func_12(Variable vargptr_155) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="authtype"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_12.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vargptr_155
		and target_12.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_strncasecompare")
		and target_12.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vargptr_155
		and target_12.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SRP"
		and target_12.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_12.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(StringLiteral).getValue()="SRP")
}

predicate func_14(Parameter vdata_153, Variable vargptr_155) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="authtype"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="primary"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="proxy_ssl"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_14.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_153
		and target_14.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vargptr_155
		and target_14.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("Curl_strncasecompare")
		and target_14.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vargptr_155
		and target_14.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SRP"
		and target_14.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_14.getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(StringLiteral).getValue()="SRP")
}

predicate func_16(Parameter vdata_153) {
	exists(ValueFieldAccess target_16 |
		target_16.getTarget().getName()="ssl"
		and target_16.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_16.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_153)
}

predicate func_18(Parameter vdata_153) {
	exists(ValueFieldAccess target_18 |
		target_18.getTarget().getName()="proxy_ssl"
		and target_18.getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_153)
}

predicate func_28(Parameter vdata_153) {
	exists(PointerFieldAccess target_28 |
		target_28.getTarget().getName()="set"
		and target_28.getQualifier().(VariableAccess).getTarget()=vdata_153)
}

predicate func_30(Parameter vdata_153, Variable varg_157) {
	exists(AssignExpr target_30 |
		target_30.getLValue().(ValueFieldAccess).getTarget().getName()="new_directory_perms"
		and target_30.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="set"
		and target_30.getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_153
		and target_30.getRValue().(VariableAccess).getTarget()=varg_157)
}

from Function func, Parameter vdata_153, Variable vargptr_155, Variable varg_157
where
not func_0(varg_157)
and not func_1(varg_157)
and not func_12(vargptr_155)
and not func_14(vdata_153, vargptr_155)
and func_16(vdata_153)
and func_18(vdata_153)
and vdata_153.getType().hasName("Curl_easy *")
and func_28(vdata_153)
and vargptr_155.getType().hasName("char *")
and varg_157.getType().hasName("long")
and func_30(vdata_153, varg_157)
and vdata_153.getParentScope+() = func
and vargptr_155.getParentScope+() = func
and varg_157.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
