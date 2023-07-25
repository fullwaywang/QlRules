/**
 * @name curl-3c9e021f86872baae412a427e807fbfa2f3e8-Curl_getconnectinfo
 * @id cpp/curl/3c9e021f86872baae412a427e807fbfa2f3e8/Curl-getconnectinfo
 * @description curl-3c9e021f86872baae412a427e807fbfa2f3e8-Curl_getconnectinfo CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfind_1398) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="tofind"
		and target_0.getQualifier().(VariableAccess).getTarget()=vfind_1398)
}

predicate func_1(Function func) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="lastconnect"
		and target_1.getQualifier() instanceof PointerFieldAccess
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(ValueFieldAccess target_2 |
		target_2.getTarget().getName()="lastconnect"
		and target_2.getQualifier() instanceof PointerFieldAccess
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="0"
		and not target_3.getValue()="1"
		and target_3.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue() instanceof ValueFieldAccess
		and target_3.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect_id"
		and target_6.getLValue().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_6.getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_6.getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vc_1397, Variable vfind_1398, Parameter vdata_1386) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vc_1397
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="found"
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vfind_1398
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="lastconnect_id"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="multi_easy"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1386
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="multi"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1386)
}

predicate func_10(Parameter vdata_1386) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="state"
		and target_10.getQualifier().(VariableAccess).getTarget()=vdata_1386)
}

predicate func_16(Function func) {
	exists(Initializer target_16 |
		target_16.getExpr() instanceof ValueFieldAccess
		and target_16.getExpr().getEnclosingFunction() = func)
}

predicate func_18(Variable vfind_1398) {
	exists(AssignExpr target_18 |
		target_18.getLValue().(ValueFieldAccess).getTarget().getName()="found"
		and target_18.getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vfind_1398
		and target_18.getRValue() instanceof Literal)
}

predicate func_19(Variable vfind_1398) {
	exists(ValueFieldAccess target_19 |
		target_19.getTarget().getName()="found"
		and target_19.getQualifier().(VariableAccess).getTarget()=vfind_1398)
}

predicate func_20(Parameter vdata_1386) {
	exists(ValueFieldAccess target_20 |
		target_20.getTarget().getName()="lastconnect"
		and target_20.getQualifier().(PointerFieldAccess).getTarget().getName()="state"
		and target_20.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1386)
}

predicate func_21(Parameter vconnp_1387, Variable vc_1397) {
	exists(AssignExpr target_21 |
		target_21.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vconnp_1387
		and target_21.getRValue().(VariableAccess).getTarget()=vc_1397)
}

from Function func, Parameter vconnp_1387, Variable vc_1397, Variable vfind_1398, Parameter vdata_1386
where
func_0(vfind_1398)
and func_1(func)
and func_2(func)
and func_3(func)
and not func_6(func)
and not func_7(vc_1397, vfind_1398, vdata_1386)
and func_10(vdata_1386)
and func_16(func)
and func_18(vfind_1398)
and func_19(vfind_1398)
and func_20(vdata_1386)
and vc_1397.getType().hasName("connectdata *")
and func_21(vconnp_1387, vc_1397)
and vfind_1398.getType().hasName("connfind")
and vdata_1386.getType().hasName("Curl_easy *")
and vconnp_1387.getParentScope+() = func
and vc_1397.getParentScope+() = func
and vfind_1398.getParentScope+() = func
and vdata_1386.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
