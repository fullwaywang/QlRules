/**
 * @name curl-3c9e021f86872baae412a427e807fbfa2f3e8-multi_done
 * @id cpp/curl/3c9e021f86872baae412a427e807fbfa2f3e8/multi-done
 * @description curl-3c9e021f86872baae412a427e807fbfa2f3e8-multi_done CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(AssignExpr).getParent().(ExprStmt).getExpr() instanceof AssignExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vconn_548) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect_id"
		and target_1.getLValue().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_1.getRValue().(PointerFieldAccess).getTarget().getName()="connection_id"
		and target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_548)
}

predicate func_2(Function func) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect_id"
		and target_2.getLValue().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_2.getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_2.getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vdata_542) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="state"
		and target_3.getQualifier().(VariableAccess).getTarget()=vdata_542)
}

predicate func_6(Variable vconn_548) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect"
		and target_6.getLValue().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_6.getRValue().(VariableAccess).getTarget()=vconn_548)
}

predicate func_7(Function func) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect"
		and target_7.getLValue().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_7.getRValue() instanceof Literal
		and target_7.getEnclosingFunction() = func)
}

from Function func, Variable vconn_548, Parameter vdata_542
where
func_0(func)
and not func_1(vconn_548)
and not func_2(func)
and func_3(vdata_542)
and func_6(vconn_548)
and func_7(func)
and vconn_548.getType().hasName("connectdata *")
and vdata_542.getType().hasName("Curl_easy *")
and vconn_548.getParentScope+() = func
and vdata_542.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
