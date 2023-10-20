/**
 * @name curl-3c9e021f86872baae412a427e807fbfa2f3e8-Curl_open
 * @id cpp/curl/3c9e021f86872baae412a427e807fbfa2f3e8/Curl-open
 * @description curl-3c9e021f86872baae412a427e807fbfa2f3e8-Curl_open CVE-2020-8231
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

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect_id"
		and target_1.getLValue().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_1.getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_1.getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vdata_607) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="state"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdata_607)
}

predicate func_3(Function func) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(ValueFieldAccess).getTarget().getName()="lastconnect"
		and target_3.getLValue().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_3.getRValue() instanceof Literal
		and target_3.getEnclosingFunction() = func)
}

from Function func, Variable vdata_607
where
func_0(func)
and not func_1(func)
and func_2(vdata_607)
and func_3(func)
and vdata_607.getType().hasName("Curl_easy *")
and vdata_607.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
