/**
 * @name curl-3c9e021f86872baae412a427e807fbfa2f3e8-close_connect_only
 * @id cpp/curl/3c9e021f86872baae412a427e807fbfa2f3e8/close-connect-only
 * @description curl-3c9e021f86872baae412a427e807fbfa2f3e8-close_connect_only CVE-2020-8231
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ValueFieldAccess target_0 |
		target_0.getTarget().getName()="lastconnect_id"
		and target_0.getQualifier() instanceof PointerFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vconn_692) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="connection_id"
		and target_1.getQualifier().(VariableAccess).getTarget()=vconn_692)
}

predicate func_2(Variable vdata_694) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="state"
		and target_2.getQualifier().(VariableAccess).getTarget()=vdata_694)
}

predicate func_4(Function func) {
	exists(ValueFieldAccess target_4 |
		target_4.getTarget().getName()="lastconnect"
		and target_4.getQualifier() instanceof PointerFieldAccess
		and target_4.getEnclosingFunction() = func)
}

from Function func, Parameter vconn_692, Variable vdata_694
where
not func_0(func)
and not func_1(vconn_692)
and func_2(vdata_694)
and func_4(func)
and vconn_692.getType().hasName("connectdata *")
and vdata_694.getType().hasName("Curl_easy *")
and vconn_692.getParentScope+() = func
and vdata_694.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
