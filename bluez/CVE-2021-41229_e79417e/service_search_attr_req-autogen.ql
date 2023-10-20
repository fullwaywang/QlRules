/**
 * @name bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-service_search_attr_req
 * @id cpp/bluez/e79417ed7185b150a056d4eb3a1ab528b91d2fc0/service-search-attr-req
 * @description bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-src/sdpd-request.c-service_search_attr_req CVE-2021-41229
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_1.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("sdp_cstate_get")
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
not func_1(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
