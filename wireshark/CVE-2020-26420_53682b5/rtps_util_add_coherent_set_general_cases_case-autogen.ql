/**
 * @name wireshark-53682b53da7f0d51effc042cc8613b47d2d65819-rtps_util_add_coherent_set_general_cases_case
 * @id cpp/wireshark/53682b53da7f0d51effc042cc8613b47d2d65819/rtps-util-add-coherent-set-general-cases-case
 * @description wireshark-53682b53da7f0d51effc042cc8613b47d2d65819-epan/dissectors/packet-rtps.c-rtps_util_add_coherent_set_general_cases_case CVE-2020-26420
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcoherent_set_info_key_1901, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcoherent_set_info_key_1901
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="32"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

from Function func, Variable vcoherent_set_info_key_1901
where
not func_0(vcoherent_set_info_key_1901, func)
and vcoherent_set_info_key_1901.getType().hasName("coherent_set_key")
and vcoherent_set_info_key_1901.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
