/**
 * @name wireshark-53682b53da7f0d51effc042cc8613b47d2d65819-rtps_util_detect_coherent_set_end_empty_data_case
 * @id cpp/wireshark/53682b53da7f0d51effc042cc8613b47d2d65819/rtps-util-detect-coherent-set-end-empty-data-case
 * @description wireshark-53682b53da7f0d51effc042cc8613b47d2d65819-epan/dissectors/packet-rtps.c-rtps_util_detect_coherent_set_end_empty_data_case CVE-2020-26420
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vkey_1991, VariableAccess target_1) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vkey_1991
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="32"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1)
}

predicate func_1(Variable vcoherent_set_entry_1986, VariableAccess target_1) {
		target_1.getTarget()=vcoherent_set_entry_1986
}

from Function func, Variable vkey_1991, Variable vcoherent_set_entry_1986, VariableAccess target_1
where
not func_0(vkey_1991, target_1)
and func_1(vcoherent_set_entry_1986, target_1)
and vkey_1991.getType().hasName("coherent_set_key")
and vcoherent_set_entry_1986.getType().hasName("coherent_set_entity_info *")
and vkey_1991.getParentScope+() = func
and vcoherent_set_entry_1986.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
