/**
 * @name wireshark-086003c9d616906e08bbeeab9c17b3aa4c6ff850-dissect_lte_rrc_T_targetRAT_MessageContainer
 * @id cpp/wireshark/086003c9d616906e08bbeeab9c17b3aa4c6ff850/dissect-lte-rrc-T-targetRAT-MessageContainer
 * @description wireshark-086003c9d616906e08bbeeab9c17b3aa4c6ff850-epan/dissectors/packet-lte-rrc.c-dissect_lte_rrc_T_targetRAT_MessageContainer CVE-2020-9431
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpd_52218, FunctionCall target_0) {
		target_0.getTarget().hasName("tvb_new_real_data")
		and not target_0.getTarget().hasName("tvb_new_child_real_data")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vpd_52218
		and target_0.getArgument(1).(Literal).getValue()="1"
		and target_0.getArgument(2).(Literal).getValue()="1"
}

from Function func, Variable vpd_52218, FunctionCall target_0
where
func_0(vpd_52218, target_0)
and vpd_52218.getType().hasName("guint8 *")
and vpd_52218.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
